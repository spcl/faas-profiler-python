#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all AWS specific logic.
"""
import base64
import io
import json

from collections import namedtuple
from urllib.parse import urlparse
from typing import Any, List, Tuple, Type

from faas_profiler_core.models import TracingContext, InboundContext, OutboundContext
from faas_profiler_core.constants import (
    Provider,
    TRACE_ID_HEADER,
    RECORD_ID_HEADER,
    PARENT_ID_HEADER,
    TRACE_CONTEXT_KEY,
    TriggerSynchronicity,
    AWSOperation,
    AWSService
)
from faas_profiler_python.patchers import PatchContext, ReturnContext

from faas_profiler_python.utilis import (
    Loggable,
    decode_base64_json_to_dict,
    encode_dict_to_base64_json,
    get_arg_by_key_or_pos,
    lowercase_keys,
    get_idx_safely,
    is_url
)
from faas_profiler_python.config import InjectionError

"""
ARN Parsing
"""

# flake8: noqa: E501
ARN_REGEX = r"^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountID>[^:\n]*):(?P<Ignore>(?P<ResourceType>[^:\/\n]*)[:\/])?(?P<Resource>.*)$"

ARN = namedtuple(
    "ARN",
    "partition service region account_id resource_type resource")


def parse_aws_arn(arn: str) -> Type[ARN]:
    match = re.match(ARN_REGEX, arn)
    if match is None:
        return None

    match_groups = match.groups()

    return ARN(
        partition=get_idx_safely(match_groups, 0),
        service=get_idx_safely(match_groups, 1),
        region=get_idx_safely(match_groups, 2),
        account_id=get_idx_safely(match_groups, 3),
        resource_type=get_idx_safely(match_groups, 5),
        resource=get_idx_safely(match_groups, 6))


"""
AWS URL and ARN
"""


def sqs_resource_name(name: str) -> str:
    """
    Resolves the resource from URL or ARN
    """
    if is_url(name):
        parse_result = urlparse(name)
        if not parse_result.path:
            return name

        path_parts = str(parse_result.path).split("/")
        return get_idx_safely(path_parts, 2, name)

    arn = parse_aws_arn(name)
    if arn:
        return arn.resource

    return name


"""
AWS Context Resolving
"""


class AWSEvent(Loggable):

    EVENT_DETECTION = [
        "lambda_function_url",
        "cloud_formation_detection",
        "cloud_front_detection",
        "cloudwatch_logs_detection",
        "eventbridge_detection",
        "dynamodb_detection",
        "s3_detection",
        "sns_detection",
        "sqs_detection",
        "ses_detection",
        "aws_config_detection",
        "code_commit_detection",
        "gateway_proxy_detection",
        "gateway_http_detection",
        "gateway_authorization_detection"
    ]

    def __init__(
        self,
        event_data: dict
    ) -> None:
        super().__init__()
        if not isinstance(event_data, dict):
            self.logger.error(
                f"AWS Event data must be a dict, got {type(event_data)}. Cannot parse Event.")
            event_data = {}

        self.data = lowercase_keys(event_data)
        self.service, self.operation = self.resolve_event()

    def resolve_event(self) -> Tuple[AWSService, AWSOperation]:
        """
        Resolves the service and operation triggering this event.
        """
        _service = AWSService.UNIDENTIFIED
        _operation = AWSOperation.UNIDENTIFIED

        for detector in self.EVENT_DETECTION:
            result = getattr(self, detector)()
            if result is not None:
                _service = get_idx_safely(result, 0, AWSService.UNIDENTIFIED)
                _operation = get_idx_safely(
                    result, 1, AWSOperation.UNIDENTIFIED)
                break

        self.logger.info(
            f"[AWS INBOUND EVENT]: Detected inbound of service {_service} and operation {_operation}")

        return _service, _operation

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns context about the trigger
        """
        inbound_context = InboundContext(
            Provider.AWS, self.service, self.operation)

        if self.service == AWSService.S3:
            self.s3_inbound_context(inbound_context)
        elif self.service == AWSService.DYNAMO_DB:
            self.dynamodb_context(inbound_context)
        elif self.service == AWSService.SQS:
            self.sqs_context(inbound_context)
        elif self.service == AWSService.SNS:
            self.sns_context(inbound_context)
        elif self.service == AWSService.EVENTBRIDGE:
            self.event_context(inbound_context)

        return inbound_context

    def extract_trace_context(self) -> Type[TracingContext]:
        """
        Extracts trace context from event data
        """
        if "headers" in self.data:
            _trace_context = self.tracing_context_from_headers()
            if _trace_context is not None:
                return _trace_context

        if TRACE_CONTEXT_KEY in self.data:
            return self.tracing_context_from_payload()

        if self.service == AWSService.SQS:
            return self.tracing_context_from_sqs()
        elif self.service == AWSService.SNS:
            return self.tracing_context_from_sns()
        elif self.service == AWSService.EVENTBRIDGE:
            return self.tracing_context_from_eventbridge()

        return None

    """
    AWS Inbound Context Resolving by Event
    """

    def s3_inbound_context(
            self,
            inbound_context: Type[InboundContext]) -> None:
        """
        Creates inbound context for S3
        """
        _s3_record = self.first_record
        _bucket = _s3_record.get("s3", {}).get("bucket")
        _object = _s3_record.get("s3", {}).get("object")

        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC
        inbound_context.set_tags({
            "bucket_name": _bucket.get("name"),
            "bucket_arn": _bucket.get("arn"),
            "object_key": _object.get("key"),
            "object_etag": _object.get("eTag")
        })
        inbound_context.set_identifiers({
            "request_id": _s3_record.get("responseelements", {}).get("x-amz-request-id"),
            "object_key": _object.get("key"),
            "bucket_name": _bucket.get("name")
        })

    def dynamodb_context(self, inbound_context: Type[InboundContext]) -> None:
        """
        Creates inbound context for DynamoDB
        """
        _db_record = self.first_record
        _dynamodb_arn = _db_record.get("eventsourcearn")
        _table_name = None
        if _dynamodb_arn:
            _dynamodb_arn = parse_aws_arn(_dynamodb_arn)
            if _dynamodb_arn.resource_type == "table":
                _table_name = str(_dynamodb_arn.resource).split("/")[0]

        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC
        inbound_context.set_tags({
            "table_name": _table_name,
        })
        inbound_context.set_identifiers({
            "table_name": _table_name,
        })

    def sqs_context(self, inbound_context: Type[InboundContext]) -> None:
        """
        Creates inbound context for SQS
        """
        _sqs_record = self.first_record

        _queue_url = None
        try:
            _event_arn = parse_aws_arn(_sqs_record.get("eventsourcearn", ""))
            _queue_url = _event_arn.resource
        except Exception:
            pass

        _message_id = _sqs_record.get("messageid")

        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC
        inbound_context.set_identifiers({
            "queue_url": _queue_url,
            "message_id": _message_id
        })
        inbound_context.set_tags({
            "queue_url": _queue_url,
            "message_id": _message_id
        })

    def sns_context(self, inbound_context: Type[InboundContext]) -> None:
        """
        Creates inbound context for SNS
        """
        _sns_record = self.first_record

        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC

        if "sns" not in _sns_record:
            return None

        _message_id = _sns_record["sns"].get("MessageId")
        _topic_arn = _sns_record["sns"].get("TopicArn")

        if not _message_id or not _topic_arn:
            return

        inbound_context.set_identifiers({
            "topic_arn": _topic_arn,
            "message_id": _message_id
        })
        inbound_context.set_tags({
            "topic_arn": _topic_arn,
            "message_id": _message_id
        })

    def event_context(self, inbound_context: Type[InboundContext]) -> None:
        """
        Creates inbound context for Event Bridge
        """
        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC

        _event_id = self.data.get("id")
        if _event_id:
            inbound_context.set_identifiers({
                "event_id": _event_id
            })
            inbound_context.set_tags({
                "event_id": _event_id
            })

    """
    AWS Tracing Context Resolving by Event
    """

    def tracing_context_from_payload(self) -> Type[TracingContext]:
        """
        Extracts tracing context from payload.
        """
        if TRACE_CONTEXT_KEY in self.data:
            trace_ctx = self.data[TRACE_CONTEXT_KEY]
            return TracingContext(
                trace_id=trace_ctx.get(TRACE_ID_HEADER),
                record_id=trace_ctx.get(RECORD_ID_HEADER),
                parent_id=trace_ctx.get(PARENT_ID_HEADER))

        return None

    def tracing_context_from_headers(self) -> Type[TracingContext]:
        """
        Extracts tracing context from headers.
        """
        headers = self.data.get("headers", {})
        return TracingContext(
            trace_id=headers.get(TRACE_ID_HEADER),
            record_id=headers.get(RECORD_ID_HEADER),
            parent_id=headers.get(PARENT_ID_HEADER))

    def tracing_context_from_sqs(self) -> Type[TracingContext]:
        """
        Extracts tracing context from SQS message attributes
        """
        _sqs_record = self.first_record
        msg_attr = _sqs_record.get("messageattributes", {})
        tracing_ctx = msg_attr.get(TRACE_CONTEXT_KEY, {})

        return self._extract_tracing_context_from_msg_attr(tracing_ctx)

    def tracing_context_from_sns(self) -> Type[TracingContext]:
        """
        Extracts tracing context from SNS message attributes.
        """
        _sns_record = self.first_record
        if "sns" not in _sns_record:
            return

        _sns_message = _sns_record["sns"]
        msg_attr = _sns_message.get("MessageAttributes")
        tracing_ctx = msg_attr.get(TRACE_CONTEXT_KEY, {})

        return self._extract_tracing_context_from_msg_attr(tracing_ctx)

    def tracing_context_from_eventbridge(self) -> Type[TracingContext]:
        """
        Extracts tracing context from Eventbridge
        """
        detail = self.data.get("detail", {})
        context = detail.get(TRACE_CONTEXT_KEY, {})
        return TracingContext(
            trace_id=context.get(TRACE_ID_HEADER),
            record_id=context.get(RECORD_ID_HEADER),
            parent_id=context.get(PARENT_ID_HEADER))

    def _extract_tracing_context_from_msg_attr(
        self,
        attr: dict
    ) -> Type[TracingContext]:
        _datatype = attr["Type"] if "Type" in attr else attr.get("dataType")
        if _datatype == "String":
            _tracing_string = attr["Value"] if "Value" in attr else attr.get(
                "stringValue", r"{}")
            _tracing_obj = json.loads(_tracing_string)
        elif _datatype == "Binary":
            _tracing_bin = attr["Value"] if "Value" in attr else attr.get(
                "binaryValue", r"{}")
            _tracing_string = base64.b64decode(_tracing_bin)
            _tracing_obj = json.loads(_tracing_string)

        return TracingContext(
            trace_id=_tracing_obj.get(TRACE_ID_HEADER),
            record_id=_tracing_obj.get(RECORD_ID_HEADER),
            parent_id=_tracing_obj.get(PARENT_ID_HEADER))

    """
    AWS Inbound Service and Operation Detection
    """

    @property
    def has_records(self) -> bool:
        """
        Returns True if event has record.
        """
        return 'records' in self.data and len(self.data['records']) > 0

    @property
    def first_record(self) -> dict:
        """
        Returns first Record if it exists
        """
        if not self.has_records:
            return {}

        try:
            return lowercase_keys(self.data['records'][0])
        except (IndexError, KeyError):
            return {}

    @property
    def event_source_of_first_record(self) -> str:
        """
        Returns event source of first record.
        """
        return self.first_record.get('eventsource', None)

    def lambda_function_url(self) -> tuple:
        request_context = lowercase_keys(self.data.get("requestcontext", {}))
        domain_name = str(request_context.get("domainname", ""))
        try:
            if domain_name.split(".")[1] == "lambda-url":
                return (
                    AWSService.LAMBDA,
                    AWSOperation.LAMBDA_FUNCTION_URL)
        except IndexError:
            pass

    def cloud_formation_detection(self) -> tuple:
        if 'stackid' in self.data and 'requesttype' in self.data and 'resourcetype' in self.data:
            return (
                AWSService.CLOUD_FORMATION,
                AWSOperation.UNIDENTIFIED)

    def cloud_front_detection(self) -> tuple:
        if 'cf' in self.first_record:
            return (
                AWSService.CLOUDFRONT,
                AWSOperation.UNIDENTIFIED)

    def cloudwatch_logs_detection(self) -> tuple:
        if "data" in self.data.get("awslogs", {}):
            return (
                AWSService.CLOUDWATCH,
                AWSOperation.CLOUDWATCH_LOGS)

    def eventbridge_detection(self) -> tuple:
        if "detail-type" in self.data:
            return (
                AWSService.EVENTBRIDGE,
                AWSOperation.EVENTBRIDGE_SCHEDULED_EVENT)

    def dynamodb_detection(self) -> tuple:
        if self.event_source_of_first_record == "aws:dynamodb":
            return (
                AWSService.DYNAMO_DB,
                AWSOperation.DYNAMO_DB_UPDATE)

    def s3_detection(self) -> tuple:
        if not self.event_source_of_first_record == "aws:s3":
            return

        operation = AWSService.UNIDENTIFIED
        _event_name = str(self.first_record.get("eventname", ""))
        _operation_name = str(_event_name).split(":")[0]
        if _operation_name == "ObjectCreated":
            operation = AWSOperation.S3_OBJECT_CREATE
        elif _operation_name == "ObjectRemoved":
            operation = AWSOperation.S3_OBJECT_REMOVED

        return (
            AWSService.S3,
            operation)

    def sns_detection(self) -> tuple:
        if self.event_source_of_first_record == "aws:sns":
            return (
                AWSService.SNS,
                AWSOperation.SNS_TOPIC_NOTIFICATION)

    def sqs_detection(self) -> tuple:
        if self.event_source_of_first_record == "aws:sqs":
            return (
                AWSService.SQS,
                AWSOperation.SQS_RECEIVE)

    def ses_detection(self) -> tuple:
        if self.event_source_of_first_record == "aws:ses":
            return (
                AWSService.SES,
                AWSOperation.SES_EMAIL_RECEIVE)

    def aws_config_detection(self) -> tuple:
        if "configruleid" in self.data and "configrulename" in self.data and "configrulearn" in self.data:
            return (
                AWSService.AWS_CONFIG,
                AWSOperation.UNIDENTIFIED)

    def code_commit_detection(self) -> tuple:
        if self.event_source_of_first_record == "aws:codecommit":
            return (
                AWSService.CODE_COMMIT,
                AWSOperation.UNIDENTIFIED)

    def gateway_proxy_detection(self) -> tuple:
        if "proxy" in self.data.get("pathparameters", {}):
            return (
                AWSService.API_GATEWAY,
                AWSOperation.API_GATEWAY_AWS_PROXY)

    def gateway_http_detection(self) -> tuple:
        if self.gateway_proxy_detection():
            return

        if "resourceid" in lowercase_keys(self.data.get(
                "requestcontext", {})):
            return (
                AWSService.API_GATEWAY,
                AWSOperation.API_GATEWAY_HTTP)

    def gateway_authorization_detection(self) -> tuple:
        if self.data.get("authorizationtoken") == "incoming-client-token":
            return (
                AWSService.API_GATEWAY,
                AWSOperation.API_GATEWAY_AUTHORIZER)


class AWSContext(Loggable):

    # https://docs.aws.amazon.com/lambda/latest/dg/python-context.html

    def __init__(self, context_data) -> None:
        super().__init__()
        self.data = context_data

    @property
    def client_context(self) -> Any:
        return getattr(self.data, "client_context", None)

    @property
    def custom_context(self) -> dict:
        if self.client_context is None:
            return {}

        client_ctx = getattr(self.client_context, "custom", {})
        if not isinstance(client_ctx, dict):
            self.logger.error(
                f"Custom client context is not a dict, got {type(client_ctx)}. Cannot parse custom client context.")
            return {}

        return client_ctx

    def extract_trace_context(self) -> Type[TracingContext]:
        """
        Extracts Trace context from AWS Lambda Context object.
        """
        return TracingContext(
            trace_id=self.custom_context.get(TRACE_ID_HEADER),
            record_id=self.custom_context.get(RECORD_ID_HEADER),
            parent_id=self.custom_context.get(PARENT_ID_HEADER))

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Extracts default Lambda inbound context
        """
        _function_name = getattr(self.data, "function_name", "unidentified")
        _request_id = getattr(self.data, "aws_request_id", "unidentified")
        return InboundContext(
            provider=Provider.AWS,
            service=AWSService.LAMBDA,
            operation=AWSOperation.LAMBDA_INVOKE,
            identifier={
                "function_name": _function_name,
                "request_id": _request_id})


"""
AWS Outbound
"""


def extract_outbound_contexts(
    service: AWSService,
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext
) -> List[Type[OutboundContext]]:
    """
    Extracts all outbound contexts
    """
    tags = common_tags_api_call(patch_context, return_context)
    if service in OUTBOUND_PROXY:
        return OUTBOUND_PROXY[service](
            operation, patch_context, return_context, tags=tags)
    else:
        return []


def inject_payload(
    service: AWSService,
    operation: AWSOperation,
    patch_context: PatchContext,
    data: dict
) -> None:
    """
    Inject Payload
    """
    if service in INJECTION_PROXY:
        return INJECTION_PROXY[service](operation, patch_context, data)


def common_tags_api_call(
    patch_context: PatchContext,
    return_context: ReturnContext
) -> dict:
    """
    Extracts common AWS SDK tags
    """
    meta = getattr(patch_context.instance, "meta", None)
    operation_name = get_arg_by_key_or_pos(
        patch_context.args,
        patch_context.kwargs,
        pos=0,
        kw="operation_name")

    try:
        op_model = meta.service_model.operation_model(operation_name)
        _http_method = op_model.http.get("method")
        _http_uri = op_model.http.get("requestUri")
    except Exception:
        _http_method, _http_uri = None, None

    _status = None
    if return_context.response:
        _status = return_context.response.get(
            "ResponseMetadata",
            {}).get("HTTPStatusCode")

    return {
        "request_method": _http_method,
        "request_url": getattr(meta, "endpoint_url"),
        "request_status": _status,
        "request_uri": _http_uri}


def aws_api_parameters(patch_context: PatchContext) -> dict:
    return get_arg_by_key_or_pos(
        patch_context.args,
        patch_context.kwargs,
        pos=1,
        kw="api_params",
        default={})


def aws_request_id(return_context: ReturnContext) -> str:
    if return_context.response:
        return return_context.response.get(
            "ResponseMetadata", {}).get("RequestId")

    return None


"""
AWS Outbound
"""


def lambda_outbound(
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext,
    tags: dict = {}
) -> List[Type[OutboundContext]]:
    """
    Lambda Contexts
    """
    if operation != AWSOperation.LAMBDA_INVOKE:
        return

    api_parameters = aws_api_parameters(patch_context)
    request_id = aws_request_id(return_context)
    function_name = api_parameters.get("FunctionName")

    trigger_sync = TriggerSynchronicity.SYNC
    if "InvokeArgs" in api_parameters or api_parameters.get(
            "InvocationType") == "Event":
        trigger_sync = TriggerSynchronicity.ASYNC

    return [OutboundContext(
        provider=Provider.AWS,
        service=AWSService.LAMBDA,
        operation=operation,
        trigger_synchronicity=trigger_sync,
        tags=tags,
        identifier={
            "request_id": request_id,
            "function_name": function_name})]


def s3_outbound(
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext,
    tags: dict = {}
) -> List[Type[OutboundContext]]:
    """
    S3 Contexts
    """
    api_parameters = aws_api_parameters(patch_context)

    bucket_name = api_parameters.get("Bucket")
    key = api_parameters.get("Key")

    request_id = aws_request_id(return_context)
    size = get_s3_size(patch_context, return_context)

    return [OutboundContext(
        provider=Provider.AWS,
        service=AWSService.S3,
        operation=operation,
        trigger_synchronicity=TriggerSynchronicity.ASYNC,
        tags={"size": size, **tags},
        identifier={
            "request_id": request_id,
            "bucket_name": bucket_name,
            "object_key": key})]


def get_s3_size(
    patch_context: PatchContext,
    return_context: ReturnContext,
) -> float:
    """
    Returns the size of the object of a S3 Access
    """
    api_parameters = aws_api_parameters(patch_context)
    response = return_context.response

    if return_context.response:
        content_length = response.get(
            "ContentLength", response.get("content-length"))
        if not content_length:
            req_meta_data = response.get("ResponseMetadata")
            content_length = req_meta_data.get(
                "ContentLength", req_meta_data.get("content-length"))

        if content_length:
            return content_length

    if "Body" in api_parameters:
        body = api_parameters["Body"]
        if isinstance(body, io.BytesIO):
            return body.getbuffer().nbytes
        else:
            return getattr(body, "_size", None)

    return None


def dynamodb_outbound(self, tags: dict = {}) -> List[Type[OutboundContext]]:
    """
    DynamoDB contexts
    """
    return []
    # json.dumps(self.api_parameters["Item"], sort_keys=True)
    # sha256 = hashlib.sha256()
    # sha256.update(foo.encode("utf-8"))
    # sha256.hexdigest()


def sqs_outbound(
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext,
    tags: dict = {}
) -> List[Type[OutboundContext]]:
    """
    SQS Contexts
    """
    contexts = []
    api_parameters = aws_api_parameters(patch_context)
    queue_url = sqs_resource_name(api_parameters.get("QueueUrl"))

    if operation == AWSOperation.SQS_SEND_BATCH:
        for entry in return_context.response.get("Successful", []):
            message_id = entry.get("MessageId")
            contexts.append(OutboundContext(
                provider=Provider.AWS,
                service=AWSService.SQS,
                operation=operation,
                trigger_synchronicity=TriggerSynchronicity.ASYNC,
                tags=tags,
                identifier={
                    "message_id": message_id,
                    "queue_url": queue_url
                }))
    elif operation == AWSOperation.SQS_SEND:
        message_id = return_context.response.get("MessageId")
        contexts.append(OutboundContext(
            provider=Provider.AWS,
            service=AWSService.SQS,
            operation=operation,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            tags=tags,
            identifier={
                "message_id": message_id,
                "queue_url": queue_url
            }))

    return contexts


def sns_outbound(
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext,
    tags: dict = {}
) -> List[Type[OutboundContext]]:
    """
    SNS Contexts
    """
    contexts = []
    api_parameters = aws_api_parameters(patch_context)
    topic_arn = api_parameters.get("TopicArn")
    if operation == AWSOperation.SNS_PUBLISH_BATCH:
        for entry in return_context.response.get("Successful", []):
            message_id = entry.get("MessageId")
            contexts.append(OutboundContext(
                provider=Provider.AWS,
                service=AWSService.SNS,
                operation=operation,
                trigger_synchronicity=TriggerSynchronicity.ASYNC,
                tags=tags,
                identifier={
                    "message_id": message_id,
                    "topic_arn": topic_arn
                }))
    elif operation == AWSOperation.SNS_PUBLISH:
        message_id = return_context.response.get("MessageId")
        contexts.append(OutboundContext(
            provider=Provider.AWS,
            service=AWSService.SNS,
            operation=operation,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            tags=tags,
            identifier={
                "message_id": message_id,
                "topic_arn": topic_arn
            }))

    return contexts


def event_outbound(
    operation: AWSOperation,
    patch_context: PatchContext,
    return_context: ReturnContext,
    tags: dict = {}
) -> List[Type[OutboundContext]]:
    """
    Event Bridge Context
    """
    contexts = []

    for entry in return_context.response.get("Entries"):
        event_id = entry.get("EventId")
        if not event_id:
            continue

        contexts.append(OutboundContext(
            provider=Provider.AWS,
            service=AWSService.EVENTBRIDGE,
            operation=operation,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            tags=tags,
            identifier={
                "event_id": event_id
            }))

    return contexts


OUTBOUND_PROXY = {
    AWSService.LAMBDA: lambda_outbound,
    AWSService.S3: s3_outbound,
    AWSService.DYNAMO_DB: dynamodb_outbound,
    AWSService.SQS: sqs_outbound,
    AWSService.SNS: sns_outbound,
    AWSService.EVENTBRIDGE: event_outbound
}

"""
AWS Injection
"""


def inject_lambda(
    operation: AWSOperation,
    patch_context: PatchContext,
    data: dict
) -> None:
    """
    Injects data to AWS Lambda call

    The Client Context is passed as Base64 object in the api parameters.
    Thus we need to encode the context (if existing), add our tracing context
    and then decode in back to Base64

    More info: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
    """
    api_parameters = aws_api_parameters(patch_context)

    client_context = {}
    if "ClientContext" in api_parameters:
        try:
            client_context = decode_base64_json_to_dict(
                api_parameters["ClientContext"])
        except ValueError as err:
            raise InjectionError(
                f"Could not decode client context from base64 to json: {err}")

    # Injection
    client_context.setdefault("custom", {}).update(data)

    try:
        api_parameters["ClientContext"] = encode_dict_to_base64_json(
            client_context)
    except ValueError as err:
        raise InjectionError(
            f"Could not encode client context from json to base64: {err}")


def inject_sqs(
    operation: AWSOperation,
    patch_context: PatchContext,
    data: dict
) -> None:
    """
    Injects data to AWS SQS Message Attributes
    """
    api_parameters = aws_api_parameters(patch_context)

    def _inject_message_entry(message):
        msg_attr = message.setdefault("MessageAttributes", {})
        msg_attr[TRACE_CONTEXT_KEY] = {
            "DataType": "String", "StringValue": json.dumps(data)}

    if operation == AWSOperation.SQS_SEND:
        _inject_message_entry(api_parameters)
    elif operation == AWSOperation.SQS_SEND_BATCH:
        for entry in api_parameters.get("Entries", []):
            _inject_message_entry(entry)


def inject_sns(
    operation: AWSOperation,
    patch_context: PatchContext,
    data: dict
) -> None:
    """
    Injects data to AWS SNS Message Attributes
    """
    api_parameters = aws_api_parameters(patch_context)

    def _inject_message_entry(message):
        msg_attr = message.setdefault("MessageAttributes", {})
        msg_attr[TRACE_CONTEXT_KEY] = {
            "DataType": "Binary", "BinaryValue": json.dumps(data)}

    if operation == AWSOperation.SNS_PUBLISH:
        _inject_message_entry(api_parameters)
    elif operation == AWSOperation.SNS_PUBLISH_BATCH:
        for entry in api_parameters.get(
                "PublishBatchRequestEntries", []):
            _inject_message_entry(entry)


def inject_event(
    operation: AWSOperation,
    patch_context: PatchContext,
    data: dict
) -> None:
    """
    Injects data to AWS Event bridge detail
    """
    api_parameters = aws_api_parameters(patch_context)

    for entry in api_parameters.get("Entries", []):
        _detail = entry.get("Detail", r"{}")
        _detail_obj = json.loads(_detail)

        _detail_obj[TRACE_CONTEXT_KEY] = data

        entry["Detail"] = json.dumps(_detail_obj)


INJECTION_PROXY = {
    AWSService.LAMBDA: inject_lambda,
    AWSService.SQS: inject_sqs,
    AWSService.SNS: inject_sns,
    AWSService.EVENTBRIDGE: inject_event
}
