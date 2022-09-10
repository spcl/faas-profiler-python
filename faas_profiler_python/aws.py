#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all AWS specific logic.
"""
import json

from collections import namedtuple
from datetime import datetime
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
from faas_profiler_python.patchers import PatchContext

from faas_profiler_python.utilis import (
    Loggable,
    decode_base64_json_to_dict,
    encode_dict_to_base64_json,
    get_arg_by_key_or_pos,
    lowercase_keys, get_idx_safely
)
from faas_profiler_python.config import InjectionError

"""
ARN Parsing
"""

ARN = namedtuple(
    "ARN",
    "partition service region account_id resource_type resource")


def parse_aws_arn(arn: str) -> Type[ARN]:
    parts = str(arn).split(":")
    if get_idx_safely(parts, 0) != "arn":
        raise ValueError(f"ARN {arn} is not a valid arn.")

    service = get_idx_safely(parts, 2)
    resource = get_idx_safely(parts, 5)
    resource_type = None

    if service not in ['s3', 'sns', 'apigateway', 'execute-api']:
        sep_idx = [resource.find(sep) for sep in [":", "/"] if sep in resource]
        if sep_idx:
            resource_type = resource[:min(sep_idx)]
            resource = resource[min(sep_idx) + 1:]

    return ARN(
        partition=get_idx_safely(parts, 1),
        service=service,
        region=get_idx_safely(parts, 3),
        account_id=get_idx_safely(parts, 4),
        resource_type=resource_type,
        resource=resource)


"""
AWS Context Resolving
"""


class AWSEvent(Loggable):

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

    def resolve_event(self) -> Tuple[AWSService, AWSOperation]:  # noqa: C901
        """
        Resolves the service and operation triggering this event.
        """
        service = AWSService.UNIDENTIFIED
        operation = AWSService.UNIDENTIFIED

        if self._is_lambda_function_url():
            service = AWSService.LAMBDA
        elif self._is_cloud_front():
            service = AWSService.CLOUDFRONT
        elif self._is_dynamodb():
            service = AWSService.DYNAMO_DB
            operation = AWSOperation.DYNAMO_DB_UPDATE
        elif self._is_cloud_formation():
            service = AWSService.CLOUD_FORMATION
        elif self._is_sqs():
            service = AWSService.SQS
            operation = AWSOperation.SQS_RECEIVE
        elif self._is_sns():
            service = AWSService.SNS
            operation = AWSOperation.SNS_TOPIC_NOTIFICATION
        elif self._is_ses():
            service = AWSService.SES
            operation = AWSOperation.SES_EMAIL_RECEIVE
        elif self._is_s3():
            service = AWSService.S3
            operation = self._get_s3_operation()
        elif self._is_code_commit():
            service = AWSService.CODE_COMMIT
        elif self._is_aws_config():
            service = AWSService.AWS_CONFIG
        elif self._is_kinesis_analytics():
            service = AWSService.KINESIS
        elif self._is_kinesis_firehose():
            service = AWSService.KINESIS
        elif self._is_kinesis_stream():
            service = AWSService.KINESIS
        elif self._is_gateway_http():
            service = AWSService.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_HTTP
        elif self._is_gateway_proxy():
            service = AWSService.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_AWS_PROXY
        elif self._is_gateway_authorization():
            service = AWSService.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_AUTHORIZER

        return service, operation

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns context about the trigger
        """
        trigger_ctx = InboundContext(
            Provider.AWS,
            self.service,
            self.operation,
            {},
            invoked_at=datetime.now())

        if self.service == AWSService.S3:
            self._add_s3_trigger_context(trigger_ctx)
        elif self.service == AWSService.DYNAMO_DB:
            self._add_dynamodb_context(trigger_ctx)
        elif self.service == AWSService.LAMBDA:
            self._add_lambda_context()

        return trigger_ctx

    def extract_trace_context(self) -> Type[TracingContext]:
        """
        Extracts trace context from event data
        """
        trace_context = self._payload_tracing_context()
        if trace_context:
            return trace_context

        # if "headers" in self.data:
        #     return self._http_tracing_context()
        # if self.service == EventTypes.CLOUDWATCH_SCHEDULED_EVENT:
        #     return self._scheduled_event_context()

        # Default case: Return empty trace context
        return None

    def _payload_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts tracing context from payload
        """
        if TRACE_CONTEXT_KEY in self.data:
            trace_ctx = self.data[TRACE_CONTEXT_KEY]
            return TracingContext(
                trace_id=trace_ctx.get(TRACE_ID_HEADER),
                record_id=trace_ctx.get(RECORD_ID_HEADER),
                parent_id=trace_ctx.get(PARENT_ID_HEADER))

        return None

    def _http_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts the tracing context from http headers.
        """
        headers = lowercase_keys(self.data.get("headers", {}))
        return TracingContext(
            trace_id=headers.get(TRACE_ID_HEADER),
            record_id=headers.get(RECORD_ID_HEADER),
            parent_id=headers.get(PARENT_ID_HEADER))

    def _sns_tracing_context(self) -> Type[TracingContext]:
        # TODO
        pass

    def _sqs_tracing_context(self) -> Type[TracingContext]:
        # TODO
        pass

    def _scheduled_event_context(self) -> Type[TracingContext]:
        """
        Extracts the tracing context from detail values.
        """
        detail = lowercase_keys(self.data.get("detail", {}))
        context = detail.get(TRACE_CONTEXT_KEY, {})
        return TracingContext(
            trace_id=context.get(TRACE_CONTEXT_KEY),
            record_id=context.get(RECORD_ID_HEADER),
            parent_id=context.get(PARENT_ID_HEADER))

    def _add_s3_trigger_context(
            self, trigger_context: Type[InboundContext]) -> None:
        """
        Adds S3 specific trigger information.
        """
        trigger_context.trigger_synchronicity = TriggerSynchronicity.ASYNC
        _s3_record = self._get_first_record()
        _bucket = _s3_record.get("s3", {}).get("bucket")
        _object = _s3_record.get("s3", {}).get("object")

        trigger_context.set_tags({
            "bucket_name": _bucket.get("name"),
            "bucket_arn": _bucket.get("arn"),
            "object_key": _object.get("key"),
            "object_etag": _object.get("eTag")
        })

        trigger_context.set_identifiers({
            "request_id": _s3_record.get("responseelements", {}).get("x-amz-request-id"),
            "object_key": _object.get("key"),
            "bucket_name": _bucket.get("name")
        })

    def _add_dynamodb_context(
        self,
        trigger_context: Type[InboundContext]
    ) -> None:
        """
        Add DynamoDB trigger information
        """
        trigger_context.trigger_synchronicity = TriggerSynchronicity.ASYNC
        _db_record = self._get_first_record()
        _dynamodb_arn = _db_record.get("eventsourcearn")
        _table_name = None
        if _dynamodb_arn:
            _dynamodb_arn = parse_aws_arn(_dynamodb_arn)
            if _dynamodb_arn.resource_type == "table":
                _table_name = str(_dynamodb_arn.resource).split("/")[0]

        _items = []
        for record in self.data.get("records", []):
            _item = record.get("dynamodb", {}).get("NewImage")
            if _item:
                _items.append(_item)

        trigger_context.set_identifiers({
            "table_name": _table_name,
            "items": _items
        })

    # Helpers

    def _has_records(self) -> bool:
        return 'records' in self.data and len(self.data['records']) > 0

    def _get_first_record(self) -> dict:
        if not self._has_records():
            return {}

        try:
            return lowercase_keys(self.data['records'][0])
        except (IndexError, KeyError):
            return {}

    def _get_event_source(self) -> str:
        return self._get_first_record.get('eventsource', None)

    def _is_lambda_function_url(self) -> bool:
        # request_context = lowercase_keys(self.data.get("requestcontext", {}))
        # domain_name = request_context.get("domainname")

        return False

    def _is_cloud_formation(self) -> bool:
        return 'stackid' in self.data and 'requesttype' in self.data and 'resourcetype' in self.data

    def _is_cloud_front(self) -> bool:
        return 'cf' in self._get_first_record()

    def _is_cloudwatch_logs(self) -> bool:
        return "data" in self.data.get("awslogs", {})

    def _is_cloudwatch_scheduled_event(self) -> bool:
        return self.data.get("source") == "aws.events"

    def _is_dynamodb(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:dynamodb"

    def _is_s3(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:s3"

    def _get_s3_operation(self) -> AWSOperation:
        event_name = self._get_first_record().get("eventname")
        if event_name is None:
            return AWSOperation.UNIDENTIFIED

        _operation = str(event_name).split(":")[0]
        if _operation == "ObjectCreated":
            return AWSOperation.S3_OBJECT_CREATE
        elif _operation == "ObjectRemoved":
            return AWSOperation.S3_OBJECT_REMOVED

        return AWSOperation.UNIDENTIFIED

    def _is_sns(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:sns"

    def _is_sqs(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:sqs"

    def _is_ses(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:ses"

    def _is_aws_config(self) -> bool:
        return "configruleid" in self.data and "configrulename" in self.data and "configrulearn" in self.data

    def _is_code_commit(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:codecommit"

    def _is_kinesis_analytics(self) -> bool:
        if "applicationarn" in self.data:
            return parse_aws_arn(
                self.data["applicationarn"]).service == "kinesisanalytics"

        return False

    def _is_kinesis_firehose(self) -> bool:
        if not self._has_records():
            return False

        if "approximatearrivaltimestamp" in self._get_first_record():
            return True

        if "deliverystreamarn" in self.data:
            delivery_arn = parse_aws_arn(self.data["deliverystreamarn"])
            return delivery_arn.service == "kinesis"

        return False

    def _is_kinesis_stream(self) -> bool:
        return self._get_first_record().get("eventsource") == "aws:kinesis"

    def _is_gateway_proxy(self) -> bool:
        return "proxy" in self.data.get("pathparameters", {})

    def _is_gateway_http(self) -> bool:
        return "resourceid" in lowercase_keys(self.data.get(
            "requestcontext", {})) and not self._is_gateway_proxy()

    def _is_gateway_authorization(self) -> bool:
        return self.data.get("authorizationtoken") == "incoming-client-token"


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
            invoked_at=datetime.now(),
            identifier={
                "function_name": _function_name,
                "request_id": _request_id})


"""
AWS Outbound
"""


class AWSOutbound(Loggable):

    OUTBOUND_PROXY = {
        AWSService.LAMBDA: "lambda_outbound",
        AWSService.S3: "s3_outbound",
        AWSService.DYNAMO_DB: "dynamodb_outbound",
        AWSService.SQS: "sqs_outbound"
    }

    INJECTION_PROXY = {
        AWSService.LAMBDA: "inject_lambda",
        AWSService.SQS: "inject_sqs"
    }

    def __init__(
        self,
        service: AWSService,
        operation: AWSOperation,
        patch_context: Type[PatchContext]
    ) -> None:
        super().__init__()

        self.service = service
        self.operation = operation
        self.patch_context = patch_context

        self.api_parameters = get_arg_by_key_or_pos(
            patch_context.args,
            patch_context.kwargs,
            pos=1,
            kw="api_params",
            default={})

    def extract_outbound_contexts(self) -> List[Type[OutboundContext]]:
        """
        Extracts all outbound contexts
        """
        tags = self._common_tags()
        print(tags)
        if self.service in self.OUTBOUND_PROXY:
            return getattr(
                self, self.OUTBOUND_PROXY[self.service])(tags)
        else:
            self.logger.error(
                f"[AWS OUTBOUND]: No handler defined for {self.service}")
            return []

    def inject_payload(self, data: dict) -> None:
        """
        Inject Payload
        """
        if self.service in self.INJECTION_PROXY:
            getattr(
                self, self.INJECTION_PROXY[self.service])(data)
            self.logger.error(
                f"[AWS INJECTION]: Payload injected for {self.service}")
        else:
            self.logger.error(
                f"[AWS INJECTION]: No injection handler defined for {self.service}")

    def _common_tags(self) -> dict:
        """
        Extracts common AWS SDK tags
        """
        meta = getattr(self.patch_context.instance, "meta", None)
        operation_name = get_arg_by_key_or_pos(
            self.patch_context.args,
            self.patch_context.kwargs,
            pos=0,
            kw="operation_name")

        try:
            op_model = meta.service_model.operation_model(operation_name)
            _http_method = op_model.http.get("method")
            _http_uri = op_model.http.get("requestUri")
        except Exception:
            _http_method, _http_uri = None, None

        _response = self.patch_context.response
        _status = None
        if _response:
            _status = _response.get(
                "ResponseMetadata",
                {}).get("HTTPStatusCode")

        return {
            "parameters": {
                str(k): str(v) for k, v in self.api_parameters.items()},
            "request_method": _http_method,
            "request_url": getattr(meta, "endpoint_url"),
            "request_status": _status,
            "request_uri": _http_uri}

    """
    AWS Outbound
    """

    def lambda_outbound(self, tags: dict = {}) -> List[Type[OutboundContext]]:
        """
        Lambda Contexts
        """
        if self.operation != AWSOperation.LAMBDA_INVOKE:
            return

        _response = self.patch_context.response
        _request_id = None
        if _response and "ResponseMetadata" in _response:
            _request_id = _response["ResponseMetadata"].get("RequestId")

        _function_name = self.api_parameters.get("FunctionName")

        _trigger_sync = TriggerSynchronicity.SYNC
        if "InvokeArgs" in self.api_parameters or self.api_parameters.get(
                "InvocationType") == "Event":
            _trigger_sync = TriggerSynchronicity.ASYNC

        return [OutboundContext(
            provider=Provider.AWS,
            service=self.service,
            operation=self.operation,
            trigger_synchronicity=_trigger_sync,
            tags=tags,
            identifier={
                "request_id": _request_id,
                "function_name": _function_name})]

    def s3_outbound(self, tags: dict = {}) -> List[Type[OutboundContext]]:
        """
        S3 Contexts
        """
        if (self.operation != AWSOperation.S3_OBJECT_CREATE and
                self.operation != AWSOperation.S3_OBJECT_REMOVED):
            return

        _response = self.patch_context.response

        _bucket_name = self.api_parameters.get("Bucket")
        _key = self.api_parameters.get("Key")

        _request_id = None
        if _response and "ResponseMetadata" in _response:
            _request_id = _response["ResponseMetadata"].get("RequestId")

        _body_size, _content_length = None, None

        if _response:
            if "ContentLength" in _response or "content-length" in _response:
                _content_length = _response.get(
                    "content-length") or _response.get("ContentLength")
            elif "ResponseMetadata" in _response:
                req_meta_data = _response["ResponseMetadata"]
                _content_length = req_meta_data.get(
                    "content-length") or req_meta_data.get("ContentLength")

        if "Body" in self.api_parameters:
            _body_size = getattr(self.api_parameters["Body"], "_size", None)

        if self.operation == AWSOperation.S3_OBJECT_CREATE:
            _size = _body_size if _body_size else _content_length
        else:
            _size = _content_length if _content_length else _body_size

        return [OutboundContext(
            provider=Provider.AWS,
            service=self.service,
            operation=self.operation,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            tags={"size": _size, **tags},
            identifier={
                "request_id": _request_id,
                "bucket_name": _bucket_name,
                "object_key": _key})]

    def dynamodb_outboun(self, tags: dict = {}) -> List[Type[OutboundContext]]:
        """
        DynamoDB contexts
        """
        return []
        # json.dumps(self.api_parameters["Item"], sort_keys=True)
        # sha256 = hashlib.sha256()
        # sha256.update(foo.encode("utf-8"))
        # sha256.hexdigest()

    def sqs_outbound(self, tags: dict = {}) -> List[Type[OutboundContext]]:
        """
        SQS Contexts
        """
        contexts = []
        _queue_url = self.api_parameters.get("QueueUrl")
        _response = self.patch_context.response
        if self.operation == AWSOperation.SQS_SEND_BATCH:
            for entry in _response.get("Successful", []):
                _message_id = entry.get("MessageId")
                contexts.append(OutboundContext(
                    provider=Provider.AWS,
                    service=self.service,
                    operation=self.operation,
                    trigger_synchronicity=TriggerSynchronicity.ASYNC,
                    tags=tags,
                    identifier={
                        "message_id": _message_id,
                        "queue_url": _queue_url
                    }))
        elif self.operation == AWSOperation.SQS_SEND:
            _message_id = _response.get("MessageId")
            contexts.append(OutboundContext(
                provider=Provider.AWS,
                service=self.service,
                operation=self.operation,
                trigger_synchronicity=TriggerSynchronicity.ASYNC,
                tags=tags,
                identifier={
                    "message_id": _message_id,
                    "queue_url": _queue_url
                }))

        return contexts

    """
    AWS Injection
    """

    def inject_lambda(self, data: dict):
        """
        Injects data to AWS Lambda call

        The Client Context is passed as Base64 object in the api parameters.
        Thus we need to encode the context (if existing), add our tracing context
        and then decode in back to Base64

        More info: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
        """
        client_context = {}
        if "ClientContext" in self.api_parameters:
            try:
                client_context = decode_base64_json_to_dict(
                    self.api_parameters["ClientContext"])
            except ValueError as err:
                raise InjectionError(
                    f"Could not decode client context from base64 to json: {err}")

        #     payload = {}
        #     if "Payload" in api_parameters:
        #         try:
        #             payload = json.loads(api_parameters["Payload"].decode('utf-8'))
        #         except json.JSONDecodeError as err:
        #             raise InjectionError(
        #                 f"Could not decode payload to json: {err}")

        # Injection
        client_context.setdefault("custom", {}).update(data)

        try:
            self.api_parameters["ClientContext"] = encode_dict_to_base64_json(
                client_context)
        except ValueError as err:
            raise InjectionError(
                f"Could not encode client context from json to base64: {err}")

    def inject_sqs(self, data: dict) -> None:
        """
        Injects data to AWS SQS Message Attributes
        """
        def _inject_message_entry(message):
            msg_attr = message.setdefault("MessageAttributes", {})
            msg_attr[TRACE_CONTEXT_KEY] = {
                "DataType": "String", "StringValue": json.dumps(data)}

        if self.operation == AWSOperation.SQS_SEND:
            _inject_message_entry(self.api_parameters)
        elif self.operation == AWSOperation.SQS_SEND_BATCH:
            for entry in self.api_parameters.get("Entries", []):
                _inject_message_entry(entry)
