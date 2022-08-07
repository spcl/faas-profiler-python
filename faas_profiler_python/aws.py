#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all AWS specific logic.
"""

from collections import namedtuple
from datetime import datetime
from typing import Any, Tuple, Type

from faas_profiler_core.models import TracingContext, InboundContext
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

from faas_profiler_python.utilis import (
    Loggable,
    decode_base64_json_to_dict,
    encode_dict_to_base64_json,
    lowercase_keys, get_idx_safely
)
from faas_profiler_python.config import (
    UnsupportedServiceError,
    InjectionError
)

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
        operation = AWSOperation.UNIDENTIFIED

        # EventTypes.CLOUDWATCH_LOGS: self._is_cloudwatch_logs,
        # EventTypes.CLOUDWATCH_SCHEDULED_EVENT:
        # self._is_cloudwatch_scheduled_event,

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

        return trigger_ctx

    def extract_trace_context(self) -> Type[TracingContext]:
        # if "headers" in self.data:
        #     return self._http_tracing_context()
        # if self.service == EventTypes.CLOUDWATCH_SCHEDULED_EVENT:
        #     return self._scheduled_event_context()

        # Default case: Return empty trace context
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


"""
AWS Service detection
"""

SERVICE_BY_ENDPOINT = {
    "lambda": AWSService.LAMBDA,
    "s3": AWSService.S3
}


def service_by_outbound_endpoint(endpoint_prefix: str) -> AWSService:
    """
    Returns the AWS Service by service endpoint prefix
    """
    return SERVICE_BY_ENDPOINT.get(endpoint_prefix, AWSService.UNIDENTIFIED)


"""
AWS Operation detection
"""

OPERATION_BY_NAME = {
    AWSService.LAMBDA: {
        "invoke": AWSOperation.LAMBDA_INVOKE
    },
    AWSService.S3: {
        "putobject": AWSOperation.S3_OBJECT_CREATE
    }
}


def operation_by_operation_name(
        service: AWSService,
        operation_name: str) -> AWSOperation:
    """
    Returns the AWS Operation based on service and operation name
    """
    service_operations = OPERATION_BY_NAME.get(service)
    if service_operations:
        return service_operations.get(
            operation_name, AWSOperation.UNIDENTIFIED)

    return AWSOperation.UNIDENTIFIED


"""
AWS outbound identifier detection
"""


def get_outbound_identifiers(
    service: AWSService,
    operation: AWSOperation,
    api_parameters: dict = {},
    api_response: dict = {}
) -> dict:
    """
    Returns a dict of identifiers for the outbound AWS call.
    """
    identifiers = {}

    api_parameters = lowercase_keys(api_parameters)
    api_response = lowercase_keys(api_response)

    request_id = api_response.get("responsemetadata", {}).get("RequestId")
    if request_id:
        identifiers["request_id"] = request_id

    if service == AWSService.S3:
        service_identifiers_function = get_outbound_s3_identifiers
    elif service == AWSService.LAMBDA:
        service_identifiers_function = get_outbound_lambda_identifiers

    if service_identifiers_function:
        identifiers.update(service_identifiers_function(
            operation, api_parameters, api_response))

    return identifiers


def get_outbound_s3_identifiers(
    operation: AWSOperation,
    api_parameters: dict,
    api_response: dict
) -> dict:
    """
    Extracts outbound s3 identifiers
    """
    identifiers = {}
    _bucket_name = api_parameters.get("bucket")
    _key = api_parameters.get("key")

    if _bucket_name:
        identifiers["bucket_name"] = _bucket_name
    if _key:
        identifiers["object_key"] = _key

    return identifiers


def get_outbound_lambda_identifiers(
    operation: AWSOperation,
    api_parameters: dict,
    api_response: dict
) -> dict:
    """
    Extracts outbound Lambda identifiers
    """
    _function_name = api_parameters.get("functionname")
    if _function_name:
        return {"function_name": _function_name}

    return {}


"""
AWS Injection
"""


def inject_lambda_call(
    operation: AWSOperation,
    api_parameters: dict,
    injection_data: dict
):
    """
    Injects data to AWS Lambda call

    The Client Context is passed as Base64 object in the api parameters.
    Thus we need to encode the context (if existing), add our tracing context
    and then decode in back to Base64

    More info: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
    """
    client_context = {}
    if "ClientContext" in api_parameters:
        try:
            client_context = decode_base64_json_to_dict(
                api_parameters["ClientContext"])
        except ValueError as err:
            raise InjectionError(
                f"Could not decode client context from base64 to json: {err}")

    # Injection
    client_context.setdefault("custom", {}).update(injection_data)

    try:
        api_parameters["ClientContext"] = encode_dict_to_base64_json(
            client_context)
    except ValueError as err:
        raise InjectionError(
            f"Could not encode client context from json to base64: {err}")


INJECTABLE_SERVICES = {
    AWSService.LAMBDA: inject_lambda_call
}


def inject_aws_call(
    service: AWSService,
    operation: AWSOperation,
    api_parameters: dict,
    injection_data: dict,
) -> None:
    """
    Injects data into api parameters
    """
    if service not in INJECTABLE_SERVICES:
        raise UnsupportedServiceError(
            f"AWS API call {service} does not support injection.")

    INJECTABLE_SERVICES[service](
        operation, api_parameters, injection_data)
