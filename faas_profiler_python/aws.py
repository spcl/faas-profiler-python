#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all AWS specific logic.
"""

from collections import namedtuple
import logging

from enum import Enum
from typing import Any, Tuple, Type

from faas_profiler_python.utilis import lowercase_keys, get_idx_safely
from faas_profiler_python.config import (
    Provider,
    TracingContext,
    InboundContext,
    Service,
    Operation,
    TRACE_ID_HEADER,
    INVOCATION_ID_HEADER,
    PARENT_ID_HEADER,
    TRACE_CONTEXT_KEY,
    TriggerSynchronicity,
)

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


class EventTypes(Enum):
    """
    Enumeration of different AWS Event Types (incomming invocation)
    """
    UNIDENTIFIED = 'unidentified'
    API_GATEWAY_AWS_PROXY = 'api_gateway_aws_proxy'
    API_GATEWAY_HTTP = 'api_gateway_http'
    S3 = 'S3'
    SNS = 'sns'
    DYNAMO_DB = 'dynamodb'
    CLOUDFRONT = 'cloudfront'
    CLOUDWATCH_SCHEDULED_EVENT = 'cloudwatch_scheduled_event'
    CLOUDWATCH_LOGS = 'cloudwatch_logs'
    API_GATEWAY_AUTHORIZER = 'api_gateway_authorizer'
    AWS_CONFIG = 'aws_config'
    CLOUD_FORMATION = 'cloud_formation'
    CODE_COMMIT = 'code_commit'
    SES = 'ses'
    SQS = 'sqs'
    KINESIS_STREAM = 'kinesis_stream'
    KINESIS_FIREHOSE = 'kinesis_firehose'
    KINESIS_ANALYTICS = 'kinesis_analytics'
    COGNITO_SYNC_TRIGGER = 'cognito_sync_trigger'
    MOBILE_BACKEND = 'is_mobile_backend'


class AWSServices(Service):
    """
    Enumeration of different AWS services
    """
    UNIDENTIFIED = 'unidentified'
    LAMBDA = "lambda"
    CLOUDFRONT = 'cloudfront'
    DYNAMO_DB = 'dynamodb'
    CLOUD_FORMATION = 'cloud_formation'
    SNS = 'sns'
    SES = 'ses'
    SQS = 'sqs'
    S3 = "s3"
    CODE_COMMIT = 'code_commit'
    AWS_CONFIG = 'aws_config'
    KINESIS = 'kinesis'
    API_GATEWAY = 'api_gateway'


class AWSOperation(Operation):
    """
    Enumeration of different AWS Operations
    """
    UNIDENTIFIED = 'unidentified'
    # S3
    S3_OBJECT_CREATE = "ObjectCreated"  # Combines: PUT, POST, COPY
    S3_OBJECT_REMOVED = "ObjectRemoved"  # Combines: permanently and marked deleted

    # Dynamo DB
    DYNAMO_DB_UPDATE = "Update"  # Combines: INSERT, MODIFY, DELETE

    # GATEWAY
    API_GATEWAY_AWS_PROXY = 'GatewayProxy'
    API_GATEWAY_HTTP = 'GatewayAPI'
    API_GATEWAY_AUTHORIZER = 'GatewayAuthorizer'

    # SQS
    SQS_RECEIVE = "ReceiveMessage"

    # SNS
    SNS_TOPIC_NOTIFICATION = "TopicNotification"

    # SES
    SES_EMAIL_RECEIVE = "ReceiveEmail"


class AWSEvent:

    _logger = logging.getLogger("AWSEvent")
    _logger.setLevel(logging.INFO)

    def __init__(
        self,
        event_data: dict
    ) -> None:
        if not isinstance(event_data, dict):
            self._logger.error(
                f"AWS Event data must be a dict, got {type(event_data)}. Cannot parse Event.")
            event_data = {}

        self.data = lowercase_keys(event_data)
        self.service, self.operation = self.resolve_event()

    def resolve_event(self) -> Tuple[AWSServices, AWSOperation]:  # noqa: C901
        """
        Resolves the service and operation triggering this event.
        """
        service = AWSServices.UNIDENTIFIED
        operation = AWSOperation.UNIDENTIFIED

        # EventTypes.CLOUDWATCH_LOGS: self._is_cloudwatch_logs,
        # EventTypes.CLOUDWATCH_SCHEDULED_EVENT:
        # self._is_cloudwatch_scheduled_event,

        if self._is_lambda_function_url():
            service = AWSServices.LAMBDA
        elif self._is_cloud_front():
            service = AWSServices.CLOUDFRONT
        elif self._is_dynamodb():
            service = AWSServices.DYNAMO_DB
            operation = AWSOperation.DYNAMO_DB_UPDATE
        elif self._is_cloud_formation():
            service = AWSServices.CLOUD_FORMATION
        elif self._is_sqs():
            service = AWSServices.SQS
            operation = AWSOperation.SQS_RECEIVE
        elif self._is_sns():
            service = AWSServices.SNS
            operation = AWSOperation.SNS_TOPIC_NOTIFICATION
        elif self._is_ses():
            service = AWSServices.SES
            operation = AWSOperation.SES_EMAIL_RECEIVE
        elif self._is_s3():
            service = AWSServices.S3
            operation = self._get_s3_operation()
        elif self._is_code_commit():
            service = AWSServices.CODE_COMMIT
        elif self._is_aws_config():
            service = AWSServices.AWS_CONFIG
        elif self._is_kinesis_analytics():
            service = AWSServices.KINESIS
        elif self._is_kinesis_firehose():
            service = AWSServices.KINESIS
        elif self._is_kinesis_stream():
            service = AWSServices.KINESIS
        elif self._is_gateway_http():
            service = AWSServices.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_HTTP
        elif self._is_gateway_proxy():
            service = AWSServices.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_AWS_PROXY
        elif self._is_gateway_authorization():
            service = AWSServices.API_GATEWAY
            operation = AWSOperation.API_GATEWAY_AUTHORIZER

        return service, operation

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns context about the trigger
        """
        trigger_ctx = InboundContext(
            Provider.AWS, self.service, self.operation)

        if self.service == AWSServices.S3:
            self._add_s3_trigger_context(trigger_ctx)

        return trigger_ctx

    def extract_trace_context(self) -> Type[TracingContext]:
        # if "headers" in self.data:
        #     return self._http_tracing_context()
        # if self.service == EventTypes.CLOUDWATCH_SCHEDULED_EVENT:
        #     return self._scheduled_event_context()

        # Default case: Return empty trace context
        return TracingContext()

    def _http_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts the tracing context from http headers.
        """
        headers = lowercase_keys(self.data.get("headers", {}))
        return TracingContext(
            trace_id=headers.get(TRACE_ID_HEADER),
            invocation_id=headers.get(INVOCATION_ID_HEADER),
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
            invocation_id=context.get(INVOCATION_ID_HEADER),
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

        trigger_context.set_identifier(
            "request_id", _s3_record.get(
                "responseelements", {}).get("x-amz-request-id"))
        trigger_context.set_identifier("bucket_name", _bucket.get("name"))
        trigger_context.set_identifier("bucket_arn", _bucket.get("arn"))
        trigger_context.set_identifier("object_key", _object.get("key"))

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


class AWSContext:

    # https://docs.aws.amazon.com/lambda/latest/dg/python-context.html

    _logger = logging.getLogger("AWSContext")
    _logger.setLevel(logging.INFO)

    def __init__(self, context_data) -> None:
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
            self._logger.error(
                f"Custom client context is not a dict, got {type(client_ctx)}. Cannot parse custom client context.")
            return {}

        return client_ctx

    def extract_trace_context(self) -> Type[TracingContext]:
        """
        Extracts Trace context from AWS Lambda Context object.
        """
        return TracingContext(
            trace_id=self.custom_context.get(TRACE_ID_HEADER),
            invocation_id=self.custom_context.get(INVOCATION_ID_HEADER),
            parent_id=self.custom_context.get(PARENT_ID_HEADER))
