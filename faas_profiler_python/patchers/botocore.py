#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import List, Tuple, Type

from faas_profiler_core.constants import AWSService, AWSOperation
from faas_profiler_core.models import OutboundContext

from faas_profiler_python.patchers import FunctionPatcher, PatchContext, ReturnContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos
from faas_profiler_python.aws import extract_outbound_contexts, inject_payload


"""
Botocore Patcher
"""

__all__ = [
    "BotocoreAPI"
]


class BotocoreAPI(FunctionPatcher):
    module_name: str = "botocore.client"
    function_name: str = "BaseClient._make_api_call"

    def extract_outbound_context(
        self,
        patch_context: PatchContext,
        return_context: ReturnContext
    ) -> List[Type[OutboundContext]]:
        """
        Extracts Outbound Context from botocore API call.
        """
        service, operation = aws_service_and_operation_detection(patch_context)
        return extract_outbound_contexts(
            service, operation, patch_context, return_context)

    def inject_tracing_context(
        self,
        patch_context: PatchContext,
        data: dict
    ) -> None:
        """
        Modifies the function arguments to inject a trace context (In place).
        """
        service, operation = aws_service_and_operation_detection(patch_context)
        inject_payload(service, operation, patch_context, data)


def aws_service_and_operation_detection(
    patch_context: Type[PatchContext]
) -> Tuple[AWSService, AWSOperation]:
    """
    Detects AWS Service and Operation
    """
    endpoint_prefix = service_prefix(patch_context.instance)
    service = service_by_outbound_endpoint(endpoint_prefix)

    operation_name = get_arg_by_key_or_pos(
        patch_context.args, patch_context.kwargs, pos=0, kw="operation_name")
    operation_name = str(operation_name).lower()
    operation = operation_by_operation_name(service, operation_name)

    return service, operation


def service_prefix(botocore_instance) -> str:
    """
    Return the AWS service endpoint prefix
    """
    if not hasattr(botocore_instance, "_endpoint"):
        return None

    return getattr(botocore_instance._endpoint, "_endpoint_prefix", None)


"""
AWS Service detection
"""

SERVICE_BY_ENDPOINT = {
    "lambda": AWSService.LAMBDA,
    "s3": AWSService.S3,
    "dynamodb": AWSService.DYNAMO_DB,
    "sqs": AWSService.SQS,
    "sns": AWSService.SNS,
    "events": AWSService.EVENTBRIDGE
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
        "invoke": AWSOperation.LAMBDA_INVOKE,
        "invokeasync": AWSOperation.LAMBDA_INVOKE
    },
    AWSService.S3: {
        "putobject": AWSOperation.S3_OBJECT_CREATE,
        "getobject": AWSOperation.S3_OBJECT_GET,
        "deleteobject": AWSOperation.S3_OBJECT_REMOVED,
        "headobject": AWSOperation.S3_OBJECT_HEAD,
        "headbucket": AWSOperation.S3_BUCKET_HEAD
    },
    AWSService.DYNAMO_DB: {
        "putitem": AWSOperation.DYNAMO_DB_UPDATE,
        "removeitem": AWSOperation.DYNAMO_DB_UPDATE,
        "updateitem": AWSOperation.DYNAMO_DB_UPDATE
    },
    AWSService.SQS: {
        "sendmessage": AWSOperation.SQS_SEND,
        "sendmessagebatch": AWSOperation.SQS_SEND_BATCH
    },
    AWSService.SNS: {
        "publish": AWSOperation.SNS_PUBLISH,
        "publishbatch": AWSOperation.SNS_PUBLISH_BATCH
    },
    AWSService.EVENTBRIDGE: {
        "putevents": AWSOperation.EVENTBRIDGE_PUT_EVENTS,
    }
}


def operation_by_operation_name(
    service: AWSService,
    operation_name: str
) -> AWSOperation:
    """
    Returns the AWS Operation based on service and operation name
    """
    service_operations = OPERATION_BY_NAME.get(service)
    if service_operations:
        return service_operations.get(
            operation_name, AWSOperation.UNIDENTIFIED)

    return AWSOperation.UNIDENTIFIED
