#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import Type

from faas_profiler_core.constants import AWSService, AWSOperation, Provider, TriggerSynchronicity
from faas_profiler_core.models import OutboundContext, TracingContext
from faas_profiler_python.config import InjectionError, UnsupportedServiceError

from faas_profiler_python.patchers import FunctionPatcher, PatchContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos
from faas_profiler_python.aws import (
    operation_by_operation_name,
    service_by_outbound_endpoint,
    get_outbound_identifiers,
    inject_aws_call
)


"""
AWS Botocore data extraction
"""


def service_prefix(botocore_instance) -> str:
    """
    Return the AWS service endpoint prefix
    """
    if not hasattr(botocore_instance, "_endpoint"):
        return None

    return getattr(botocore_instance._endpoint, "_endpoint_prefix", None)


"""
Botocore Request Handlers
"""


def s3_handler(
    patch_context: Type[PatchContext],
    outbound_context: Type[OutboundContext]
) -> None:
    """
    Handle S3 request
    """
    api_parameters = get_arg_by_key_or_pos(
        patch_context.args,
        patch_context.kwargs,
        pos=1,
        kw="api_params",
        default={})

    _body_size, _content_length = None, None

    if patch_context.response:
        _resp = patch_context.response
        if "ContentLength" in _resp or "content-length" in _resp:
            _content_length = _resp.get(
                "content-length") or _resp.get("ContentLength")
        elif "ResponseMetadata" in patch_context.response:
            req_meta_data = _resp["ResponseMetadata"]
            _content_length = req_meta_data.get(
                "content-length") or req_meta_data.get("ContentLength")

    if "Body" in api_parameters:
        _body_size = getattr(api_parameters["Body"], "_size", None)

    if outbound_context.operation == AWSOperation.S3_OBJECT_CREATE:
        _size = _body_size if _body_size else _content_length
    else:
        _size = _content_length if _content_length else _body_size

    outbound_context.set_tags({"size": _size})


REQUEST_HANDLERS_BY_SERVICE = {
    AWSService.S3: s3_handler
}

"""
Botocore Patcher
"""


class BotocoreAPI(FunctionPatcher):
    module_name: str = "botocore"
    submodules: str = ["client"]
    function_name: str = "BaseClient._make_api_call"

    def extract_outbound_context(
        self,
        patch_context: Type[PatchContext]
    ) -> Type[OutboundContext]:
        """
        Extracts outbound context based on AWS API call done with boto3
        """
        endpoint_prefix = service_prefix(patch_context.instance)
        service = service_by_outbound_endpoint(endpoint_prefix)

        outbound_context = OutboundContext(
            Provider.AWS, service, AWSOperation.UNIDENTIFIED,
            trigger_synchronicity=TriggerSynchronicity.ASYNC)

        if service != AWSService.UNIDENTIFIED:
            self.logger.info(
                f"[OUTBOUND] Detected AWS API call to {service}")

            operation_name = get_arg_by_key_or_pos(
                patch_context.args, patch_context.kwargs, pos=0, kw="operation_name")
            operation = operation_by_operation_name(
                service, str(operation_name).lower())
            self.logger.info(
                f"[OUTBOUND] Detected AWS API call operation {operation}")

            outbound_context.operation = operation

            api_parameters = get_arg_by_key_or_pos(
                patch_context.args,
                patch_context.kwargs,
                pos=1,
                kw="api_params",
                default={})
            api_response = patch_context.response if patch_context.response else {}

            meta = getattr(patch_context.instance, "meta", None)
            http_method, http_uri = self._get_http_info(meta, operation_name)

            _service_handler = REQUEST_HANDLERS_BY_SERVICE.get(service)
            if _service_handler:
                _service_handler(patch_context, outbound_context)

            outbound_context.set_tags({
                "parameters": {
                    str(k): str(v) for k, v in api_parameters.items()},
                "request_method": http_method,
                "request_url": getattr(meta, "endpoint_url"),
                "request_status": api_response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                "request_uri": http_uri})
            identifiers = get_outbound_identifiers(
                service, operation, api_parameters=api_parameters, api_response=api_response)
            self.logger.info(
                f"[OUTBOUND] Extracted identifiers for AWS API call: {identifiers}")

            outbound_context.set_identifiers(identifiers)

            if service == AWSService.LAMBDA and operation == AWSOperation.LAMBDA_INVOKE:
                if api_parameters.get(
                    "InvocationType",
                        "RequestResponse") == "RequestResponse":
                    outbound_context.trigger_synchronicity = TriggerSynchronicity.SYNC

        else:
            self.logger.error(
                f"[OUTBOUND] Could not detect service for {patch_context}.")

        return outbound_context

    def inject_tracing_context(
        self,
        patch_context: Type[PatchContext],
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Modifies the function arguments to inject a trace context (In place).
        """
        endpoint_prefix = service_prefix(patch_context.instance)
        service = service_by_outbound_endpoint(endpoint_prefix)
        if service != AWSService.UNIDENTIFIED:
            self.logger.info(
                f"[INJECTION] Detected AWS API call to {service}")

            operation_name = get_arg_by_key_or_pos(
                patch_context.args, patch_context.kwargs, pos=0, kw="operation_name")
            operation_name = str(operation_name).lower()
            operation = operation_by_operation_name(service, operation_name)

            api_parameters = get_arg_by_key_or_pos(
                patch_context.args,
                patch_context.kwargs,
                pos=1,
                kw="api_params",
                default={})

            try:
                inject_aws_call(
                    service,
                    operation,
                    api_parameters,
                    tracing_context.to_injectable())
            except UnsupportedServiceError as err:
                self.logger.warn(f"[INJECTION] {err}")
            except InjectionError as err:
                self.logger.warn(f"[INJECTION] Injection failed: {err}")
            else:
                self.logger.info("[INJECTION] Payload injected.")
        else:
            self.logger.error(
                f"[INJECTION] Could not detect service for {patch_context}. Cannot inject.")

    def _get_http_info(
        self,
        meta,
        operation_name: str = None
    ) -> tuple:
        if operation_name and meta:
            try:
                op_model = meta.service_model.operation_model(operation_name)

                return (
                    op_model.http.get("method"),
                    op_model.http.get("requestUri"))
            except Exception as err:
                self._logger.error(f"Could not get operation model: {err}")
                return None, None

        return None, None
