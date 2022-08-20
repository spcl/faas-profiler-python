#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import Type

from faas_profiler_core.constants import AWSService, AWSOperation, Provider
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
            Provider.AWS, service, AWSOperation.UNIDENTIFIED)

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
