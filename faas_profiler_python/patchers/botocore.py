#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import Type

from faas_profiler_python.patchers import FunctionPatcher, InvocationContext, PatchEvent
from faas_profiler_python.utilis import (
    decode_base64_json_to_dict,
    encode_dict_to_base64_json,
    get_arg_by_key_or_pos
)

from faas_profiler_python.aws import AWSServices


class BotocoreAPI(FunctionPatcher):
    module_name: str = "botocore"
    submodules: str = ["client"]
    function_name: str = "BaseClient._make_api_call"

    INJECTABLE_SERVICES = [AWSServices.LAMBDA]

    def extract_context(
            self,
            invocation_context: Type[InvocationContext]) -> None:

        service = self._get_service(invocation_context.instance)
        meta = getattr(invocation_context.instance, "meta", None)

        operation = get_arg_by_key_or_pos(
            invocation_context.original_args,
            invocation_context.original_kwargs,
            pos=0,
            kw="operation_name",
            default='unidentified')
        api_params = get_arg_by_key_or_pos(
            invocation_context.original_args,
            invocation_context.original_kwargs,
            pos=1,
            kw="api_params",
            default='{}')

        http_method, http_uri = self._get_http_info(meta, operation)

        response_ctx = {}
        if invocation_context.response:
            response_ctx = {
                "request_id": invocation_context.response.get(
                    "ResponseMetadata",
                    {}).get("RequestId"),
                "http_code": invocation_context.response.get(
                    "ResponseMetadata",
                    {}).get("HTTPStatusCode"),
                "retry_attempts": invocation_context.response.get(
                    "ResponseMetadata",
                    {}).get("RetryAttempts"),
                "content_type": invocation_context.response.get("ContentType"),
                "content_length": invocation_context.response.get("ContentLength"),
            }

        if response_ctx.get("request_id"):
            invocation_context.set_identifier(
                "request_id", response_ctx.get("request_id"))

        invocation_context.set_identifier("operation", operation)
        invocation_context.set_identifier("service", service.value)
        self._set_service_specific_identifiers(
            invocation_context, service, api_params)

        invocation_context.set_tags({
            "service": service,
            "operation": operation,
            "endpoint_url": getattr(meta, "endpoint_url"),
            "region_name": getattr(meta, "region_name"),
            "api_params": api_params,
            "http_method": http_method,
            "http_uri": http_uri,
            **response_ctx
        })

        return super().extract_context(invocation_context)

    def modify_function_args(
        self,
        patch_event: Type[PatchEvent]
    ) -> None:
        """
        Modifies the function arguments to inject a trace context (In place).
        """
        if self._tracer is None:
            self.logger.warn("Skipping injection. No tracer defined.")
            return

        service = self._get_service(patch_event.instance)

        if service not in self.INJECTABLE_SERVICES:
            self.logger.warn(
                f"Ignored AWS API call to {service}. Cannot inject.")
            return

        if patch_event.args is None:
            self._logger.error("Cannot inject function with no parameters")
            return

        api_params = get_arg_by_key_or_pos(
            patch_event.args, patch_event.kwargs, 1, "api_params", {})
        operation = get_arg_by_key_or_pos(
            patch_event.args, patch_event.kwargs, 0, "operation_name")

        # Lambda Invocaction (sync and async)
        if service == AWSServices.LAMBDA and operation == "Invoke":
            self._inject_lambda_call(
                api_params, self._tracer.context.to_injectable())

    def _set_service_specific_identifiers(
        self,
        invocation_context: Type[InvocationContext],
        service: AWSServices,
        api_params: dict = {}
    ) -> None:
        """
        Set resource specific identifiers
        """
        if service == AWSServices.S3:
            invocation_context.set_identifier(
                "bucket_name", api_params.get("Bucket"))
            invocation_context.set_identifier(
                "object_key", api_params.get("Key"))

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

    def _get_service(self, instance) -> str:
        """
        Detects the AWS service based on the endpoint prefix
        """
        if not hasattr(instance, "_endpoint"):
            self.logger.error(
                f"Could not detect service of {instance}. No _endpoint defined.")
            return AWSServices.UNIDENTIFIED

        _prefix = getattr(instance._endpoint, "_endpoint_prefix", None)
        try:
            return AWSServices(_prefix)
        except ValueError as err:
            self.logger.error(
                f"Could not detect service of {instance}: {err}")
            return AWSServices.UNIDENTIFIED

    def _inject_lambda_call(
        self,
        api_params: dict,
        data_to_inject: dict
    ) -> None:
        """
        The Client Context is passed as Base64 object in the api parameters.
        Thus we need to encode the context (if existing), add our tracing context
        and then decode in back to Base64

        More info: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
        """
        client_context = {}
        if "ClientContext" in api_params:
            try:
                client_context = decode_base64_json_to_dict(
                    api_params["ClientContext"])
            except ValueError as err:
                self.logger.error(err)
                return

        # Injection
        client_context.setdefault("custom", {}).update(data_to_inject)

        try:
            api_params["ClientContext"] = encode_dict_to_base64_json(
                client_context)
        except ValueError as err:
            self.logger.error(err)
        else:
            self.logger.info("Payload for AWS Lambda Invoke injected.")
