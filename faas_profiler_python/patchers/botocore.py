#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import Type

from faas_profiler_core.constants import AWSService, AWSOperation, Provider
from faas_profiler_core.models import OutboundContext, TracingContext

from faas_profiler_python.patchers import FunctionPatcher, PatchEvent
from faas_profiler_python.utilis import (
    decode_base64_json_to_dict,
    encode_dict_to_base64_json,
    get_arg_by_key_or_pos
)


class BotocoreAPI(FunctionPatcher):
    module_name: str = "botocore"
    submodules: str = ["client"]
    function_name: str = "BaseClient._make_api_call"

    INJECTABLE_SERVICES = [AWSService.LAMBDA]

    def extract_outbound_context(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        outbound_context.provider = Provider.AWS
        outbound_context.service = self._get_service(outbound_context.instance)
        outbound_context.operation = AWSOperation.UNIDENTIFIED

        operation = get_arg_by_key_or_pos(
            outbound_context.args,
            outbound_context.kwargs,
            pos=0,
            kw="operation_name")

        if outbound_context.service == AWSService.S3:
            if operation == "PutObject":
                outbound_context.operation = AWSOperation.S3_OBJECT_CREATE

        meta = getattr(outbound_context.instance, "meta", None)
        api_params = get_arg_by_key_or_pos(
            outbound_context.args,
            outbound_context.kwargs,
            pos=1,
            kw="api_params",
            default='{}')

        http_method, http_uri = self._get_http_info(meta, operation)

        response_ctx = {}
        if outbound_context.response:
            response_ctx = {
                "request_id": outbound_context.response.get(
                    "ResponseMetadata",
                    {}).get("RequestId"),
                "http_code": outbound_context.response.get(
                    "ResponseMetadata",
                    {}).get("HTTPStatusCode"),
                "retry_attempts": outbound_context.response.get(
                    "ResponseMetadata",
                    {}).get("RetryAttempts"),
                "content_type": outbound_context.response.get("ContentType"),
                "content_length": outbound_context.response.get("ContentLength"),
            }

        if response_ctx.get("request_id"):
            outbound_context.set_identifier(
                "request_id", response_ctx.get("request_id"))

        self._set_service_specific_identifiers(
            outbound_context, api_params)

        outbound_context.set_tags({
            "endpoint_url": getattr(meta, "endpoint_url"),
            "region_name": getattr(meta, "region_name"),
            "api_params": api_params,
            "http_method": http_method,
            "http_uri": http_uri,
            **response_ctx
        })

    def inject_tracing_context(
        self,
        patch_event: Type[PatchEvent],
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Modifies the function arguments to inject a trace context (In place).
        """
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
        if service == AWSService.LAMBDA and operation == "Invoke":
            self._inject_lambda_call(
                api_params, tracing_context.to_injectable())

    def _set_service_specific_identifiers(
        self,
        outbound_context: Type[OutboundContext],
        api_params: dict = {}
    ) -> None:
        """
        Set resource specific identifiers
        """
        if outbound_context.service == AWSService.S3:
            outbound_context.set_identifier(
                "bucket_name", api_params.get("Bucket"))
            outbound_context.set_identifier(
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

    def _get_service(self, instance) -> AWSService:
        """
        Detects the AWS service based on the endpoint prefix
        """
        if not hasattr(instance, "_endpoint"):
            self.logger.error(
                f"Could not detect service of {instance}. No _endpoint defined.")
            return AWSService.UNIDENTIFIED

        _prefix = getattr(instance._endpoint, "_endpoint_prefix", None)
        try:
            return AWSService(_prefix)
        except ValueError as err:
            self.logger.error(
                f"Could not detect service of {instance}: {err}")
            return AWSService.UNIDENTIFIED

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
