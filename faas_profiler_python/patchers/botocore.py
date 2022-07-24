#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Type, Any

from faas_profiler_python.patchers import FunctionPatcher
from faas_profiler_python.utilis import decode_base64_json_to_dict, encode_dict_to_base64_json, get_arg_by_key_or_pos


@dataclass
class AWSApiCall:
    service: str = None
    operation: str = None
    endpoint_url: str = None
    region_name: str = None
    api_params: dict = None
    http_uri: str = None
    http_method: str = None


@dataclass
class AWSApiResponse:
    request_id: str = None
    http_code: int = None
    retry_attempts: int = None
    content_type: str = None
    content_length: int = None


class BotocoreAPI(FunctionPatcher):
    module_name: str = "botocore"
    submodules: str = ["client"]
    function_name: str = "BaseClient._make_api_call"

    INJECTABLE_SERVICES = ['lambda', 'sns', 'sqs', 'cloudwatch']

    def before_invocation(
        self,
        original_func: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ) -> Type[AWSApiCall]:
        service = self._get_service(instance)

        meta = getattr(instance, "meta", None)

        operation = get_arg_by_key_or_pos(
            args, kwargs, 0, "operation_name") if args else None
        api_params = get_arg_by_key_or_pos(
            args, kwargs, 1, "api_params") if args else None

        http_method, http_uri = self._get_http_info(meta, operation)

        return AWSApiCall(
            service=str(service).lower(),
            operation=str(operation).lower(),
            endpoint_url=getattr(meta, "endpoint_url"),
            region_name=getattr(meta, "region_name"),
            api_params=api_params,
            http_uri=http_uri,
            http_method=http_method)

    def modify_function_args(
        self,
        function_args: tuple,
        aws_api_call: Type[AWSApiCall] = None
    ) -> None:
        """
        Modifies the function arguments to inject a trace context (In place).
        """
        if self._tracer is None:
            self.logger.warn("Skipping injection. No tracer defined.")
            return

        if aws_api_call is None:
            self.logger.warn(
                "Skipping injection. No AWS API call result defined.")
            return

        if aws_api_call.service not in self.INJECTABLE_SERVICES:
            self.logger.warn(
                f"Ignored AWS API call to {aws_api_call.service}. Cannot inject.")
            return

        call_args, call_kwargs = function_args
        if call_args is None:
            self._logger.error("Cannot inject function with no parameters")
            return

        api_params = get_arg_by_key_or_pos(
            call_args, call_kwargs, 1, "api_params")

        # Lambda Invocation (sync and async)
        if aws_api_call.service == "lambda" and aws_api_call.operation == "invoke":
            self._inject_lambda_call(
                api_params, self._tracer.context.to_injectable())

    def after_invocation(self, response: Any, error: Any = None) -> Any:
        if response is None:
            return AWSApiResponse()

        # TODO: Handle error

        return AWSApiResponse(
            request_id=response.get("ResponseMetadata", {}).get("RequestId"),
            http_code=response.get(
                "ResponseMetadata",
                {}).get("HTTPStatusCode"),
            retry_attempts=response.get(
                "ResponseMetadata",
                {}).get("RetryAttempts"),
            content_type=response.get("ContentType"),
            content_length=response.get("ContentLength"))

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
        if not hasattr(instance, "_endpoint"):
            return

        return getattr(instance._endpoint, "_endpoint_prefix", None)

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
