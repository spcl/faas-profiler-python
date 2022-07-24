#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Type, Any

from faas_profiler_python.patchers import FunctionPatcher
from faas_profiler_python.utilis import get_arg_by_key_or_pos


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

    def after_invocation(self, response: Any, error: Any = None) -> Any:
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
