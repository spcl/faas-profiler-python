#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for AWS invocation capturing.
"""

import io
from typing import Type
from faas_profiler_python.aws import AWSServices

from faas_profiler_python.captures import Capture
from faas_profiler_python.patchers import InvocationContext
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.patchers.io import Open


class S3Capture(Capture):
    requested_patch = BotocoreAPI

    def initialize(self, parameters: dict = {}) -> None:
        self.invocations = []
        return super().initialize(parameters)

    def capture(self, invocation_context: Type[InvocationContext]) -> None:
        if invocation_context.tags.get("service") != AWSServices.S3:
            return

        tags = invocation_context.tags
        api_params = tags.get("api_params", {})

        self.invocations.append({
            "operation": tags.get("operation"),
            "error": invocation_context.has_error,
            "error_message": str(invocation_context.error),
            "bucket": api_params.get("Bucket"),
            "key": api_params.get("Key"),
            "api_params": {str(k): str(v) for k, v in api_params.items()},
            "request_url": tags.get("endpoint_url"),
            "request_uri": tags.get("http_uri"),
            "request_method": tags.get("http_method"),
            "request_status": tags.get("http_code"),
            "size": tags.get("content_length") or self._get_size_by_body(api_params),
            "execution_time": invocation_context.execution_time
        })

    def _get_size_by_body(self, api_params):
        if not api_params:
            return None

        body = api_params.get("Body", None)
        if body and isinstance(body, io.BytesIO):
            return body.getbuffer().nbytes

    def results(self) -> list:
        return self.invocations


class EFSCapture(Capture):
    requested_patch = Open

    def initialize(self, parameters: dict = {}) -> None:
        self.mounting_points = parameters.get("mount_points")
        self.invocations = []

        if not self.mounting_points:
            raise ValueError(
                "Cannot initialise EFSCapture without mounting points")
        return super().initialize(parameters)

    def capture(self, invocation_context: Type[InvocationContext]) -> None:
        for monting_point in self.mounting_points:
            file = invocation_context.tags.get("file")
            if file and file.startswith(monting_point):
                self.invocations.append({
                    "efs_mount": monting_point,
                    "file": file,
                    "mode": self._determine_mode(invocation_context.tags.get("mode")),
                    "encoding": invocation_context.tags.get("encoding"),
                    # "io_type": str(io_return.wrapper_type),
                    "execution_time": invocation_context.execution_time
                })

    def results(self) -> list:
        return self.invocations

    def _determine_mode(self, mode: str) -> str:
        if "r+" in mode or "w+" in mode or "a" in mode:
            return "read/write"

        if "r" in mode:
            return "read"

        if "w" in mode or "a" in mode:
            return "write"
