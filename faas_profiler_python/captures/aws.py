#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for AWS invocation capturing.
"""

from typing import Type

from faas_profiler_python.captures import Capture, PatchInvocation
from faas_profiler_python.patchers.botocore import AWSApiCall, AWSApiResponse, BotocoreAPI
from faas_profiler_python.patchers.io import Open, IOCall, IOReturn


class S3Capture(Capture):
    requested_patch = BotocoreAPI

    def initialize(self, parameters: dict = {}) -> None:
        self.invocations = []
        return super().initialize(parameters)

    def capture(
        self,
        patch_invocation: Type[PatchInvocation],
        aws_api_call: Type[AWSApiCall] = None,
        aws_api_response: Type[AWSApiResponse] = None
    ) -> None:
        if aws_api_response is None or aws_api_response is None:
            return

        if aws_api_call.service != "s3":
            return

        self.invocations.append({
            "operation": aws_api_call.operation,
            "bucket": aws_api_call.api_params.get("Bucket"),
            "key": aws_api_call.api_params.get("Key"),
            "api_params": {str(k): str(v) for k, v in aws_api_call.api_params.items()},
            "request_url": aws_api_call.endpoint_url,
            "request_uri": aws_api_call.http_uri,
            "request_method": aws_api_call.http_method,
            "request_status": aws_api_response.http_code,
            "size": aws_api_response.content_length,
            "execution_time": patch_invocation.execution_time
        })

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

    def capture(
        self,
        patch_invocation: Type[PatchInvocation],
        io_call: Type[IOCall] = None,
        io_return: Type[IOReturn] = None
    ) -> None:
        for monting_point in self.mounting_points:
            if io_call.file.startswith(monting_point):
                self.invocations.append({
                    "efs_mount": monting_point,
                    "file": io_call.file,
                    "mode": self._determine_mode(io_call.mode),
                    "encoding": io_return.encoding,
                    "io_type": str(io_return.wrapper_type),
                    "execution_time": patch_invocation.execution_time
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
