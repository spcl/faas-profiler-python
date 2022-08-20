#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for AWS invocation capturing.
"""

import io
from typing import Type

from faas_profiler_python.captures import Capture
from faas_profiler_python.patchers import OutboundContext
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.patchers.io import Open

from faas_profiler_core.constants import AWSOperation, AWSService
from faas_profiler_core.models import S3CaptureItem


class S3Capture(Capture):
    requested_patch = BotocoreAPI

    def initialize(self, *args, **kwargs) -> None:
        super().initialize(*args, **kwargs)
        self._invocations = []

    def capture(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        if outbound_context.service != AWSService.S3:
            return

        api_params = outbound_context.tags.get("parameters")
        self._invocations.append(
            S3CaptureItem(
                operation=outbound_context.operation,
                parameters=api_params,
                bucket_name=outbound_context.identifier.get("bucket_name"),
                object_key=outbound_context.identifier.get("object_key"),
                object_size=self._get_size_by_body(api_params),
                request_method=outbound_context.tags.get("request_method"),
                request_status=outbound_context.tags.get("request_status"),
                request_url=outbound_context.tags.get("request_url"),
                request_uri=outbound_context.tags.get("request_uri"),
                execution_time=(
                    outbound_context.finished_at -
                    outbound_context.invoked_at).total_seconds()))

    def _get_size_by_body(self, api_params):
        if not api_params:
            return None

        body = api_params.get("Body", None)
        if body and isinstance(body, io.BytesIO):
            return body.getbuffer().nbytes

    def results(self) -> list:
        return [
            inc.dump() for inc in self._invocations]


class EFSCapture(Capture):
    requested_patch = Open

    def initialize(self, parameters: dict = {}) -> None:
        self.mounting_points = parameters.get("mount_points")
        self.invocations = []

        if not self.mounting_points:
            raise ValueError(
                "Cannot initialise EFSCapture without mounting points")
        return super().initialize(parameters)

    def capture(self, invocation_context: Type[OutboundContext]) -> None:
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
