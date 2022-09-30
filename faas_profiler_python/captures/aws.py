#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for AWS invocation capturing.
"""

from typing import Type

from faas_profiler_python.captures import Capture
from faas_profiler_python.patchers import OutboundContext

from faas_profiler_core.constants import (
    Provider,
    InternalService,
    AWSService
)
from faas_profiler_core.models import (
    S3Accesses,
    S3AccessItem,
    EFSAccesses,
    EFSAccessItem
)


class S3Access(Capture):
    requested_patch = "botocore"

    def initialize(
        self,
        *args,
        bucket_names: list = None,
        **kwargs
    ) -> None:
        super().initialize(*args, **kwargs)

        self.bucket_names = bucket_names
        self._result = S3Accesses(accesses=[])

    def capture(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        """
        Capture S3 access.
        """
        if outbound_context.service != AWSService.S3:
            return

        bucket_name = outbound_context.identifier.get("bucket_name")
        object_key = outbound_context.identifier.get("object_key")
        size = outbound_context.tags.get("size")
        execution_time = outbound_context.overhead_time

        if self.bucket_names and bucket_name not in self._bucket_names:
            self.logger.info(
                f"[S3 Capture]: Ignore S3 Operation on bucket {bucket_name} and"
                "object {_object_key}. Bucket is not of target.")
            return

        self._result.accesses.append(S3AccessItem(
            mode=outbound_context.operation.value,
            bucket_name=bucket_name,
            object_key=object_key,
            object_size=size,
            execution_time=execution_time
        ))

    def results(self) -> dict:
        return self._result.dump()


class EFSAccess(Capture):
    requested_patch = "open_io"

    def initialize(
            self,
            mount_point: str = "/mnt/lambda",
            *args,
            **kwargs) -> None:
        super().initialize(*args, **kwargs)
        self.mount_point = mount_point

        if not self.mount_point:
            raise ValueError(
                "Cannot initialise EFSCapture without mount_point")

        self._result = EFSAccesses(mount_point=mount_point, accesses=[])

    def capture(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        """
        Capture a EFS file access.
        """
        if outbound_context.provider != Provider.INTERNAL:
            return

        if outbound_context.service != InternalService.IO:
            return

        file = outbound_context.tags.get("file")
        if not str(file).startswith(self.mount_point):
            return

        self._result.accesses.append(EFSAccessItem(
            mode=outbound_context.operation.value,
            file=file,
            file_size=outbound_context.tags.get("size"),
            execution_time=outbound_context.overhead_time
        ))

    def results(self) -> dict:
        return self._result.dump()
