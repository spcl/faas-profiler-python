#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for AWS invocation capturing.
"""

from typing import Type

from faas_profiler_python.captures import Capture
from faas_profiler_python.patchers import OutboundContext
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.patchers.io import OpenIO

from faas_profiler_core.constants import (
    Provider,
    InternalService,
    InternalOperation,
    AWSService,
    AWSOperation
)
from faas_profiler_core.models import (
    S3Capture,
    S3AccessItem,
    EFSAccessItem,
    EFSCapture
)


class S3Access(Capture):
    requested_patch = BotocoreAPI

    def initialize(
        self,
        *args,
        bucket_names: list = None,
        **kwargs
    ) -> None:
        super().initialize(*args, **kwargs)

        self._bucket_names = bucket_names
        self._captured_buckets = set()

        self._obj_created = {}
        self._obj_deleted = {}
        self._obj_get = {}
        self._obj_head = {}

    # flake8: noqa: C901
    def capture(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        """
        Capture S3 access.
        """
        if outbound_context.service != AWSService.S3:
            return

        _bucket_name = outbound_context.identifier.get("bucket_name")
        _object_key = outbound_context.identifier.get("object_key")
        _size = outbound_context.tags.get("size")
        _execution_time = outbound_context.overhead_time

        if self._bucket_names and _bucket_name not in self._bucket_names:
            self.logger.info(
                f"[S3 Capture]: Ignore S3 Operation on bucket {_bucket_name} and"
                "object {_object_key}. Bucket is not of target.")
            return

        self._captured_buckets.add(_bucket_name)

        if outbound_context.operation == AWSOperation.S3_OBJECT_GET:
            bkt_obj_get = self._obj_get.setdefault(_bucket_name, {})
            prev_gets = bkt_obj_get.setdefault(_object_key, ([], []))

            if _size:
                prev_gets[0].append(_size)
            if _execution_time:
                prev_gets[1].append(_execution_time)

        if outbound_context.operation == AWSOperation.S3_OBJECT_CREATE:
            bkt_obj_create = self._obj_created.setdefault(_bucket_name, {})
            prev_creates = bkt_obj_create.setdefault(_object_key, ([], []))

            if _size:
                prev_creates[0].append(_size)
            if _execution_time:
                prev_creates[1].append(_execution_time)

        if outbound_context.operation == AWSOperation.S3_OBJECT_REMOVED:
            bkt_obj_deleted = self._obj_deleted.setdefault(_bucket_name, {})
            prev_deletes = bkt_obj_deleted.setdefault(_object_key, ([], []))

            if _size:
                prev_deletes[0].append(_size)
            if _execution_time:
                prev_deletes[1].append(_execution_time)

        if outbound_context.operation == AWSOperation.S3_OBJECT_HEAD:
            bkt_obj_head = self._obj_head.setdefault(_bucket_name, {})
            prev_heads = bkt_obj_head.setdefault(_object_key, ([], []))

            if _execution_time:
                prev_heads[1].append(_execution_time)

    def results(self) -> list:
        captures = []

        for bkt_name in self._captured_buckets:
            captures.append(
                S3Capture(
                    bucket_name=bkt_name,
                    get_objects=self._capture_mappings_to_items(
                        self._obj_get.get(
                            bkt_name,
                            {}),
                        mode=AWSOperation.S3_OBJECT_GET),
                    create_objects=self._capture_mappings_to_items(
                        self._obj_created.get(
                            bkt_name,
                            {}),
                        mode=AWSOperation.S3_OBJECT_CREATE),
                    deleted_objects=self._capture_mappings_to_items(
                        self._obj_deleted.get(
                            bkt_name,
                            {}),
                        mode=AWSOperation.S3_OBJECT_REMOVED),
                    head_objects=self._capture_mappings_to_items(
                        self._obj_head.get(
                            bkt_name,
                            {}),
                        mode=AWSOperation.S3_OBJECT_HEAD)).dump())

        return captures

    def _capture_mappings_to_items(
        self,
        capture_mapping: dict,
        mode: AWSOperation
    ) -> list:
        items = []
        for obj_k, (sizes, exe_times) in capture_mapping.items():
            items.append(S3AccessItem(
                mode=mode,
                object_key=obj_k,
                object_sizes=sizes,
                execution_times=exe_times))

        return items


class EFSAccess(Capture):
    requested_patch = OpenIO

    def initialize(self, mounting_points: list, *args, **kwargs) -> None:
        super().initialize(*args, **kwargs)
        self._mounting_points = mounting_points

        if not self._mounting_points:
            raise ValueError(
                "Cannot initialise EFSCapture without mounting points")

        self._file_reads = {
            mnt_point: {} for mnt_point in self._mounting_points}
        self._file_writes = {
            mnt_point: {} for mnt_point in self._mounting_points}

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

        _file = outbound_context.tags.get("file")
        _size = outbound_context.tags.get("size")
        _execution_time = outbound_context.overhead_time

        for mounting_point in self._mounting_points:
            _efs_mnt_reads = self._file_reads[mounting_point]
            _efs_mnt_writes = self._file_writes[mounting_point]
            if _file and str(_file).startswith(mounting_point):
                if (outbound_context.operation == InternalOperation.IO_READ or
                        outbound_context.operation == InternalOperation.IO_READ_WRITE):
                    prev_reads = _efs_mnt_reads.setdefault(_file, ([], []))
                    if _size is not None:
                        prev_reads[0].append(_size)
                    if _execution_time:
                        prev_reads[1].append(_execution_time)

                if (outbound_context.operation == InternalOperation.IO_WRITE or
                        outbound_context.operation == InternalOperation.IO_READ_WRITE):
                    prev_writes = _efs_mnt_writes.setdefault(_file, ([], []))
                    if _size is not None:
                        prev_writes[0].append(_size)
                    if _execution_time:
                        prev_writes[1].append(_execution_time)

    def results(self) -> list:
        captures = []
        for mounting_point in self._mounting_points:
            capture = EFSCapture(mounting_point)
            mnt_writes = self._file_writes.get(mounting_point, {})
            for file, (sizes, execution_times) in mnt_writes.items():
                capture.written_files.append(EFSAccessItem(
                    mode=InternalOperation.IO_WRITE,
                    file=file,
                    file_sizes=sizes,
                    execution_times=execution_times))

            mnt_reads = self._file_reads.get(mounting_point, {})
            for file, (sizes, execution_times) in mnt_reads.items():
                capture.read_files.append(EFSAccessItem(
                    mode=InternalOperation.IO_READ,
                    file=file,
                    file_sizes=sizes,
                    execution_times=execution_times))

            captures.append(capture.dump())

        return captures
