#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common exporters
"""

from faas_profiler_python.exporters import Exporter


class Console(Exporter):
    """
    Prints results to console
    """

    def export(self, trace_record: dict):
        """
        Prints raw data to std out.
        """
        print(trace_record)


class AWSVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in S3.
    """

    def __init__(
        self,
        bucket_name: str,
        region_name: str
    ) -> None:
        from faas_profiler_core.storage import S3RecordStorage
        self.record_storage = S3RecordStorage(
            bucket_name=bucket_name,
            region_name=region_name)

    def export(self, trace_record: dict) -> None:
        """
        Uploads record as json to bucket.
        """
        self.record_storage.store_unprocessed_record(trace_record)


class GCPVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in Google Cloud Storage.
    """

    def __init__(
        self,
        project: str,
        bucket_name: str,
        region_name: str
    ) -> None:
        from faas_profiler_core.storage import GCPRecordStorage
        self.record_storage = GCPRecordStorage(
            project=project,
            bucket_name=bucket_name,
            region_name=region_name)

    def export(self, trace_record: dict) -> None:
        """
        Uploads record as json to bucket.
        """
        self.record_storage.store_unprocessed_record(trace_record)
