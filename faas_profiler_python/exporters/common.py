#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common exporters
"""

from uuid import uuid4
from faas_profiler_python.exporters import Exporter, json_formatter
import boto3

UNPROCESSED_RECORDS_PREFIX = "unprocessed_records/"
UNPROCESSED_RECORDS_FORMAT = UNPROCESSED_RECORDS_PREFIX + \
    "{record_id}.json"


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

    client = boto3.client('s3', region_name="eu-central-1")

    def __init__(
        self,
        bucket_name: str
    ) -> None:
        self.bucket_name = bucket_name

    def export(self, trace_record: dict) -> None:
        """
        Uploads record as json to bucket.
        """
        record_id = trace_record.get("tracing_context", {}).get(
            "record_id", uuid4())
        record_key = UNPROCESSED_RECORDS_FORMAT.format(
            record_id=record_id)
        record_json = json_formatter(trace_record)

        self.client.put_object(
            Bucket=self.bucket_name,
            Key=record_key,
            Body=record_json)


# class GCPVisualizerUploader(Exporter):
#     """
#     Uploads record to visualizer bucket in Google Cloud Storage.
#     """

#     def __init__(
#         self,
#         project: str,
#         bucket_name: str,
#         region_name: str
#     ) -> None:
#         from faas_profiler_core.storage import GCPRecordStorage
#         self.record_storage = GCPRecordStorage(
#             project=project,
#             bucket_name=bucket_name,
#             region_name=region_name)

#     def export(self, trace_record: dict) -> None:
#         """
#         Uploads record as json to bucket.
#         """
#         self.record_storage.store_unprocessed_record(trace_record)
