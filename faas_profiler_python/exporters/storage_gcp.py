#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for cloud storage exports
"""

import os

from uuid import uuid4
from google.cloud import storage

from faas_profiler_python.gcp import gcp_project
from faas_profiler_python.exporters import Exporter, json_formatter

UNPROCESSED_RECORDS_PREFIX = "unprocessed_records/"
UNPROCESSED_RECORDS_FORMAT = UNPROCESSED_RECORDS_PREFIX + \
    "{record_id}.json"


class GCPVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in Google Cloud Storage.
    """

    client = storage.Client(gcp_project())

    def __init__(
        self,
        bucket_name: str = None,
    ) -> None:
        self.bucket_name = bucket_name

        if self.bucket_name is None:
            self.bucket_name = os.environ.get(
                "RECORDS_BUCKET", "faas-profiler-records")

        self.bucket = self.client.bucket(self.bucket_name)

    def export(self, trace_record: dict) -> None:
        """
        Uploads record as json to bucket.
        """
        record_id = trace_record.get("tracing_context", {}).get(
            "record_id", uuid4())
        record_key = UNPROCESSED_RECORDS_FORMAT.format(
            record_id=record_id)
        record_json = json_formatter(trace_record)

        record_blob = self.bucket.blob(record_key)
        record_blob.upload_from_string(record_json)
