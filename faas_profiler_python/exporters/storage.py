#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for cloud storage exports
"""

import os
import boto3

from uuid import uuid4

from faas_profiler_python.gcp import gcp_project, gcp_region_name
from faas_profiler_python.exporters import Exporter, json_formatter

UNPROCESSED_RECORDS_PREFIX = "unprocessed_records/"
UNPROCESSED_RECORDS_FORMAT = UNPROCESSED_RECORDS_PREFIX + \
    "{record_id}.json"


class AWSVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in S3.
    """

    client = boto3.client('s3', region_name="eu-central-1")

    def __init__(
        self,
        bucket_name: str = None
    ) -> None:
        self.bucket_name = bucket_name
        if self.bucket_name is None:
            self.bucket_name = os.environ.get(
                "RECORDS_BUCKET", "faas-profiler-records")

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


class GCPVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in Google Cloud Storage.
    """

    def __init__(
        self,
        project: str = gcp_project(),
        bucket_name: str = None,
        region_name: str = gcp_region_name()
    ) -> None:
        from google.cloud import storage

        self.project = project
        self.region_name = region_name
        self.bucket_name = bucket_name

        if self.bucket_name is None:
            self.bucket_name = os.environ.get(
                "RECORDS_BUCKET", "faas-profiler-records")

        self.client = storage.Client(self.project)
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
