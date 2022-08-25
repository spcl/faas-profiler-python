#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common exporters
"""

import boto3

from typing import Type

from faas_profiler_core.storage import S3RecordStorage, GCPRecordStorage

from faas_profiler_python.exporters import Exporter, ResultCollector, json_formatter


class Console(Exporter):
    """
    Prints results to console
    """

    def export(self, results_collector: Type[ResultCollector]):
        """
        Prints raw data to std out.
        """
        print(results_collector.raw_data)


class Visualizer(Exporter):
    """
    Sends records to visualizer function
    """

    def __init__(self, function_name: str, region_name: str) -> None:
        super().__init__()

        self.function_name = function_name
        self.region_name = region_name
        if self.function_name is None or self.region_name is None:
            raise ValueError(
                "Cannot initialize VisualizerExporter without function name or region name")

        self.client = boto3.client("lambda", region_name=self.region_name)

    def export(self, results_collector: Type[ResultCollector]):
        """
        Sends data to AWS Lambda function
        """
        self.client.invoke(
            FunctionName=self.function_name,
            InvocationType='Event',
            Payload=results_collector.format(formatter=json_formatter))


class AWSVisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket in S3.
    """

    def __init__(
        self,
        bucket_name: str,
        region_name: str
    ) -> None:
        self.record_storage = S3RecordStorage(
            bucket_name=bucket_name,
            region_name=region_name)

    def export(self, results_collector: Type[ResultCollector]):
        """
        Uploads record as json to bucket.
        """
        self.record_storage.store_unprocessed_record(results_collector.record)


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
        self.record_storage = GCPRecordStorage(
            project=project,
            bucket_name=bucket_name,
            region_name=region_name)

    def export(self, results_collector: Type[ResultCollector]):
        """
        Uploads record as json to bucket.
        """
        self.record_storage.store_unprocessed_record(results_collector.record)
