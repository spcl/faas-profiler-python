#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common exporters
"""

import boto3

from typing import Type

from faas_profiler_python.exporters import Exporter, ResultCollector, json_formatter


class Console(Exporter):
    """
    Prints results to console
    """

    def export(self, results_collector: Type[ResultCollector]):
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


class VisualizerUploader(Exporter):
    """
    Uploads record to visualizer bucket.
    """

    BUCKET_FOLDER = "unprocessed_records"

    def __init__(self, bucket_name: str) -> None:
        super().__init__()

        self.bucket_name = bucket_name

        if self.bucket_name is None:
            raise ValueError(
                "Cannot initialize VisualizerUploader without bucket name")

        self.client = boto3.client('s3')

    def export(self, results_collector: Type[ResultCollector]):
        """
        Uploads record as json to bucket.
        """
        _key_name = f"{self.BUCKET_FOLDER}/{results_collector.record_id}.json"
        body = results_collector.format(formatter=json_formatter)

        self.client.put_object(
            Bucket=self.bucket_name,
            Key=_key_name,
            Body=body)
