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

    def __init__(self, parameters: dict = {}) -> None:
        self.function_name = parameters.get("function_name")
        self.region_name = parameters.get("region_name")

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
