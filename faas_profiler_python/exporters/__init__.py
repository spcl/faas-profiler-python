#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for exporting and collecting results.
"""
from __future__ import annotations

import json
import yaml

from typing import List, Type, Any

from faas_profiler_core.models import (
    InboundContext,
    OutboundContext,
    TracingContext,
    TraceRecord,
    FunctionContext
)

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable


def json_formatter(raw_data: dict) -> str:
    return json.dumps(
        raw_data,
        ensure_ascii=False,
        indent=None
    ).encode('utf-8')


def yaml_formatter(raw_data: dict) -> str:
    return yaml.dump(
        raw_data,
        sort_keys=False,
        default_flow_style=False
    ).encode('utf-8')


class Exporter(BasePlugin, Loggable):
    """
    Base class for all exporters in FaaS Profiler.
    """

    def __init__(self, parameters: dict = {}) -> None:
        super().__init__()

    def export(self, results_collector: Type[ResultCollector]):
        pass


class ResultCollector(Loggable):
    """
    Convenience class for collecting all results
    """

    def __init__(
        self,
        function_context: Type[FunctionContext],
        tracing_context: Type[TracingContext],
        inbound_context: Type[InboundContext],
        outbound_contexts: List[Type[OutboundContext]]
    ) -> None:
        self.record = TraceRecord(
            function_context=function_context,
            tracing_context=tracing_context,
            inbound_context=inbound_context,
            outbound_contexts=outbound_contexts)
        self._raw_data = self.record.dump()

    @property
    def raw_data(self) -> dict:
        """
        Returns data as dict
        """
        return self._raw_data

    def format(self, formatter=json_formatter) -> Any:
        """
        Returns the data formatted.
        """
        return formatter(self.raw_data)
