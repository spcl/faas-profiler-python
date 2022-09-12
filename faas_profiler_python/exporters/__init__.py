#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for exporting and collecting results.
"""
from __future__ import annotations

import json
import os
from uuid import UUID
import uuid
import yaml

from typing import List, Type, Any

from faas_profiler_core.models import (
    InboundContext,
    OutboundContext,
    TracingContext,
    TraceRecord,
    FunctionContext,
    RecordData
)

from faas_profiler_python.core import BasePlugin, BatchExecution
from faas_profiler_python.utilis import Loggable


def json_formatter(raw_data: dict) -> str:
    def default(o): return f"<<non-serializable: {type(o).__qualname__}>>"
    return json.dumps(
        raw_data,
        ensure_ascii=False,
        indent=None,
        default=default
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

    def __init__(self, *args, **kwargs) -> None:
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
        outbound_contexts: List[Type[OutboundContext]],
        periodic_results_file: str,
        default_batch: Type[BatchExecution],
        capture_batch: Type[BatchExecution]
    ) -> None:
        periodic_results = self._read_periodic_results_file(
            periodic_results_file)
        default_results = default_batch.export_results()
        capture_results = capture_batch.export_results()

        if tracing_context is None:
            tracing_context = TracingContext(record_id=uuid(), trace_id=uuid())

        self.results = periodic_results + default_results + capture_results
        self.record = TraceRecord(
            function_context=function_context,
            tracing_context=tracing_context,
            inbound_context=inbound_context,
            outbound_contexts=outbound_contexts,
            data={
                r["name"]: RecordData.load(r) for r in self.results})
        self._raw_data = self.record.dump()

        self._record_id = tracing_context.record_id

        assert self._record_id is not None

    @property
    def raw_data(self) -> dict:
        """
        Returns data as dict
        """
        return self._raw_data

    @property
    def record_id(self) -> UUID:
        """
        Returns the record ID for the results
        """
        return self._record_id

    def format(self, formatter=json_formatter) -> Any:
        """
        Returns the data formatted.
        """
        return formatter(self.raw_data)

    def _read_periodic_results_file(self, periodic_results_file: str) -> list:
        if not os.path.exists(periodic_results_file):
            return []

        with open(periodic_results_file, "r") as fp:
            return json.load(fp)
