#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""
from __future__ import annotations

import logging

from typing import Any, Type
from uuid import uuid4

from faas_profiler_python.config import TraceContext
from faas_profiler_python.patchers import request_patcher
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.payload import Payload


class DistributedTracer:
    """
    Implementation of a distributed Tracer.
    """

    _logger = logging.getLogger("DistributedTracer")
    _logger.setLevel(logging.INFO)

    outbound_libraries = [
        BotocoreAPI
    ]

    def __init__(
        self,
        payload: Type[Payload]
    ) -> None:
        self.payload = payload
        self.current_invocation_span = InvocationSpan.create_from_incoming_payload(
            self.payload)
        self.outbound_patchers = self._patch_outbound_libraries()

    @property
    def context(self) -> Type[TraceContext]:
        """
        Returns the current trace context given by the invocation span.
        """
        return self.current_invocation_span.trace_context

    def record_outbound_request(self):
        """
        Records the outbound request
        """
        print("recorded")

    def _patch_outbound_libraries(self):
        """
        Patches all outbound libraries
        """
        outbound_patchers = {}
        for outbound_library in self.outbound_libraries:
            patcher = request_patcher(outbound_library)
            patcher.set_tracer(self)
            patcher.activate()

            outbound_patchers[outbound_library] = patcher

        return outbound_patchers


class InvocationSpan:
    """
    Represents a lambda invocation
    """

    _logger = logging.getLogger("InvocationSpan")
    _logger.setLevel(logging.INFO)

    @classmethod
    def create_from_incoming_payload(
        cls,
        payload: Type[Payload]
    ) -> Type[InvocationSpan]:
        parent_ctx = payload.extract_tracing_context()

        trace_id = None
        if parent_ctx.trace_id:
            trace_id = parent_ctx.trace_id
        else:
            cls._logger.info(
                "No trace id found. Creating Span with new trace id")

        parent_id = None
        if parent_ctx.invocation_id:
            parent_id = parent_ctx.invocation_id
        else:
            cls._logger.info(
                "No invocation id found. Treating Span as root span.")

        return cls(
            payload=payload,
            trace_id=trace_id,
            parent_id=parent_id)

    def __init__(
        self,
        payload: Type[Payload],
        trace_id: str = None,
        parent_id: str = None,
    ) -> None:
        self.payload = payload
        self.trace_id = trace_id if trace_id else uuid4()
        self.invocation_id = uuid4()
        self.parent_id = parent_id

        self._trace_context = TraceContext(
            self.trace_id, self.invocation_id, self.parent_id)
        self._trigger_context = self.payload.extract_trigger_context()

        self._logger.info(f"NEW SPAN: {self}")
        self._logger.info(f"Extracted Trace Context: {self._trace_context}")
        self._logger.info(
            f"Extracted Trigger Context: {self._trigger_context}")

    def __str__(self) -> str:
        return f"[trace_id={self.trace_id}, invocation_id={self.invocation_id}, parent_id={self.parent_id}]"

    @property
    def is_root(self) -> bool:
        return self.parent_id is None

    @property
    def trace_context(self) -> Type[TraceContext]:
        """
        Returns the trace context of this span
        """
        return self._trace_context

    @property
    def trigger_context(self) -> Any:
        """
        Returns the trigger context of this span
        """
        return self._trigger_context
