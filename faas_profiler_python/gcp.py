#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all GCP specific logic.
"""
import flask

from datetime import datetime
from typing import Type

from faas_profiler_core.models import InboundContext, TracingContext
from faas_profiler_core.constants import (
    TRACE_ID_HEADER,
    RECORD_ID_HEADER,
    PARENT_ID_HEADER,
    TRACE_CONTEXT_KEY,
    Provider,
    TriggerSynchronicity,
    GCPService,
    GCPOperation
)


class GCPHTTPRequest:
    """
    Representation of a GCP HTTP request
    """

    def __init__(self, request: Type[flask.Request]) -> None:
        self.request = request

    def extract_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts the tracing context from HTTP request.
        """
        payload_tracing_context = self._payload_tracing_context()
        if payload_tracing_context:
            return payload_tracing_context

        header_tracing_context = self._headers_tracing_context()
        return header_tracing_context

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Extracts inbound context of HTTP flask request.
        """
        return InboundContext(
            provider=Provider.GCP,
            service=GCPService.FUNCTIONS,
            operation=GCPOperation.FUNCTIONS_INVOKE,
            trigger_synchronicity=TriggerSynchronicity.SYNC,
            invoked_at=datetime.now())

    def _payload_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts tracing context from payload.
        """
        if not self.request.values:
            return

        trace_ctx = self.request.values.get(TRACE_CONTEXT_KEY)
        if trace_ctx:
            return TracingContext(
                trace_id=trace_ctx.get(TRACE_ID_HEADER),
                record_id=trace_ctx.get(RECORD_ID_HEADER),
                parent_id=trace_ctx.get(PARENT_ID_HEADER))

    def _headers_tracing_context(self) -> Type[TracingContext]:
        """
        Extracts tracing context from headers.
        """
        if not self.request.headers:
            return

        headers = self.request.headers
        return TracingContext(
            trace_id=headers.get(TRACE_ID_HEADER),
            record_id=headers.get(RECORD_ID_HEADER),
            parent_id=headers.get(PARENT_ID_HEADER))


class GCPEventRequest:
    """
    Representation of a GCP Event request
    """

    def __init__(
        self,
        event: dict = {},
        context = None
    ) -> None:
        self.event = event
        self.context = context
    

    


