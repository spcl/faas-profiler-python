#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all GCP specific logic.
"""
from datetime import datetime
from typing import Tuple, Type

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
from faas_profiler_python.utilis import get_idx_safely


class InvalidGCPResource(RuntimeError):
    pass


"""
GCP Resouce resolving
"""


def pubsub_topic(resource_path: str) -> Tuple[str, str]:
    """
    Extracts Project ID and Topic from pub sub topic
    """
    _resource_path = str(resource_path)
    if _resource_path.startswith("//"):
        _resource_path = _resource_path[2:]
        if not _resource_path.startswith("pubsub.googleapis.com"):
            raise InvalidGCPResource(
                f"{resource_path} is not a valid pubsub topic.")

        _resource_path.replace("pubsub.googleapis.com/", "")

    parts = _resource_path.split("/")
    _project_id, _topic = None, None
    if get_idx_safely(parts, 0) == "projects":
        _project_id = get_idx_safely(parts, 1)
    if get_idx_safely(parts, 2) == "topics":
        _topic = get_idx_safely(parts, 3)

    return _project_id, _topic


def queue_name(resource_path: str) -> Tuple[str, str, str]:
    """
    Extracts Project ID, Queue name, Location Taska Name from task name
    """
    _resource_path = str(resource_path)
    if _resource_path.startswith("//"):
        _resource_path = _resource_path[2:]
        if not _resource_path.startswith("cloudtasks.googleapis.com"):
            raise InvalidGCPResource(
                f"{resource_path} is not a valid pubsub topic.")

        _resource_path.replace("cloudtasks.googleapis.com/", "")

    parts = _resource_path.split("/")
    _project_id, _location, _queue_name, _task_name = None, None, None, None
    if get_idx_safely(parts, 0) == "projects":
        _project_id = get_idx_safely(parts, 1)
    if get_idx_safely(parts, 2) == "locations":
        _location = get_idx_safely(parts, 3)
    if get_idx_safely(parts, 4) == "queues":
        _queue_name = get_idx_safely(parts, 5)
    if get_idx_safely(parts, 6) == "tasks":
        _task_name = get_idx_safely(parts, 7)

    return _project_id, _location, _queue_name, _task_name


class GCPHTTPRequest:
    """
    Representation of a GCP HTTP request
    """

    def __init__(self, request) -> None:
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
        context=None
    ) -> None:
        self.event = event
        self.context = context
