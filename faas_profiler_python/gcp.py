#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for all GCP specific logic.
"""
import os

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
from faas_profiler_python.utilis import Loggable, get_idx_safely


class InvalidGCPResource(RuntimeError):
    pass


def gcp_project() -> str:
    """
    Gets GCP project ID by Env
    """
    return os.environ.get("GCLOUD_PROJECT", os.environ.get("GCP_PROJECT "))


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


class GCPHTTPRequest(Loggable):
    """
    Representation of a GCP HTTP request
    """

    def __init__(self, request) -> None:
        super().__init__()
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


class GCPEventRequest(Loggable):
    """
    Representation of a GCP Event request
    """

    SERVICE_BY_API = {
        'pubsub.googleapis.com': GCPService.PUB_SUB,
        'storage.googleapis.com': GCPService.STORAGE,
        'tasks.googleapis.com': GCPService.STORAGE,
        'cloudfunctions.googleapis.com': GCPService.FUNCTIONS,
        "firestore.googleapis.com": GCPService.FIRESTORE,
        "appengine.googleapis.com": GCPService.APP_ENGINE,
        "run.googleapis.com": GCPService.CLOUD_RUN
    }

    EVENT_TYPES = {
        "google.pubsub.topic.publish": (
            GCPService.PUB_SUB,
            GCPOperation.PUB_SUB_PUBLISH),
        "providers/cloud.pubsub/eventTypes/topic.publish": (
            GCPService.PUB_SUB,
            GCPOperation.PUB_SUB_PUBLISH),
        "google.storage.object.finalize": (
            GCPService.STORAGE,
            GCPOperation.STORAGE_UPLOAD),
        "google.storage.object.delete": (
            GCPService.STORAGE,
            GCPOperation.STORAGE_DELETE),
    }

    # EVENT_TYPES = {
    #     "providers/cloud.pubsub/eventTypes/topic.publish": (
    #         GCPService.PUB_SUB,
    #         GCPOperation.PUB_SUB_PUBLISH)
    # }

    def __init__(
        self,
        event: dict = {},
        context=None
    ) -> None:
        super().__init__()

        self.event = event
        self.context = context

        self.service, self.operation = self.resolve_service_operation()

        self.logger.info(
            f"[GCP INBOUND EVENT]: Detected inbound of service {self.service} and operation {self.operation}")

    def resolve_service_operation(self) -> Tuple[GCPService, GCPOperation]:
        """
        Resolve service and operation
        """
        service, operation = GCPService.UNIDENTIFIED, GCPOperation.UNIDENTIFIED

        event_type = self.context.event_type
        if event_type in self.EVENT_TYPES:
            service, operation = self.EVENT_TYPES[event_type]

        return service, operation

    def extract_tracing_context(self) -> Type[TracingContext]:
        """
        Extract tracing context from GCP Event.
        """
        if self.service == GCPService.PUB_SUB:
            return self.tracing_context_from_pubsub()

        return None

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Extracts the inbound context from GCP Event.
        """
        inbound_context = InboundContext(
            Provider.GCP, self.service, self.operation)

        if self.service == GCPService.PUB_SUB:
            self.pubsub_inbound(inbound_context)

        return inbound_context

    """
    Inbound Context Extraction
    """

    def pubsub_inbound(self, inbound_context: Type[InboundContext]) -> None:
        """
        Extract inbound context from pub/sub
        """
        inbound_context.trigger_synchronicity = TriggerSynchronicity.ASYNC

        _topic, _project_id = None, None
        if hasattr(self.context, "resource"):
            _resource = self.context.resource
            if isinstance(_resource, str):
                _project_id, _topic = pubsub_topic(_resource)
            elif isinstance(_resource, dict):
                _project_id, _topic = pubsub_topic(_resource.get("name"))
            else:
                self.logger.warn(
                    f"[GCP Inbound Event] Got resource of type {type(_resource)}. No resolving defined.")

        if _project_id is None:
            _project_id = gcp_project()

        inbound_context.set_identifiers({
            "project_id": _project_id,
            "event_id": getattr(self.context, "event_id", None),
            "topic_name": _topic
        })

    """
    Tracing Context Extraction
    """

    def tracing_context_from_pubsub(self) -> Type[TracingContext]:
        """
        Extracts tracing context from message attributes.
        """
        _attributes = self.event.get("attributes", {})

        return TracingContext(
            trace_id=_attributes.get(TRACE_ID_HEADER),
            record_id=_attributes.get(RECORD_ID_HEADER),
            parent_id=_attributes.get(PARENT_ID_HEADER))
