#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime
import decimal
import json

import logging
import boto3

from typing import Any, Type
from uuid import uuid4
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from faas_profiler_python.config import Provider, TraceContext
from faas_profiler_python.patchers import (
    InvocationContext,
    request_patcher,
    ignore_instance_from_patching
)
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.payload import Payload
from faas_profiler_python.utilis import Loggable

"""
Distributed Tracer
"""


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
        payload: Type[Payload],
        provider: Provider,
        outbound_requests_tables: dict = {}
    ) -> None:
        self.payload = payload
        self.outbound_requests_table = OutboundRequestTable.factory(provider)(
            **outbound_requests_tables.get(provider, {}))

        self.current_invocation_span = InvocationSpan.create_from_incoming_payload(
            self.payload)
        self.outbound_patchers = self._patch_outbound_libraries()

    @property
    def context(self) -> Type[TraceContext]:
        """
        Returns the current trace context given by the invocation span.
        """
        return self.current_invocation_span.trace_context

    def record_outbound_request(
            self, invocation_context: Type[InvocationContext]):
        """
        Records the outbound request
        """
        self.outbound_requests_table.store_request(
            invocation_context, self.context)

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


"""
InvocationSpan
"""


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


"""
Outbound Request Table
"""


class OutboundRequestTable(ABC, Loggable):
    """
    Base class for a outbound request table.
    """

    @classmethod
    def factory(cls, provider: Provider):
        if provider == Provider.AWS:
            return AWSOutboundRequestTable
        else:
            return NoopOutboundRequestTable

    def __init__(self, *args, **kwargs) -> None:
        super().__init__()

    @abstractmethod
    def store_request(
        self,
        invocation_context: Type[InvocationContext],
        trace_context: Type[TraceContext]
    ) -> None:
        pass


class NoopOutboundRequestTable(OutboundRequestTable):
    """
    Dummy Outbound Request Table for unresolved providers.
    """

    def store_request(
        self,
        invocation_context: Type[InvocationContext],
        trace_context: Type[TraceContext]
    ) -> None:
        self.logger.warn(
            "Skipping recording outbound request. No outbound request table defined.")


class AWSOutboundRequestTable(OutboundRequestTable):
    """
    Represents a dynamoDB backed table for recording outbounding requests in AWS
    """

    def __init__(self, table_name: str, region_name: str) -> None:
        super().__init__()

        self.table_name = table_name
        self.region_name = region_name

        if self.table_name is None or self.region_name is None:
            raise RuntimeError(
                "Cannot initialize Outbound Request Table for AWS. Table name or region name is missing.")

        self.dynamodb = boto3.client('dynamodb', region_name=self.region_name)
        self.serializer = TypeSerializer()

        ignore_instance_from_patching(self.dynamodb)

    def store_request(
        self,
        invocation_context: Type[InvocationContext],
        trace_context: Type[TraceContext]
    ) -> None:
        """
        Stores the invocation the dynamodb table
        """
        request_id = uuid4()
        record = {
            **invocation_context.to_record(),
            "outbound_request_id": str(request_id),
            "timestamp": datetime.timestamp(invocation_context.invoked_at),
            "trace_id": str(trace_context.trace_id),
            "invocation_id": str(trace_context.invocation_id)
        }
        item = json.loads(json.dumps(record), parse_float=decimal.Decimal)
        item = {
            k: self.serializer.serialize(v) for k,
            v in item.items() if v != ""}
        try:
            self.dynamodb.put_item(TableName=self.table_name, Item=item)
        except ClientError as err:
            self.logger.info(
                f"Failed to record outbound request {request_id} in {self.table_name}: {err}")
        else:
            self.logger.info(
                f"Successfully recorded outbound request {request_id} in {self.table_name}")
