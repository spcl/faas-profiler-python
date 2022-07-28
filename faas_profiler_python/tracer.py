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
import boto3

from typing import List, Type
from uuid import uuid4
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from faas_profiler_python.config import Config, Provider, TracingContext, InboundContext
from faas_profiler_python.patchers import (
    FunctionPatcher,
    OutboundContext,
    request_patcher,
    ignore_instance_from_patching
)
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.payload import Payload
from faas_profiler_python.utilis import Loggable

"""
Distributed Tracer
"""


class DistributedTracer(Loggable):
    """
    Implementation of a distributed Tracer.
    """

    outbound_libraries = [
        BotocoreAPI
    ]

    def __init__(
        self,
        config: Type[Config],
        provider: Type[Provider] = Provider.UNIDENTIFIED
    ) -> None:
        super().__init__()

        self.config: Type[Config] = config
        self.provider: Type[Provider] = provider

        self.payload: Type[Payload] = None
        self._inbound_context: Type[InboundContext] = None
        self._outbound_contexts: List[Type[OutboundContext]] = []
        self._tracing_context: Type[TracingContext] = None

        self._outbound_request_table = self._initialize_outbound_request_table()

        self._active_outbound_patchers: List[Type[FunctionPatcher]] = []

    """
    Properties
    """

    @property
    def inbound_context(self) -> Type[InboundContext]:
        """
        Returns the context of the inbound request.
        """
        return self._inbound_context

    @property
    def outbound_contexts(self) -> List[Type[OutboundContext]]:
        """
        Returns a list of contexts of outbound requests.
        """
        return self._outbound_contexts

    @property
    def tracing_context(self) -> Type[TracingContext]:
        """
        Returns the context for tracing.
        """
        return self._tracing_context

    """
    Tracing methods
    """

    def start_tracing_outbound_requests(self):
        """
        Starts tracing outgoing requests by patching the libraries that make these requests.
        """
        for outbound_library in self.outbound_libraries:
            patcher = request_patcher(outbound_library)
            patcher.register_observer(self.handle_outbound_request)
            patcher.set_trace_context_to_inject(self.tracing_context)
            patcher.activate()

            self._active_outbound_patchers.append(patcher)

    def stop_tracing_outbound_requests(self):
        """
        Stops tracing outgoing requests by unpatching libraries.
        """
        pass

    """
    Request handling methods
    """

    def handle_inbound_request(
        self,
        function_args: tuple = tuple(),
        function_kwargs: dict = {}
    ) -> None:
        """
        Handles the incoming request, which is the current call of the serverless function.

        Parameters
        ----------
        function_args: tuple
            decorated function arguments
        function_kwargs: tuple
            decorated function keyword arguments
        """
        self.payload = Payload.resolve(
            self.provider, (function_args, function_kwargs))
        self._inbound_context = self.payload.extract_inbound_context()
        self._tracing_context = TracingContext.create_from_payload_tracing_context(
            payload_tracing_context=self.payload.extract_tracing_context())

        self.logger.info(f"NEW SPAN: {self._tracing_context}")

    def handle_outbound_request(
        self,
        outbound_context: Type[OutboundContext]
    ) -> None:
        """
        Handles outgoing requests, which are stored and sent to a database if configured.

        Parameters
        ----------
        outbound_context: OutboundContext
            Context of the outbound request.
        """
        self._outbound_request_table.store_request(
            outbound_context, self.tracing_context)

    """
    Private methods
    """

    def _initialize_outbound_request_table(self):
        """
        Initializes a new Outbound Request Table based on the provider
        """
        try:
            outbound_table_cls = OutboundRequestTable.factory(self.provider)
            outbound_request_table = outbound_table_cls(
                **self.config.outbound_requests_tables.get(self.provider, {}))
            self.logger.info(
                f"Initialized new Outbound Request Table {outbound_table_cls.__name__} for {self.provider}")
            return outbound_request_table
        except Exception as err:
            self.logger.error(
                f"Could not initialize Outbound Request Table for {self.provider}: {err}")
            return NoopOutboundRequestTable()


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
        invocation_context: Type[OutboundContext],
        trace_context: Type[TracingContext]
    ) -> None:
        pass


class NoopOutboundRequestTable(OutboundRequestTable):
    """
    Dummy Outbound Request Table for unresolved providers.
    """

    def store_request(
        self,
        invocation_context: Type[OutboundContext],
        trace_context: Type[TracingContext]
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
        invocation_context: Type[OutboundContext],
        trace_context: Type[TracingContext]
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
