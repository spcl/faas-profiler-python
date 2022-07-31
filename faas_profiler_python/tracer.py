#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""
from __future__ import annotations

from typing import List, Type
from uuid import uuid4

from faas_profiler_core.outbound import OutboundRequestTable, NoopOutboundRequestTable
from faas_profiler_core.constants import Provider
from faas_profiler_core.models import InboundContext, OutboundContext, TracingContext

from faas_profiler_python.config import Config
from faas_profiler_python.patchers import (
    FunctionPatcher,
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
        self._tracing_context = self._inferre_tracing_context(
            parent_context=self.payload.extract_tracing_context())

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

        self._outbound_contexts.append(outbound_context)

    """
    Private methods
    """

    def _inferre_tracing_context(
        self,
        parent_context: Type[TracingContext]
    ) -> Type[TracingContext]:
        """
        Creates tracing context based on parent context.
        """
        if not parent_context:
            self.logger.info(
                "Parent tracing context is empty. Create new one.")
            return TracingContext(trace_id=uuid4(), record_id=uuid4)

        if parent_context.trace_id:
            trace_id = parent_context.trace_id
        else:
            trace_id = uuid4()

        if parent_context.record_id:
            parent_id = parent_context.record_id
        else:
            parent_id = None

        return TracingContext(
            trace_id=trace_id,
            record_id=uuid4(),
            parent_id=parent_id)

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

            # TODO: AWS specific
            ignore_instance_from_patching(outbound_request_table.dynamodb)
            return outbound_request_table
        except Exception as err:
            self.logger.error(
                f"Could not initialize Outbound Request Table for {self.provider}: {err}")
            return NoopOutboundRequestTable()
