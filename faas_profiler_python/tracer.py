#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""
from __future__ import annotations
import json

from typing import Any, List, Type
from uuid import uuid4

from faas_profiler_core.constants import (
    Provider,
    TRACE_CONTEXT_KEY
)
from faas_profiler_core.models import InboundContext, OutboundContext, TracingContext

from faas_profiler_python.config import Config, ALL_PATCHERS
from faas_profiler_python.patchers import (
    FunctionPatcher,
    request_patcher
)
from faas_profiler_python.patchers.botocore import BotocoreAPI
from faas_profiler_python.patchers.requests import SessionSend
from faas_profiler_python.patchers.google_cloud import (
    StorageUploadFileMemory,
    StorageUploadFileName,
    StorageUploadFile,
    StorageDeleteFile,
    InvokeFunction
)
from faas_profiler_python.payload import Payload
from faas_profiler_python.utilis import Loggable

"""
Distributed Tracer
"""

AVAILABLE_OUTBOUND_PATCHERS = {
    "aws": [BotocoreAPI],
    "requests": [SessionSend],
    "gcp": [
        StorageUploadFile,
        StorageUploadFileMemory,
        StorageUploadFileName,
        StorageDeleteFile,
        InvokeFunction
    ]
}


class DistributedTracer(Loggable):
    """
    Implementation of a distributed Tracer.
    """

    def __init__(
        self,
        config: Type[Config],
        provider: Type[Provider] = Provider.UNIDENTIFIED
    ) -> None:
        super().__init__()

        self.config: Type[Config] = config
        self.provider: Type[Provider] = provider

        self._inbound_context: Type[InboundContext] = None
        self._outbound_contexts: List[Type[OutboundContext]] = []
        self._tracing_context: Type[TracingContext] = None

        self._active_outbound_patchers: List[Type[FunctionPatcher]] = []

        self._recorded_identifier = set()

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
        if not self.config.tracing_enabled:
            self.logger.warn(
                "[TRACER]: Do not patch outgoing request. Tracer disabled.")
            return

        _trace_outgoing_requests = self.config.trace_outgoing_requests
        if _trace_outgoing_requests == ALL_PATCHERS:
            for outbound_libraries in AVAILABLE_OUTBOUND_PATCHERS.values():
                for outbound_library in outbound_libraries:
                    self._prepare_patcher(outbound_library)
        else:
            for requested_outgoing_lib in _trace_outgoing_requests:
                outbound_libraries = AVAILABLE_OUTBOUND_PATCHERS.get(
                    requested_outgoing_lib)
                if outbound_libraries is None:
                    self.logger.warn(
                        f"[TRACER]: Could not set patcher for {requested_outgoing_lib}. Not available.")
                    continue

                for outbound_library in outbound_libraries:
                    self._prepare_patcher(outbound_library)

    def stop_tracing_outbound_requests(self):
        """
        Stops tracing outgoing requests by unpatching libraries.
        """
        for active_patcher in self._active_outbound_patchers:
            active_patcher.deactivate()

    def _prepare_patcher(self, outbound_library):
        """
        Activate patcher for injection.
        """
        patcher = request_patcher(outbound_library)
        patcher.register_observer(self.handle_outbound_request)
        patcher.set_trace_context_to_inject(self.tracing_context)
        patcher.activate()

        self._active_outbound_patchers.append(patcher)

    """
    Request handling methods
    """

    def handle_inbound_request(
        self,
        payload: Type[Payload]
    ) -> None:
        """
        Handles the incoming request, which is the current call of the serverless function.

        Parameters
        ----------
        payload: Payload
            serverless Payload representation
        """
        self._inbound_context = payload.extract_inbound_context()
        self._tracing_context = self._inferre_tracing_context(
            parent_context=payload.extract_tracing_context())

        self.logger.info(
            f"[TRACER]: New Tracing Context: {self._tracing_context}")

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
        identifier_string = outbound_context.identifier_string
        if identifier_string in self._recorded_identifier:
            self.logger.info(
                f"[TRACER]: Skip recording {identifier_string}. Already recorded.")
            return

        self._outbound_contexts.append(outbound_context)
        self._recorded_identifier.add(identifier_string)

        self.logger.info(
            f"[TRACER]: Recorded outgoing request: {identifier_string}")

    def handle_function_response(
        self,
        response: Any
    ) -> Any:
        """
        Injects response if possible.
        """
        _response = response
        _is_json = False
        if isinstance(response, str):
            try:
                _response = json.loads(response)
                _is_json = True
            except Exception:
                pass

        if not isinstance(_response, dict):
            self.logger.warn(
                "Skip injecting response. Response is not a dict.")
            return response

        _response = _response[TRACE_CONTEXT_KEY] = self._tracing_context.to_injectable(
        )
        if _is_json:
            return json.dumps(_response)
        else:
            return _response

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
                "[TRACER]: Parent tracing context is empty. Create new one.")
            return TracingContext(trace_id=uuid4(), record_id=uuid4())

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
