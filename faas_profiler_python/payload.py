#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for payload resolving.
"""

from __future__ import annotations
from datetime import datetime

import logging

from abc import ABC, abstractmethod
from typing import Type

from flask import Request

from faas_profiler_core.constants import Provider, AWSOperation, AWSService
from faas_profiler_core.models import TracingContext, InboundContext

from faas_profiler_python.aws import AWSContext, AWSEvent
from faas_profiler_python.gcp import GCPHTTPRequest

from faas_profiler_python.config import Function
from faas_profiler_python.utilis import combine_list_and_dict, get_arg_by_key_or_pos, get_idx_safely


class Payload(ABC):
    """
    Base class for payload extraction and parsing.
    """

    _logger = logging.getLogger("Payload")
    _logger.setLevel(logging.INFO)

    @classmethod
    def resolve(
            cls,
            provider: Provider,
            function: Type[Function]) -> Type[Payload]:
        """
        Resolves the given payload based on the cloud provider
        """
        cls._logger.info("[PAYLOAD]: Extract payload")
        if provider == Provider.AWS:
            payload_resolver = AWSPayload
        elif provider == Provider.GCP:
            payload_resolver = GCPPayload
        else:
            cls._logger.warn(
                f"[PAYLOAD]: Could not find a payload resolver for: {provider}")
            payload_resolver = UnresolvedPayload

        try:
            return payload_resolver(*function.args, **function.kwargs)
        except Exception as err:
            cls._logger.error(
                f"[PAYLOAD]: Could parse payload: {err}")
            return UnresolvedPayload(*function.args, **function.kwargs)

    @abstractmethod
    def extract_tracing_context(self) -> Type[TracingContext]:
        pass

    @abstractmethod
    def extract_inbound_context(self) -> Type[InboundContext]:
        pass

    @abstractmethod
    def to_exportable(self):
        pass


class UnresolvedPayload(Payload):
    """
    Dummy class for payload which could not get resolved.
    """

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def extract_tracing_context(self) -> Type[TracingContext]:
        """
        Return a empty trace context.
        """
        return None

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns a empty trigger context.
        """
        return None

    def to_exportable(self):
        """
        Exports all args, kwargs
        """
        return combine_list_and_dict(self.args, self.kwargs)


class AWSPayload(Payload):
    """
    Representation of an incoming AWS Lambda payload consisting of context and event data.
    """

    def __init__(
        self,
        event: dict,
        context
    ) -> None:
        self.event_data = event
        self.context_data = context

        self.event = AWSEvent(self.event_data)
        self.context = AWSContext(self.context_data)

    def extract_tracing_context(self) -> Type[TracingContext]:
        """
        Returns context about tracing extracted either from event or client context.

        Tracing context from event is preferred.
        """
        event_ctx = self.event.extract_trace_context()
        if event_ctx and event_ctx.trace_id and event_ctx.record_id:
            return event_ctx

        return self.context.extract_trace_context()

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns context about the trigger extracted from the AWS event.
        """
        _event_inbound_context = self.event.extract_inbound_context()
        if (_event_inbound_context.service == AWSService.UNIDENTIFIED and
                _event_inbound_context.operation == AWSOperation.UNIDENTIFIED):
            _event_inbound_context = self.context.extract_inbound_context()

        _event_inbound_context.invoked_at = datetime.now()
        return _event_inbound_context

    def to_exportable(self):
        """
        Exports all variables
        """
        try:
            _context_dict = vars(self.context_data)
        except Exception:
            _context_dict = {}
        
        return {
            "event": self.event_data,
            "context": _context_dict
        }


class GCPPayload(Payload):
    """
    Representation of an incoming GCP Function payload consisting of context and event data.
    """

    def __init__(self, *args, **kwargs) -> None:
        """
        Constructor for GCP Payload
        """
        self.gcp_payload_resolver = None


        _request = kwargs.get("request")
        _event = kwargs.get("event")
        _context = kwargs.get("context")



        _first_arg = get_idx_safely(args, 0)
        # breakpoint()


        self.request = get_arg_by_key_or_pos(args, kwargs, 0, "request")
        if self.request and isinstance(self.request, Request):
            self.gcp_payload_resolver = GCPHTTPRequest(self.request)

    def extract_tracing_context(self) -> Type[TracingContext]:
        """
        Extract tracing context.
        """
        return self.gcp_payload_resolver.extract_tracing_context()

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Extracts the inbound context.
        """
        return self.gcp_payload_resolver.extract_inbound_context()

    def to_exportable(self):
        return {}
