#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for payload resolving.
"""

from __future__ import annotations

import logging

from abc import ABC, abstractmethod
from typing import Type

from faas_profiler_python.aws import AWSContext, AWSEvent
from faas_profiler_python.config import Provider, TracingContext, InboundContext


class Payload(ABC):
    """
    Base class for payload extraction and parsing.
    """

    _logger = logging.getLogger("Payload")
    _logger.setLevel(logging.INFO)

    @classmethod
    def resolve(cls, provider: Provider, payload: tuple) -> Type[Payload]:
        """
        Resolves the given payload based on the cloud provider
        """
        cls._logger.info("[PAYLOAD]: Extract payload")
        if provider == Provider.AWS:
            payload_resolver = AWSPayload
        else:
            cls._logger.warn(
                f"[PAYLOAD]: Could not find a payload resolver for: {provider}")
            payload_resolver = UnresolvedPayload

        try:
            return payload_resolver(*payload[0], **payload[1])
        except Exception as err:
            cls._logger.error(
                f"[PAYLOAD]: Could parse payload: {err}")
            return UnresolvedPayload(*payload[0], **payload[1])

    @abstractmethod
    def extract_tracing_context(self) -> Type[TracingContext]:
        pass

    @abstractmethod
    def extract_inbound_context(self) -> Type[InboundContext]:
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
        return TracingContext()

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns a empty trigger context.
        """
        return InboundContext()


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
        if event_ctx.is_complete:
            return event_ctx

        return self.context.extract_trace_context()

    def extract_inbound_context(self) -> Type[InboundContext]:
        """
        Returns context about the trigger extracted from the AWS event.
        """
        return self.event.extract_inbound_context()
