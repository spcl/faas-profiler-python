#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""
from __future__ import annotations

import logging

from typing import Type
from contextlib import contextmanager
from uuid import uuid4

from faas_profiler_python.config import (
    ProfileConfig,
    ProfileContext,
    Provider,
    PROFILE_ID_HEADER,
    ROOT_ID_HEADER,
    SPAN_ID_HEADER
)
from faas_profiler_python.aws import AWSInjection
from faas_profiler_python.payload import AWSPayload, Payload


class InvocationSpan:
    """
    Represents a lambda invocation
    """

    _logger = logging.getLogger("DistributedTracer")
    _logger.setLevel(logging.INFO)

    @classmethod
    def create_from_incoming_payload(
        cls,
        payload: Type[Payload]
    ) -> Type[InvocationSpan]:
        parent_ctx = payload.extract_tracing_context()

        if parent_ctx.profile_id is None:
            cls._logger.info(
                f"No profile id found. Creating Span with new profile id")

        if parent_ctx.root_id is None:
            cls._logger.info(f"No root id found. Treating Span as root span.")

        return cls(
            profile_id=parent_ctx.profile_id,
            root_id=parent_ctx.span_id)

    def __init__(
        self,
        profile_id: str = None,
        root_id: str = None,
        span_id: str = None
    ) -> None:
        self.profile_id = profile_id if profile_id else uuid4()
        self.root_id = root_id
        self.span_id = span_id if span_id else uuid4()

        self._logger.info(f"NEW SPAN: {self}")

    def __str__(self) -> str:
        return f"[profile_id={self.profile_id}, root_id={self.root_id}, span_id={self.span_id}]"

    @property
    def is_root(self) -> bool:
        return self.root_id is None

    @property
    def inject_context(self) -> dict:
        """
        Returns the span as injectable context.
        """
        ctx = {}
        if self.profile_id:
            ctx[PROFILE_ID_HEADER] = str(self.profile_id)
        if self.root_id:
            ctx[ROOT_ID_HEADER] = str(self.root_id)
        if self.span_id:
            ctx[SPAN_ID_HEADER] = str(self.span_id)

        return ctx


class DistributedTracer:
    """
    Implementation of a distributed Tracer.
    """

    _logger = logging.getLogger("DistributedTracer")
    _logger.setLevel(logging.INFO)

    # @classmethod
    # def find_tracer(cls, provider: Provider) -> DistributedTracer:
    #     if provider == Provider.AWS:
    #         return AWSDistributedTracer()
    #     else:
    #         cls._logger.warn(
    #             "Could not find cloud provider specific tracer. Take base tracer.")
    #         return cls()

    def __init__(
        self,
        config: Type[ProfileConfig],
        provider: Provider,
        context: Type[ProfileContext]
    ) -> None:
        self.config = config
        self.provider = provider
        self.context = context
        self.payload = None

        self.current_span: Type[InvocationSpan] = None

        self.aws_injection = AWSInjection()

    @contextmanager
    def start(self, payload: Type[Payload]):
        self.payload = payload
        self.current_span = InvocationSpan.create_from_incoming_payload(
            self.payload)

        self.inject_request()

        yield

    def inject_request(self):
        self.aws_injection.inject_api_calls(
            data_to_inject=self.current_span.inject_context)
