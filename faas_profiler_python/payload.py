#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for payload resolving.
"""

from __future__ import annotations

import logging

from abc import ABC, abstractmethod
from typing import Type
from functools import partial

from faas_profiler_python.config import Provider
from faas_profiler_python.utilis import Registerable
from faas_profiler_python.tracer import TraceContext


class Payload(Registerable, ABC):
    """
    Base class for payload extraction and parsing.
    """

    _logger = logging.getLogger("Payload")
    _logger.setLevel(logging.INFO)

    @abstractmethod
    def extract_tracing_context(self) -> Type[TraceContext]:
        pass


register_resolver = partial(Payload.register, module_delimiter=None)


@register_resolver(Provider.AWS)
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

        # self.event = AWSEvent(self.event_data)
        # self.context = AWSContext(self.context_data)

    def extract_tracing_context(self) -> Type[TraceContext]:
        return super().extract_tracing_context()


# class AWSContext:

#     def __init__(self, context) -> None:
#         self._context = context

#         self.aws_request_id = getattr(context, "aws_request_id", None)
#         self.log_group_name = getattr(context, "log_group_name", None)
#         self.log_stream_name = getattr(context, "log_stream_name", None)
#         self.function_name = getattr(context, "function_name", None)
#         self.memory_limit_in_mb = getattr(context, "memory_limit_in_mb", None)
#         self.function_version = getattr(context, "function_version", None)
#         self.invoked_function_arn = getattr(
#             context, "invoked_function_arn", None)
#         self.client_context = getattr(context, "client_context", None)

#         self.size = getsizeof(context)

#     @property
#     def context(self) -> dict:
#         return {
#             "aws_request_id": self.aws_request_id,
#             "log_group_name": self.log_group_name,
#             "log_stream_name": self.log_stream_name,
#             "function_name": self.function_name,
#             "memory_limit_in_mb": self.memory_limit_in_mb,
#             "function_version": self.function_version,
#             "invoked_function_arn": self.invoked_function_arn,
#             "client_context": self.client_context,
#         }
