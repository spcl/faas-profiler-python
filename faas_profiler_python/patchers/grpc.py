#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patchers for GRPC

FIXME: Quick and dirty solution, adapt this with the framework
"""

from __future__ import annotations

import sys
import logging
import multiprocessing

from wrapt import wrap_function_wrapper
from typing import Any, Callable, Type

from faas_profiler_core.constants import AWSService, AWSOperation, Provider, TriggerSynchronicity
from faas_profiler_core.models import OutboundContext, TracingContext
from faas_profiler_python.config import InjectionError, UnsupportedServiceError

from faas_profiler_python.patchers import FunctionPatcher, PatchContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos

from grpc_interceptor import ClientCallDetails, ClientInterceptor

_lock = multiprocessing.Lock()

_logger = logging.getLogger("[GRPC PATCH]")
_logger.setLevel(logging.INFO)

import grpc

def patch_with_hook(
    module_name: str,
    function_name: str,
    wrapper: Callable
) -> None:
    if module_name in sys.modules:
        wrap_function_wrapper(module_name, function_name, wrapper)
    else:
        print("Set hook")


def setup_grpc_interceptor():
    """
    Add a intercepter for insecure and secure channel
    """
    _logger.info("Patch channel to intercept requests.")

    # PATCHING CLIENT
    with _lock:
        patch_with_hook("grpc", "insecure_channel", _add_channel_intercepter_client)
        patch_with_hook("grpc", "secure_channel", _add_channel_intercepter_client)
        # patch_with_hook("grpc", "intercept_channel")

    # PATCHING SERVER
    with _lock:
        patch_with_hook("grpc", "server", _add_server_intercepter)

def remove_interceptor():
    pass


### Channel patches

def _add_channel_intercepter_client(
    channel_function: Type[Callable],
    instance: Any,
    function_args: tuple,
    function_kwargs: dict,
):
    _grpc_channel = channel_function(*function_args, **function_kwargs)
    return grpc.intercept_channel(_grpc_channel, Foo())


def _add_server_intercepter(
    channel_function: Type[Callable],
    instance: Any,
    function_args: tuple,
    function_kwargs: dict,
):
    pass

### Interceptors

class Foo(ClientInterceptor):
    def intercept(
        self,
        method: Callable,
        request_or_iterator: Any,
        call_details: Any,
    ):
        """Override this method to implement a custom interceptor.

        This method is called for all unary and streaming RPCs. The interceptor
        implementation should call `method` using a `grpc.ClientCallDetails` and the
        `request_or_iterator` object as parameters. The `request_or_iterator`
        parameter may be type checked to determine if this is a singluar request
        for unary RPCs or an iterator for client-streaming or client-server streaming
        RPCs.

        Args:
            method: A function that proceeds with the invocation by executing the next
                interceptor in the chain or invoking the actual RPC on the underlying
                channel.
            request_or_iterator: RPC request message or iterator of request messages
                for streaming requests.
            call_details: Describes an RPC to be invoked.

        Returns:
            The type of the return should match the type of the return value received
            by calling `method`. This is an object that is both a
            `Call <https://grpc.github.io/grpc/python/grpc.html#grpc.Call>`_ for the
            RPC and a `Future <https://grpc.github.io/grpc/python/grpc.html#grpc.Future>`_.

            The actual result from the RPC can be got by calling `.result()` on the
            value returned from `method`.
        """
        new_details = ClientCallDetails(
            call_details.method,
            call_details.timeout,
            [("authorization", "Bearer mysecrettoken")],
            call_details.credentials,
            call_details.wait_for_ready,
            call_details.compression,
        )

        return method(request_or_iterator, call_details)
