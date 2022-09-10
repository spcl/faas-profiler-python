#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patchers for GRPC

FIXME: Quick and dirty solution, adapt this with the framework
"""

from __future__ import annotations
import grpc

import sys
import logging
import multiprocessing

from wrapt import wrap_function_wrapper
from typing import Any, Callable, Type

from grpc_interceptor import ClientCallDetails, ClientInterceptor

_lock = multiprocessing.Lock()

_logger = logging.getLogger("[GRPC PATCH]")
_logger.setLevel(logging.INFO)


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
        patch_with_hook(
            "grpc",
            "insecure_channel",
            _add_channel_intercepter_client)
        patch_with_hook(
            "grpc",
            "secure_channel",
            _add_channel_intercepter_client)
        # patch_with_hook("grpc", "intercept_channel")

    # PATCHING SERVER
    # with _lock:
    #     patch_with_hook("grpc", "server", _add_server_intercepter)


def remove_interceptor():
    pass


# Channel patches

def _add_channel_intercepter_client(
    channel_function: Type[Callable],
    instance: Any,
    function_args: tuple,
    function_kwargs: dict,
):
    _grpc_channel = channel_function(*function_args, **function_kwargs)
    return grpc.intercept_channel(_grpc_channel, ClientInterceptor())


def _add_server_intercepter(
    channel_function: Type[Callable],
    instance: Any,
    function_args: tuple,
    function_kwargs: dict,
):
    pass

# Interceptors


class ClientInterceptor(ClientInterceptor):
    def intercept(
        self,
        method: Callable,
        request_or_iterator: Any,
        call_details: Any,
    ):
        # DO STUFF

        return method(request_or_iterator, call_details)
