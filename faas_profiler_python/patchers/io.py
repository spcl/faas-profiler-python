#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for IO botocore.
"""
from __future__ import annotations
from functools import partial

import os

from datetime import datetime
from typing import Any, Callable, Type

from faas_profiler_core.models import OutboundContext
from faas_profiler_core.constants import (
    Provider,
    InternalService,
    InternalOperation
)

from faas_profiler_python.patchers import FunctionPatcher
from faas_profiler_python.utilis import get_arg_by_key_or_pos

__all__ = [
    "OpenIO"
]

IO_MODE_TO_OPERATION = {
    "r": InternalOperation.IO_READ,
    "rb": InternalOperation.IO_READ,
    "r+": InternalOperation.IO_READ_WRITE,
    "rb+": InternalOperation.IO_READ_WRITE,
    "w": InternalOperation.IO_WRITE,
    "wb": InternalOperation.IO_WRITE,
    "w+": InternalOperation.IO_READ_WRITE,
    "wb+": InternalOperation.IO_READ_WRITE,
    "a": InternalOperation.IO_WRITE,
    "ab": InternalOperation.IO_WRITE,
    "a+": InternalOperation.IO_READ_WRITE,
    "ab+": InternalOperation.IO_READ_WRITE,
}

IGNOREABLE_PATHS = [
    "/proc/",
    "/tmp/is-warm.txt"
]


class IOBaseProxy(object):
    def __init__(self, original_wrapper, callback):
        self.original_wrapper = original_wrapper
        self.callback = callback

        self.enter_at = 0

    def __getattr__(self, __name):
        if __name == "__enter__" or __name == "__exit__":
            return getattr(self, __name)

        return getattr(self.original_wrapper, __name)

    def __enter__(self, *args, **kwargs):
        self.enter_at = datetime.now()
        return self.original_wrapper.__enter__(*args, **kwargs)

    def __exit__(self, *args, **kwargs):
        exit_org = self.original_wrapper.__exit__(*args, **kwargs)
        exit_at = datetime.now()
        self.callback(enter_at=self.enter_at, exit_at=exit_at)
        return exit_org

    def close(self, *args, **kwargs):
        exit_org = self.original_wrapper.close(*args, **kwargs)
        exit_at = datetime.now()
        self.callback(enter_at=self.enter_at, exit_at=exit_at)
        return exit_org


class OpenIO(FunctionPatcher):
    module_name: str = "builtins"
    function_name: str = "open"

    def _function_wrapper(
        self,
        func: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ) -> Any:
        if not self._active:
            return func(*args, **kwargs)

        file = get_arg_by_key_or_pos(args, kwargs, 0, "file")
        if any(str(file).startswith(path) for path in IGNOREABLE_PATHS):
            return func(*args, **kwargs)

        started_at = datetime.now()
        file_object = func(*args, **kwargs)

        return IOBaseProxy(file_object, partial(self.extract_io_outbound,
                                                started_at=started_at,
                                                function_args=args,
                                                function_kwargs=kwargs))

    def extract_io_outbound(
        self,
        function_args,
        function_kwargs,
        started_at: datetime = None,
        enter_at: datetime = None,
        exit_at: datetime = None
    ) -> None:
        """
        Extract IO Outbound
        """
        file = get_arg_by_key_or_pos(function_args, function_kwargs, 0, "file")

        size = None
        if file and os.path.exists(file):
            size = os.path.getsize(file)

        access_time = None
        if enter_at and started_at:
            access_time = (enter_at - started_at).total_seconds() * 1e4

        operation = self._extract_op_from_args(
            function_args, function_kwargs)

        outbound_context = OutboundContext(
            provider=Provider.INTERNAL,
            service=InternalService.IO,
            operation=operation)

        outbound_context.set_tags({
            "file": file,
            "size": size,
            "access_time": access_time
        })

        outbound_context.set_identifiers({
            "file": file
        })

        self._notify_observers(
            [outbound_context],
            invoked_at=started_at,
            finished_at=exit_at)

    def _extract_op_from_args(self, args, kwargs) -> InternalOperation:
        """
        Extract operation froma args
        """
        _mode = get_arg_by_key_or_pos(args, kwargs, 1, "mode")
        return IO_MODE_TO_OPERATION.get(
            _mode, InternalOperation.UNIDENTIFIED)
