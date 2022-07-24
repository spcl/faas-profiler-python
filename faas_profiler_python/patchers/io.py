#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for IO botocore.
"""

from __future__ import annotations

import io

from dataclasses import dataclass
from typing import Any, Callable, Type

from faas_profiler_python.patchers import FunctionPatcher
from faas_profiler_python.utilis import get_arg_by_key_or_pos


@dataclass
class IOCall:
    file: str = None
    mode: str = None
    encoding: str = None


@dataclass
class IOReturn:
    wrapper_type: io.IOBase = None
    file: str = None
    mode: str = None
    encoding: str = None


class Open(FunctionPatcher):
    module_name: str = "builtins"
    function_name: str = "open"

    def before_invocation(
        self,
        original_func: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ) -> Type[IOCall]:
        file = get_arg_by_key_or_pos(args, kwargs, 0, "file")
        mode = get_arg_by_key_or_pos(args, kwargs, 1, "mode")
        encoding = get_arg_by_key_or_pos(args, kwargs, 3, "encoding")

        return IOCall(str(file), str(mode), str(encoding))

    def after_invocation(
            self,
            response: Any,
            error: Any = None) -> Type[IOReturn]:
        if not hasattr(response, "__class__"):
            return

        io_class = response.__class__
        if not issubclass(io_class, io.IOBase):
            return

        return IOReturn(
            wrapper_type=io_class,
            file=str(getattr(response, "name", None)),
            mode=str(getattr(response, "mode", None)),
            encoding=str(getattr(response, "encoding", None)))
