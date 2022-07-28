#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for IO botocore.
"""

from __future__ import annotations

from typing import Type

from faas_profiler_python.patchers import FunctionPatcher, OutboundContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos


class Open(FunctionPatcher):
    module_name: str = "builtins"
    function_name: str = "open"

    def extract_outbound_context(
            self,
            invocation_context: Type[OutboundContext]) -> None:

        file = get_arg_by_key_or_pos(
            invocation_context.original_args,
            invocation_context.original_kwargs,
            0,
            "file")
        mode = get_arg_by_key_or_pos(
            invocation_context.original_args,
            invocation_context.original_kwargs,
            1,
            "mode")
        in_encoding = get_arg_by_key_or_pos(
            invocation_context.original_args,
            invocation_context.original_kwargs,
            3,
            "encoding")

        out_encoding = None
        if invocation_context.response:
            out_encoding = str(
                getattr(
                    invocation_context.response,
                    "encoding",
                    None))

        invocation_context.set_tags({
            "file": str(file),
            "mode": str(mode),
            "encoding": in_encoding if in_encoding else out_encoding
        })
