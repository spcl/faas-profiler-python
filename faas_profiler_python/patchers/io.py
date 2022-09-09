#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for IO botocore.
"""
from __future__ import annotations

import os

from typing import Type
from datetime import datetime

from faas_profiler_core.models import OutboundContext
from faas_profiler_core.constants import (
    Provider,
    InternalService,
    InternalOperation
)

from faas_profiler_python.patchers import FunctionPatcher, PatchContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos


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


class Open(FunctionPatcher):
    module_name: str = "builtins"
    function_name: str = "open"

    def extract_outbound_context(
        self,
        patch_context: Type[PatchContext]
    ) -> Type[OutboundContext]:
        """
        Extracts outbound context based for IO open
        """
        _folder, _filename, _size = None, None, None
        _last_modified_at, _last_accessed_at, _created_at = None, None, None
        _file = get_arg_by_key_or_pos(
            patch_context.args,
            patch_context.kwargs,
            0,
            "file")

        if _file:
            _folder, _filename = os.path.split(_file)
            _size = os.path.getsize(_file)
            _last_modified_at = datetime.fromtimestamp(os.path.getmtime(_file))
            _created_at = datetime.fromtimestamp(os.path.getctime(_file))
            _last_accessed_at = datetime.fromtimestamp(os.path.getatime(_file))

        _in_op, _in_enc = self._extract_from_args(
            patch_context.args, patch_context.kwargs)

        _out_op, _out_enc = self._extract_from_response(
            patch_context.response)

        _operation = _out_op if _out_op else _in_op
        _encoding = _out_enc if _out_enc else _in_enc

        outbound_context = OutboundContext(
            provider=Provider.INTERNAL,
            service=InternalService.IO,
            operation=_operation)

        outbound_context.set_tags({
            "file": _file,
            "filename": _filename,
            "folder": _folder,
            "size": _size,
            "encoding": _encoding,
            "created_at": _created_at,
            "last_modified_at": _last_modified_at,
            "last_accessed_at": _last_accessed_at})

        outbound_context.set_identifiers({
            "file": _file
        })

        return outbound_context

    def _extract_from_args(self, args, kwargs) -> tuple:
        """
        Extract operation, encoding from args
        """
        _mode = get_arg_by_key_or_pos(args, kwargs, 1, "mode")
        _operation = IO_MODE_TO_OPERATION.get(
            _mode, InternalOperation.UNIDENTIFIED)

        _encoding = get_arg_by_key_or_pos(args, kwargs, 3, "encoding")

        return _operation, _encoding

    def _extract_from_response(self, response) -> tuple:
        """
        Extract operation, encoding from response
        Response is IO Wrapper
        """
        _mode = getattr(response, "mode", None)
        _operation = IO_MODE_TO_OPERATION.get(
            _mode, InternalOperation.UNIDENTIFIED)

        _encoding = getattr(response, "encoding", None)

        return _operation, _encoding
