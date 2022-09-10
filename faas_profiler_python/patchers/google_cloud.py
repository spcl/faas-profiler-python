#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import List, Type

from faas_profiler_core.models import OutboundContext
from faas_profiler_core.constants import Provider, TriggerSynchronicity, GCPService, GCPOperation

from faas_profiler_python.patchers import FunctionPatcher, PatchContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos, get_idx_safely

"""
Google Cloud Function Patcher
"""


def parse_function_name(name: str):
    """
    Parse function name into subparts
    """
    parts = str(name).split("/")

    _project_id = get_idx_safely(parts, 1, None)
    _region = get_idx_safely(parts, 3, None)
    _function_name = get_idx_safely(parts, 5, None)

    return _project_id, _region, _function_name


class InvokeFunction(FunctionPatcher):
    module_name = "google.cloud"
    submodules = ["functions_v1"]
    function_name = "CloudFunctionsServiceClient.call_function"

    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        self.patch_context = patch_context

    def extract_outbound_context(self) -> List[Type[OutboundContext]]:
        """
        Extract outbound context from invocation
        """
        if not self.patch_context:
            return

        _response = self.patch_context.response
        _request_id = None

        if _response:
            _request_id = getattr(_response, "execution_id", None)

        name = get_arg_by_key_or_pos(
            self.patch_context.args,
            self.patch_context.kwargs,
            pos=0,
            kw="name",
            default="")

        _, _, function_name = parse_function_name(name)

        return [OutboundContext(
            provider=Provider.GCP,
            service=GCPService.FUNCTIONS,
            operation=GCPOperation.FUNCTIONS_INVOKE,
            identifier={
                "request_id": _request_id,
                "function_name": function_name
            })]


"""
Google Cloud Storage Patcher
"""


class StorageUpload(FunctionPatcher):
    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        self.patch_context = patch_context

    def extract_outbound_context(self) -> List[Type[OutboundContext]]:
        """
        Extract outbound contexts of storage upload.
        """
        if not self.patch_context:
            return

        _blob = self.patch_context.instance
        _generation_id = getattr(_blob, "generation", None)
        _object_key = getattr(_blob, "name", None)

        _bucket_name = None
        if hasattr(_blob, "bucket"):
            _bucket_name = getattr(_blob.bucket, "name", None)

        return [OutboundContext(
            provider=Provider.GCP,
            service=GCPService.STORAGE,
            operation=GCPOperation.STORAGE_UPLOAD,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            identifier={
                "bucket_name": _bucket_name,
                "object_key": _object_key,
                "generation": _generation_id})]


class StorageUploadFileName(StorageUpload):
    module_name = "google.cloud"
    submodules = ["storage"]
    function_name = "Blob.upload_from_filename"


class StorageUploadFile(StorageUpload):
    module_name = "google.cloud"
    submodules = ["storage"]
    function_name = "Blob.upload_from_file"


class StorageUploadFileMemory(StorageUpload):
    module_name = "google.cloud"
    submodules = ["storage"]
    function_name = "Blob.upload_from_string"


class StorageDeleteFile(FunctionPatcher):
    module_name = "google.cloud"
    submodules = ["storage"]
    function_name = "Blob.delete"

    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        self.patch_context = patch_context

    def extract_outbound_context(self) -> List[Type[OutboundContext]]:
        """
        Extract outbound contexts of storage upload.
        """
        if not self.patch_context:
            return

        _blob = self.patch_context.instance
        _object_key = getattr(_blob, "name", None)

        _bucket_name = None
        if hasattr(_blob, "bucket"):
            _bucket_name = getattr(_blob.bucket, "name", None)

        return [OutboundContext(
            provider=Provider.GCP,
            service=GCPService.STORAGE,
            operation=GCPOperation.STORAGE_DELETE,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            identifier={
                "bucket_name": _bucket_name,
                "object_key": _object_key})]
