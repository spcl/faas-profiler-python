#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher for AWS botocore.
"""

from __future__ import annotations
from typing import List, Type

from faas_profiler_core.models import OutboundContext, TracingContext
from faas_profiler_core.constants import Provider, TriggerSynchronicity, GCPService, GCPOperation

from faas_profiler_python.gcp import pubsub_topic, queue_name

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


"""
Pub/Sub Patcher
"""


class PubSubPublish(FunctionPatcher):
    module_name = "google.cloud"
    submodules = ["pubsub"]
    function_name = "PublisherClient.publish"

    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        self.patch_context = patch_context

    def extract_outbound_context(self) -> List[Type[OutboundContext]]:
        """
        Extract outbound contexts of pubsub publish.
        """
        if not self.patch_context:
            return

        _topic_name = get_arg_by_key_or_pos(
            self.patch_context.args,
            self.patch_context.kwargs,
            0,
            "topic")

        _project_id, _topic = pubsub_topic(_topic_name)

        _event_id = None
        if self.patch_context.response:
            try:
                _event_id = getattr(self.patch_context.response, "result")()
            except Exception:
                pass

        return [OutboundContext(
            provider=Provider.GCP,
            service=GCPService.PUB_SUB,
            operation=GCPOperation.PUB_SUB_PUBLISH,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            identifier={
                "project_id": _project_id,
                "event_id": _event_id,
                "topic_name": _topic})]

    def inject_tracing_context(
        self,
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Injects tracing context to publish attributes
        """
        self.patch_context.kwargs.update(tracing_context.to_injectable())


"""
Pub/Sub Patcher
"""


class TasksCreate(FunctionPatcher):
    module_name = "google.cloud"
    submodules = ["tasks"]
    function_name = "CloudTasksClient.create_task"

    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        self.patch_context = patch_context

    def extract_outbound_context(self) -> List[Type[OutboundContext]]:
        """
        Extract outbound contexts of tasks create.
        """
        if not self.patch_context:
            return

        _task_name = None
        if self.patch_context.response:
            _task_name = self.patch_context.response.name
        else:
            self.logger.warn("Extract task name from arguments")

        _project_id, _location, _queue_name, _task_id = queue_name(_task_name)

        return [OutboundContext(
            provider=Provider.GCP,
            service=GCPService.CLOUD_TASKS,
            operation=GCPOperation.CLOUD_TASKS_CREATE,
            trigger_synchronicity=TriggerSynchronicity.ASYNC,
            identifier={
                "project_id": _project_id,
                "region": _location,
                "queue_name": _queue_name,
                "task_name": _task_id})]

    def inject_tracing_context(
        self,
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Injects tracing context into HTTP Headers of HTTP request.
        """
        task = self._find_cloud_task(
            self.patch_context.args,
            self.patch_context.kwargs)
        if task is None:
            self.logger.error(
                "[GCP TASKS PATCHER]: Could not find task in payload. Skip injection.")
            return

        # Inject HTTP Request
        if hasattr(task, "http_request"):
            http_request_task = task.http_request
            http_request_task.headers.update(
                tracing_context.to_injectable())

    def _find_cloud_task(self, func_args, func_kwargs):
        """
        Finds cloud task in arguments
        """
        _task = None

        _request = get_arg_by_key_or_pos(
            self.patch_context.args, self.patch_context.kwargs, 0, "request")

        if _request is not None:
            _task = getattr(_request, "task", None)

        if _task is None:
            _task = get_arg_by_key_or_pos(
                self.patch_context.args, self.patch_context.kwargs, 1, "task")

        return _task
