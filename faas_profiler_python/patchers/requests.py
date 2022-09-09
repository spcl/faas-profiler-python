#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patchers for Requests
"""

import json

from __future__ import annotations
from typing import Type
from urllib.parse import urlparse

from faas_profiler_core.constants import (
    GCPService,
    GCPOperation,
    Provider,
    UnidentifiedOperation,
    UnidentifiedService,
    TriggerSynchronicity
)
from faas_profiler_core.models import OutboundContext, TracingContext

from faas_profiler_python.patchers import FunctionPatcher, PatchContext
from faas_profiler_python.utilis import get_arg_by_key_or_pos


def handle_cloud_functions_request(
    patch_context: Type[PatchContext],
    outbound_context: Type[OutboundContext]
) -> None:
    """
    Handle request to cloudfunctions domain.
    """
    outbound_context.provider = Provider.GCP
    outbound_context.service = GCPService.FUNCTIONS
    outbound_context.operation = GCPOperation.FUNCTIONS_INVOKE
    outbound_context.trigger_synchronicity = TriggerSynchronicity.SYNC

    request = get_arg_by_key_or_pos(
        patch_context.args, patch_context.kwargs, 0, "request")
    _parsed_url = urlparse(request.url)

    outbound_context.set_tags({
        "request_method": request.method,
        "request_url": _parsed_url.hostname,
        "request_uri": _parsed_url.path})

    _function_name = "unidentified"
    if _parsed_url.path:
        _function_name = _parsed_url.path[1:]

    outbound_context.set_identifiers({"function_name": _function_name})

    _api_params = None
    if request.body:
        _api_params = json.loads(request.body)

    outbound_context.set_tags({"parameters": _api_params})

    _response = patch_context.response
    if _response:
        if _response.headers:
            outbound_context.set_identifiers({
                "request_id": _response.headers.get("function-execution-id", None)})

        outbound_context.set_tags({"request_status": _response.status_code})


def default_handler(
    patch_context: Type[PatchContext],
    outbound_context: Type[OutboundContext]
) -> None:
    """
    Handle generic requests.
    """


REQUEST_HANDLERS_BY_DOMAIN = {
    "cloudfunctions": handle_cloud_functions_request
}


class SessionSend(FunctionPatcher):
    module_name: str = "requests"
    function_name: str = "Session.send"

    def extract_outbound_context(
        self,
        patch_context: Type[PatchContext]
    ) -> Type[OutboundContext]:
        """
        Extracts a context of a generic request.
        """
        outbound_context = OutboundContext(
            provider=Provider.UNIDENTIFIED,
            service=UnidentifiedService.UNIDENTIFIED,
            operation=UnidentifiedOperation.UNIDENTIFIED)

        request = get_arg_by_key_or_pos(
            patch_context.args, patch_context.kwargs, 0, "request")
        if not request:
            return outbound_context

        if request.url:
            _parsed_url = urlparse(request.url)
            _, domain, *sub_domains = _parsed_url.hostname.split(".")[::-1]

            request_handler = REQUEST_HANDLERS_BY_DOMAIN.get(domain)
            if request_handler:
                self.logger.info(
                    f"[OUTBOUND]: Found request handler for domain {domain}")
                request_handler(patch_context, outbound_context)
            else:
                self.logger.info(
                    f"[OUTBOUND]: No request handler available for domain {domain}")
                default_handler(patch_context, outbound_context)

        return outbound_context

    def inject_tracing_context(
        self,
        patch_context: Type[PatchContext],
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Inject Trace context into headers
        """
        request = get_arg_by_key_or_pos(
            patch_context.args, patch_context.kwargs, 0, "request")
        if not request:
            return

        request.headers = {
            **request.headers,
            **tracing_context.to_injectable()}
