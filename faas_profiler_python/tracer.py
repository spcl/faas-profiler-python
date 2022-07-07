#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""

from dataclasses import dataclass

# https://specs.openstack.org/openstack/api-wg/guidelines/headers.html
PROFILE_ID_HEADER = "FaaS-Profiler-Profile-ID"
ROOT_ID_HEADER = "FaaS-Profiler-Root-ID"
SPAN_ID_HEADER = "FaaS-Profiler-Span-ID"

TRACE_CONTEXT_KEY = "_faas_profiler_context"


@dataclass
class TraceContext:
    profile_id: str = None
    root_id: str = None
    span_id: str = None

    @property
    def is_complete(self) -> bool:
        """
        Returns True if trace context is complete
        """
        return (
            self.profile_id is not None and
            self.root_id is not None and
            self.span_id is not None)
