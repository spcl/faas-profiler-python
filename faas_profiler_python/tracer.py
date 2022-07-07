#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Distributed tracer module.
"""

from dataclasses import dataclass


@dataclass
class TraceContext:
    trace_id: int
    parent_id: int
    current_id: int

    @property
    def is_complete(self) -> bool:
        return True
