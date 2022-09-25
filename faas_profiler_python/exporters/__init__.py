#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for exporting and collecting results.
"""
from __future__ import annotations

import json
import yaml

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable


def json_formatter(raw_data: dict) -> str:
    def default(o): return f"<<non-serializable: {type(o).__qualname__}>>"
    return json.dumps(
        raw_data,
        ensure_ascii=False,
        indent=None,
        default=default
    ).encode('utf-8')


def yaml_formatter(raw_data: dict) -> str:
    return yaml.dump(
        raw_data,
        sort_keys=False,
        default_flow_style=False
    ).encode('utf-8')


class Exporter(BasePlugin, Loggable):
    """
    Base class for all exporters in FaaS Profiler.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__()

    def export(self, trace_record: dict) -> None:
        pass
