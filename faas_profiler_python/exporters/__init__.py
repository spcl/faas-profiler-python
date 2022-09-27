#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for exporting and collecting results.
"""
from __future__ import annotations

import importlib
import ujson
import yaml
import logging

from typing import List

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable
from faas_profiler_python.config import LoadedPlugin

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


AVAILABLE_EXPORTERS = {
    "common::Console": "faas_profiler_python.exporters.common.Console",
    "common::AWSVisualizerUploader": "faas_profiler_python.exporters.common.AWSVisualizerUploader",
    "common::GCPVisualizerUploader": "faas_profiler_python.exporters.common.GCPVisualizerUploader"
}


def load_exporter(name: str, parameters: dict = {}) -> LoadedPlugin:
    """
    Loads a single exporter
    """
    if name not in AVAILABLE_EXPORTERS:
        raise RuntimeError(f"No exporter with name {name} found")

    module_str, klass_str = AVAILABLE_EXPORTERS[name].rsplit(".", 1)

    try:
        module = importlib.import_module(module_str)
        klass = getattr(module, klass_str)
        return LoadedPlugin(name, klass, parameters)
    except (ImportError, AttributeError):
        raise RuntimeError(
            f"No module found {module_str} with exporter class {klass_str}")


def load_all_exporters(exporters: list = []) -> List[LoadedPlugin]:
    """
    Loads all exporters.
    """
    loaded_exporters = []
    for exporter in exporters:
        try:
            loaded_plugin = load_exporter(
                name=exporter.get("name"),
                parameters=exporter.get(
                    "parameters",
                    {}))
            loaded_exporters.append(loaded_plugin)
        except Exception as err:
            logger.error(f"Failed to load exporter plugin: {err}")

    return loaded_exporters


def json_formatter(raw_data: dict) -> str:
    def default(o): return f"<<non-serializable: {type(o).__qualname__}>>"
    return ujson.dumps(
        raw_data,
        ensure_ascii=False,
        indent=0,
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
