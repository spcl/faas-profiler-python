#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for invocation capturing.
"""

from __future__ import annotations

import logging
import importlib

from typing import Type, Any, Tuple

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.patchers import OutboundContext
from faas_profiler_python.utilis import Loggable
from faas_profiler_python.config import LoadedPlugin

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

AVAILABLE_CAPTURES = {
    "aws::S3Access": "faas_profiler_python.captures.aws.S3Access",
    "aws::EFSAccess": "faas_profiler_python.captures.aws.EFSAccess"
}


def load_capture(name: str, parameters: dict = {}) -> LoadedPlugin:
    """
    Loads a single capture
    """
    if name not in AVAILABLE_CAPTURES:
        raise RuntimeError(f"No capture with name {name} found")

    module_str, klass_str = AVAILABLE_CAPTURES[name].rsplit(".", 1)

    try:
        module = importlib.import_module(module_str)
        klass = getattr(module, klass_str)
        return LoadedPlugin(name, klass, parameters)
    except (ImportError, AttributeError):
        raise RuntimeError(
            f"No module found {module_str} with capture class {klass_str}")


def load_all_captures(captures: list = []) -> Tuple[list, list]:
    """
    Loads all captures
    """
    loaded_captures = []
    for capture in captures:
        try:
            loaded_plugin = load_capture(
                name=capture.get("name"),
                parameters=capture.get(
                    "parameters",
                    {}))
            loaded_captures.append(loaded_plugin)
        except Exception as err:
            logger.error(f"Failed to load capture plugin: {err}")

    return loaded_captures


class Capture(BasePlugin, Loggable):
    requested_patch: str = None

    def __new__(cls: type[Capture]) -> Capture:
        if cls.requested_patch is None:
            raise ValueError(
                f"Cannot initialize capture {cls} without requested patch.")

        return BasePlugin.__new__(cls)

    def initialize(self, profiler, *args, **kwargs) -> None:
        self.patcher = profiler.register_patcher(self.requested_patch)
        self.patcher.register_observer(self.capture)

    def start(self) -> None:
        self.patcher.activate()

    def capture(
        self,
        outbound_context: Type[OutboundContext],
    ) -> None:
        pass

    def stop(self) -> None:
        self.patcher.deactivate()

    def deinitialize(self) -> None:
        del self.patcher

    def results(self) -> Any:
        return None
