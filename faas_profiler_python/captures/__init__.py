#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for invocation capturing.
"""

from __future__ import annotations

import inspect

from typing import Type, Any

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.patchers import FunctionPatcher, OutboundContext, request_patcher
from faas_profiler_python.utilis import Loggable


class Capture(BasePlugin, Loggable):
    requested_patch: FunctionPatcher = None

    def __new__(cls: type[Capture]) -> Capture:
        if cls.requested_patch is None:
            raise ValueError(
                f"Cannot initialize capture {cls} without requested patch.")

        if not inspect.isclass(
                cls.requested_patch) or not issubclass(
                cls.requested_patch,
                FunctionPatcher):
            raise ValueError(
                f"'requested_patch' needs to be class and a subclass of FunctionPatcher, got {cls.requested_patch}")

        return BasePlugin.__new__(cls)

    def initialize(self, *args, **kwargs) -> None:
        self.patcher = request_patcher(self.requested_patch)
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
