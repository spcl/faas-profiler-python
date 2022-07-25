#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for invocation capturing.
"""

from __future__ import annotations

import inspect

from typing import Type

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.patchers import FunctionPatcher, InvocationContext, request_patcher
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

    def initialize(self, parameters: dict = {}) -> None:
        self.patcher = request_patcher(self.requested_patch)
        self.patcher.register_capture(self)

    def start(self) -> None:
        self.patcher.activate()

    def capture(
        self,
        invocation_context: Type[InvocationContext],
    ) -> None:
        pass

    def stop(self) -> None:
        self.patcher.deactivate()

    def deinitialize(self) -> None:
        del self.patcher

    def results(self) -> list:
        return []
