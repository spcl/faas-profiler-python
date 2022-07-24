#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base for Measurements.

Defines abstract base class for all measurements and measuring points
"""

from __future__ import annotations
from typing import Type


from faas_profiler_python.config import ProfileContext
from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable


class MeasurementError(RuntimeError):
    pass


class Measurement(BasePlugin, Loggable):
    """
    Base class for all measurements in FaaS Profiler.

    Cannot be initialised.
    """

    def initialize(
        self,
        profile_context: Type[ProfileContext],
        parameters: dict = {}
    ) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def deinitialize(self) -> None:
        pass

    def results(self) -> dict:
        pass


class PeriodicMeasurement(Measurement):
    """
    Base class for measurements that are executed in parallel in another process.
    """

    def measure(self):
        pass
