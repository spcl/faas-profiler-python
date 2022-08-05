#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base for Measurements.

Defines abstract base class for all measurements and measuring points
"""

from __future__ import annotations

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable


class MeasurementError(RuntimeError):
    pass


class Measurement(BasePlugin, Loggable):
    """
    Base class for all measurements in FaaS Profiler.

    Cannot be initialised.
    """

    def initialize(self, *args, **kwargs) -> None:
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
