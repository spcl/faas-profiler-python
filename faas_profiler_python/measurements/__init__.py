#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base for Measurements.

Defines abstract base class for all measurements and measuring points
"""

from __future__ import annotations

import importlib
import logging

from typing import Tuple

from faas_profiler_python.core import BasePlugin
from faas_profiler_python.utilis import Loggable
from faas_profiler_python.config import LoadedPlugin

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

AVAILABLE_MEASUREMENTS = {
    "cpu::Usage": "faas_profiler_python.measurements.cpu.Usage",
    "disk::IOCounters": "faas_profiler_python.measurements.disk.IOCounters",
    "information::Environment": "faas_profiler_python.measurements.information.Environment",
    "information::OperatingSystem": "faas_profiler_python.measurements.information.OperatingSystem",
    "information::TimeShift": "faas_profiler_python.measurements.information.TimeShift",
    "information::IsWarm": "faas_profiler_python.measurements.information.IsWarm",
    "memory::Usage": "faas_profiler_python.measurements.memory.Usage",
    "memory::LineUsage": "faas_profiler_python.measurements.memory.LineUsage",
    "network::Connections": "faas_profiler_python.measurements.network.Connections",
    "network::IOCounters": "faas_profiler_python.measurements.network.IOCounters",
}


def load_measurement(name: str, parameters: dict = {}) -> LoadedPlugin:
    """
    Loads a single measurement
    """
    if name not in AVAILABLE_MEASUREMENTS:
        raise RuntimeError(f"No measurement with name {name} found")

    module_str, klass_str = AVAILABLE_MEASUREMENTS[name].rsplit(".", 1)

    try:
        module = importlib.import_module(module_str)
        klass = getattr(module, klass_str)
        return LoadedPlugin(name, klass, parameters)
    except (ImportError, AttributeError):
        raise RuntimeError(
            f"No module found {module_str} with measurement class {klass_str}")


def load_all_measurements(measurements: list = []) -> Tuple[list, list]:
    """
    Loads all measurements grouped by periodic and default measurements
    """
    default_measurements, periodic_measurements = [], []
    for measurement in measurements:
        try:
            loaded_plugin = load_measurement(name=measurement.get(
                "name"), parameters=measurement.get("parameters", {}))
            if issubclass(loaded_plugin.cls, PeriodicMeasurement):
                periodic_measurements.append(loaded_plugin)
            else:
                default_measurements.append(loaded_plugin)
        except Exception as err:
            logger.error(f"Failed to load measurement plugin: {err}")

    return default_measurements, periodic_measurements


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
