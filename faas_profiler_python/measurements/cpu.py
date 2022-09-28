#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for cpu measurements
"""

import psutil
import time
import warnings

from faas_profiler_python.measurements import PeriodicMeasurement, Measurement
from faas_profiler_core.models import CPUCoreUsage, CPUUsage


def get_process_cpu_usage(
    process: psutil.Process,
    include_children: bool = False,
    exclude_child_pids: list = []
) -> float:
    """
    Get the CPU usage per process
    """
    percent = process.cpu_percent(interval=None)

    if include_children:
        try:
            for child_process in process.children(recursive=True):
                if child_process.pid not in exclude_child_pids:
                    percent += child_process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return percent


class UsageOverTime(PeriodicMeasurement):
    """
    CPU consumption of the process over time.
    """

    MINIMAL_INTERVAL = 0.1

    def initialize(
        self,
        include_children: bool = False,
        process_pid: int = None,
        function_pid: int = None,
        interval: int = None,
        **kwargs
    ) -> None:
        self._include_children = include_children
        self._own_process_id = process_pid

        if interval < self.MINIMAL_INTERVAL:
            warnings.warn(
                f"Periodic interval {interval} is less than {self.MINIMAL_INTERVAL}. We cannot guarantee correct results")

        self._result = CPUUsage(interval=interval, percentage=[])

        try:
            self.process = psutil.Process(function_pid)
        except psutil.Error as err:
            self.logger.warn(f"Could not set process: {err}")

        # Based on the psutil doc is the first access also zero.
        # We do a first measurement here, to get meaningful results at start()
        self._get_cpu_percentage()

    def start(self) -> None:
        self._result.percentage.append(
            (time.time(), self._get_cpu_percentage()))

    def measure(self):
        self._result.percentage.append(
            (time.time(), self._get_cpu_percentage()))

    def stop(self) -> None:
        self._result.percentage.append(
            (time.time(), self._get_cpu_percentage()))

    def deinitialize(self) -> None:
        del self.process
        del self._result

    def results(self) -> dict:
        return self._result.dump()

    def _get_cpu_percentage(self) -> float:
        try:
            return get_process_cpu_usage(
                self.process,
                self._include_children,
                exclude_child_pids=[
                    self._own_process_id])
        except Exception as err:
            self._logger.error(
                f"Could not get cpu percentage info from {self.process}: {err}")

        return 0.0


class UsageByCoresOverTime(PeriodicMeasurement):
    """
    CPU Usage (system-wide) by cores over time
    """

    MINIMAL_INTERVAL = 0.1

    def initialize(
        self,
        interval: int = None,
        **kwargs
    ) -> None:
        if interval < self.MINIMAL_INTERVAL:
            warnings.warn(
                f"Periodic interval {interval} is less than {self.MINIMAL_INTERVAL}. We cannot guarantee correct results")

        self._result = CPUCoreUsage(
            interval=interval,
            percentage={})

        # Based on the psutil doc is the first access also zero.
        # We do a first measurement here, to get meaningful results at start()
        psutil.cpu_percent(interval=None, percpu=True)

    def start(self) -> None:
        self._add_measurement()

    def measure(self):
        self._add_measurement()

    def stop(self) -> None:
        self._add_measurement()

    def deinitialize(self) -> None:
        del self._result

    def results(self) -> dict:
        return self._result.dump()

    def _add_measurement(self):
        timestamp = time.time()
        for core, percentage in enumerate(
                psutil.cpu_percent(interval=None, percpu=True)):
            core_measurement = self._result.percentage.setdefault(core, [])
            core_measurement.append((timestamp, percentage))


class Usage(Measurement):
    """
    CPU Usage per process.
    """

    def initialize(
        self,
        include_children: bool = False,
        process_pid: int = None,
        function_pid: int = None,
        **kwargs
    ) -> None:
        self._include_children = include_children
        self._own_process_id = process_pid
        self._result = CPUUsage(interval=None, percentage=[])

        try:
            self.process = psutil.Process(function_pid)
        except psutil.Error as err:
            self.logger.warn(f"Could not set process: {err}")

        # Based on the psutil doc is the first access also zero.
        # We do a first measurement here, to get meaningful results at start()
        self._get_cpu_percentage()

    def start(self) -> None:
        self._result.percentage.append(
            (time.time(), self._get_cpu_percentage()))

    def stop(self) -> None:
        self._result.percentage.append(
            (time.time(), self._get_cpu_percentage()))

    def deinitialize(self) -> None:
        del self.process
        del self._result

    def results(self) -> dict:
        return self._result.dump()

    def _get_cpu_percentage(self) -> float:
        try:
            return get_process_cpu_usage(
                self.process,
                self._include_children,
                exclude_child_pids=[
                    self._own_process_id])
        except Exception as err:
            self._logger.error(
                f"Could not get cpu percentage info from {self.process}: {err}")

        return 0.0


class UsageByCores(Measurement):
    """
    CPU Usage (system-wide) per Core
    """

    def initialize(
        self,
        *args,
        **kwargs
    ) -> None:
        self._result = CPUCoreUsage(
            interval=None,
            percentage={})

        # Based on the psutil doc is the first access also zero.
        # We do a first measurement here, to get meaningful results at start()
        psutil.cpu_percent(interval=None, percpu=True)

    def start(self) -> None:
        self._add_measurement()

    def stop(self) -> None:
        self._add_measurement()

    def deinitialize(self) -> None:
        del self._result

    def results(self) -> dict:
        return self._result.dump()

    def _add_measurement(self):
        timestamp = time.time()
        for core, percentage in enumerate(
                psutil.cpu_percent(interval=None, percpu=True)):
            core_measurement = self._result.percentage.setdefault(core, [])
            core_measurement.append((timestamp, percentage))
