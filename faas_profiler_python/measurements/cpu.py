#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for cpu measurements
"""

import psutil
import time

from faas_profiler_python.measurements import PeriodicMeasurement
from faas_profiler_core.models import CPUUsage


class Usage(PeriodicMeasurement):
    """
    CPU consumption of the process over time.
    """

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

        self._result = CPUUsage(
            interval=interval, measuring_points=[])

        try:
            self.process = psutil.Process(function_pid)
        except psutil.Error as err:
            self.logger.warn(f"Could not set process: {err}")

    def start(self) -> None:
        self._result.measuring_points.append(
            (time.time(), self._get_cpu_percentage()))

    def measure(self):
        self._result.measuring_points.append(
            (time.time(), self._get_cpu_percentage()))

    def stop(self) -> None:
        self._result.measuring_points.append(
            (time.time(), self._get_cpu_percentage()))

    def deinitialize(self) -> None:
        del self.process
        del self._result

    def results(self) -> dict:
        return self._result.dump()

    def _get_cpu_percentage(self):
        try:
            percent = self.process.cpu_percent()

            if self._include_children:
                try:
                    for child_process in self.process.children(recursive=True):
                        if self._own_process_id is None or child_process.pid != self._own_process_id:
                            percent += child_process.cpu_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return percent
        except psutil.AccessDenied as e:
            self._logger.error(
                f"Could not get cpu percentage info from {self.process}: {e}")

        return None
