#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for cpu measurements
"""

import psutil

from typing import List, Type
from time import time
from dataclasses import asdict

from faas_profiler_python.measurements import PeriodicMeasurement
from faas_profiler_python.config import ProfileContext, MeasuringPoint, average_measuring_points


class Usage(PeriodicMeasurement):

    def initialize(
        self,
        profile_context: Type[ProfileContext],
        parameters: dict = {}
    ) -> None:
        self.include_children = parameters.get("include_children", True)

        self._own_process_id = profile_context.measurement_process_pid
        self._measuring_points: List[MeasuringPoint] = []
        self._average_usage = 0

        try:
            self.process = psutil.Process(profile_context.pid)
        except psutil.Error as err:
            self.logger.warn(f"Could not set process: {err}")

    def start(self) -> None:
        self._append_new_cpu_measurement()

    def measure(self):
        self._append_new_cpu_measurement()

    def deinitialize(self) -> None:
        self._average_usage = average_measuring_points(self._measuring_points)

        del self.process

    def results(self) -> dict:
        return {
            "measuring_points": list(map(asdict, self._measuring_points)),
            "average_usage": self._average_usage
        }

    def _append_new_cpu_measurement(self):
        current_cpu_percentage = self._get_cpu_percentage()
        if current_cpu_percentage:
            self._measuring_points.append(MeasuringPoint(
                timestamp=time(),
                data=current_cpu_percentage))

    def _get_cpu_percentage(self):
        try:
            percent = self.process.cpu_percent()

            if self.include_children:
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
