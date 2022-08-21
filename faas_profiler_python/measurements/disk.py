#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for network measurements:
- DiskIOCounters
"""
import psutil

from typing import Type

from faas_profiler_python.measurements import Measurement
from faas_profiler_core.models import DiskIOCounters


class IOCounters(Measurement):

    def initialize(
        self,
        function_pid: int = None,
        **kwargs
    ) -> None:
        self._start_io: Type[psutil._common.pio] = None
        self._end_io: Type[psutil._common.pio] = None

        self._io_counter = DiskIOCounters(0, 0, 0, 0)

        try:
            self.process = psutil.Process(function_pid)
        except psutil.AccessDenied as err:
            self._logger.warn(f"Could not set process: {err}")
            self.process = None

    def start(self) -> None:
        if self.process:
            self._start_io = self.process.io_counters()

    def stop(self) -> None:
        if self.process:
            self._end_io = self.process.io_counters()

    def deinitialize(self) -> None:
        del self.process

    def results(self) -> dict:
        if self._start_io and self._end_io:
            self._io_counter.read_count = self._end_io.read_count - self._start_io.read_count
            self._io_counter.write_count = self._end_io.write_count - self._start_io.write_count
            self._io_counter.read_bytes = self._end_io.read_bytes - self._start_io.read_bytes
            self._io_counter.write_bytes = self._end_io.write_bytes - self._start_io.write_bytes

        return self._io_counter.dump()
