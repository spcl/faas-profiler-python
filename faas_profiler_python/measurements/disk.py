#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for network measurements:
- DiskIOCounters
"""

from typing import Type
import psutil

from faas_profiler_python.config import ProfileContext
from faas_profiler_python.measurements.base import Measurement, register_with_name


@register_with_name("Disk::IOCounters")
class IOCounters(Measurement):

    def setUp(
        self,
        profiler_context: Type[ProfileContext],
        config: dict = {}
    ) -> None:
        self.start_snapshot: Type[psutil._common.pio] = None
        self.end_snapshot: Type[psutil._common.pio] = None

        self._io_delta = {}

        try:
            self.process = psutil.Process(profiler_context.pid)
        except psutil.AccessDenied:
            self.process = None

    def start(self) -> None:
        if self.process:
            self.start_snapshot = self.process.io_counters()

    def stop(self) -> None:
        if self.process:
            self.end_snapshot = self.process.io_counters()

    def tearDown(self) -> None:
        if self.start_snapshot and self.end_snapshot:
            self._io_delta = {
                "read_count": self.end_snapshot.read_count -
                self.start_snapshot.read_count,
                "write_count": self.end_snapshot.write_count -
                self.start_snapshot.write_count,
                "read_bytes": self.end_snapshot.read_bytes -
                self.start_snapshot.read_bytes,
                "write_bytes": self.end_snapshot.write_bytes -
                self.start_snapshot.write_bytes,
            }

        del self.process

    def results(self) -> dict:
        return self._io_delta
