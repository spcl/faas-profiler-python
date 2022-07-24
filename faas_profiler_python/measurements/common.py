#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for common measurements
"""

from time import time
from typing import Type

from faas_profiler_python.measurements import Measurement
from faas_profiler_python.config import ProfileContext


class WallTime(Measurement):
    """
    Measures the execution time of the function using the Python standard time library.

    The measurement runs in the same process as the function.
    """

    def initialize(
        self,
        profile_context: Type[ProfileContext],
        parameters: dict = {}
    ) -> None:
        self.start_time: float = None
        self.end_time: float = None

    def start(self) -> None:
        self.start_time = time()

    def stop(self) -> None:
        self.end_time = time()

    def results(self) -> dict:
        return {
            "wall_time": self.end_time - self.start_time
        }
