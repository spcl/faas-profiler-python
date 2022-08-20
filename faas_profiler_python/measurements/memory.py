#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for memory measurements:
- LineUsage
- Usage
"""

import psutil
import sys
import linecache

from memory_profiler import CodeMap

from faas_profiler_python.measurements import PeriodicMeasurement, Measurement
from faas_profiler_core.models import (
    MemoryLineUsage,
    MemoryLineUsageItem,
    MemoryUsage
)


class LineUsage(Measurement):

    def initialize(
        self,
        function,
        include_children: bool = False,
        **kwargs
    ) -> None:
        self.include_children = include_children
        self._function = function

        self._code_map = CodeMap(
            include_children=self.include_children, backend="psutil")
        self._original_trace_function = None
        self._prevlines = []
        self._prev_lineno = None

        self._result = MemoryLineUsage(
            line_memories=[])

    def start(self) -> None:
        self._code_map.add(self._function.__code__)

        self._original_trace_function = sys.gettrace()
        sys.settrace(self._trace_memory_usage)

    def stop(self) -> None:
        sys.settrace(self._original_trace_function)

    def _trace_memory_usage(self, frame, event, arg):
        if frame.f_code in self._code_map:
            if event == 'call':
                self._prevlines.append(frame.f_lineno)
            elif event == 'line':
                self._code_map.trace(
                    frame.f_code, self._prevlines[-1], self._prev_lineno)
                self._prev_lineno = self._prevlines[-1]
                self._prevlines[-1] = frame.f_lineno
            elif event == 'return':
                lineno = self._prevlines.pop()
                self._code_map.trace(frame.f_code, lineno, self._prev_lineno)
                self._prev_lineno = lineno

        if self._original_trace_function is not None:
            self._original_trace_function(frame, event, arg)

        return self._trace_memory_usage

    def results(self) -> dict:
        for (filename, lines) in self._code_map.items():
            all_lines = linecache.getlines(filename)
            for (line_number, memory) in lines:
                if not memory:
                    continue

                content = all_lines[line_number - 1]
                self._result.line_memories.append(
                    MemoryLineUsageItem(
                        line_number=line_number,
                        content=content,
                        memory_increment=memory[0],
                        memory_total=memory[1],
                        occurrences=memory[2]))

        return self._result.dump()


class Usage(PeriodicMeasurement):

    def initialize(
        self,
        function_pid: int = None,
        process_pid: int = None,
        include_children: bool = False,
        interval: float = None,
        **kwargs
    ) -> None:
        self.include_children = include_children

        self._own_process_id = process_pid
        self._function_pid = function_pid

        self._result = MemoryUsage(
            interval=interval, measuring_points=[])

        try:
            self.process = psutil.Process(self._function_pid)
        except psutil.Error as err:
            self._logger.warn(f"Could not set process: {err}")

    def start(self) -> None:
        self._result.measuring_points.append(self._get_memory())

    def measure(self):
        self._result.measuring_points.append(self._get_memory())

    def stop(self) -> None:
        self._result.measuring_points.append(self._get_memory())

    def deinitialize(self) -> None:
        del self.process

    def results(self) -> dict:
        return self._result.dump()

    def _get_memory(self):
        try:
            memory_info = self.process.memory_info()
            memory = memory_info.rss

            if self.include_children:
                try:
                    for child_process in self.process.children(recursive=True):
                        if self._own_process_id is None or child_process.pid != self._own_process_id:
                            child_memory_info = child_process.memory_info()
                            memory += child_memory_info.rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return memory
        except psutil.AccessDenied as e:
            self._logger.error(
                f"Could not get process memory info from {self.process}: {e}")

        return None
