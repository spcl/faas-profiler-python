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


class LineUsage(Measurement):

    def initialize(
        self,
        function,
        include_children: bool = False,
        **kwargs
    ) -> None:
        self.include_children = include_children
        self.code_map = CodeMap(
            include_children=self.include_children, backend="psutil")

        self._original_trace_function = None
        self.prevlines = []
        self.prev_lineno = None
        self.function = function

    def start(self) -> None:
        self.code_map.add(self.function.__code__)

        self._original_trace_function = sys.gettrace()
        sys.settrace(self._trace_memory_usage)

    def stop(self) -> None:
        sys.settrace(self._original_trace_function)

    def _trace_memory_usage(self, frame, event, arg):
        if frame.f_code in self.code_map:
            if event == 'call':
                self.prevlines.append(frame.f_lineno)
            elif event == 'line':
                self.code_map.trace(
                    frame.f_code, self.prevlines[-1], self.prev_lineno)
                self.prev_lineno = self.prevlines[-1]
                self.prevlines[-1] = frame.f_lineno
            elif event == 'return':
                lineno = self.prevlines.pop()
                self.code_map.trace(frame.f_code, lineno, self.prev_lineno)
                self.prev_lineno = lineno

        if self._original_trace_function is not None:
            self._original_trace_function(frame, event, arg)

        return self._trace_memory_usage

    def results(self) -> dict:
        line_memory = {}
        for (filename, lines) in self.code_map.items():
            all_lines = linecache.getlines(filename)
            for (line_number, memory) in lines:
                if not memory:
                    continue

                line_memory[line_number] = {
                    "line_content": all_lines[line_number - 1],
                    "occurrences": memory[2],
                    "increment": memory[0],
                    "total_memory": memory[1]
                }

        return {
            "line_memory": line_memory
        }


class Usage(PeriodicMeasurement):

    def initialize(
        self,
        function_pid: int = None,
        process_pid: int = None,
        include_children: bool = False,
        **kwargs
    ) -> None:
        self.include_children = include_children

        self._own_process_id = process_pid
        self._function_pid = function_pid

        self._measuring_points = []

        try:
            self.process = psutil.Process(self._function_pid)
        except psutil.Error as err:
            self._logger.warn(f"Could not set process: {err}")

    def start(self) -> None:
        self._measuring_points.append(self._get_memory())

    def measure(self):
        self._measuring_points.append(self._get_memory())

    def stop(self) -> None:
        self._measuring_points.append(self._get_memory())

    def deinitialize(self) -> None:
        del self.process

    def results(self) -> dict:
        return {
            "measuring_points": self._measuring_points
        }

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
