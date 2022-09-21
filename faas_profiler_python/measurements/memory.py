#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for memory measurements:
- LineUsage
- Usage
"""

from typing import List
import psutil
import sys
import os
import linecache
import inspect

from faas_profiler_python.measurements import PeriodicMeasurement, Measurement
from faas_profiler_core.models import (
    MemoryLineUsage,
    MemoryLineUsageItem,
    MemoryUsage
)
from faas_profiler_python.utilis import Loggable


def get_memory(
    process: psutil.Process,
    include_children: bool = False,
    exclude_child_pids: list = []
) -> float:
    """
    Get memory RSS of process
    """
    memory_info = process.memory_info()
    memory = memory_info.rss

    if include_children:
        try:
            for child_process in process.children(recursive=True):
                if child_process.pid not in exclude_child_pids:
                    child_memory_info = child_process.memory_info()
                    memory += child_memory_info.rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return memory


class CodeMap(Loggable):

    def __init__(
        self,
        process: psutil.Process,
        include_children: bool = False,
        exclude_pid: int = None
    ) -> None:
        self._process = process
        self._include_children = include_children
        self._exclude_pid = exclude_pid

        self._toplevel = []
        self._codes = {}

        super().__init__()

    def code_exists(self, code) -> bool:
        """
        Returns True if code exists in mapping
        """
        return code in self._codes

    def add_code(self, code, parent=None) -> None:
        """
        Adds a new code block to the memory mapping
        """
        if self.code_exists(code):
            return

        if parent:
            self._codes[code] = self._codes[parent]
        else:
            filename = code.co_filename
            if filename.endswith((".pyc", ".pyo")):
                filename = filename[:-1]

            if not os.path.exists(filename):
                self.logger.error(f"[CODEMAP]: Could not find file {filename}")
                return

            (lines, start_number) = inspect.getsourcelines(code)
            all_line_numbers = range(start_number, start_number + len(lines))
            self._toplevel.append((filename, code, all_line_numbers))
            self._codes[code] = {}

        for subcode in filter(inspect.iscode, code.co_consts):
            self.add_code(subcode, parent=parent)

    def trace_memory(self, code, lineno, prev_lineno):
        """
        Trace memory for code and line number.
        """
        try:
            memory = get_memory(
                self._process,
                include_children=self._include_children,
                exclude_child_pids=[self._exclude_pid])
        except Exception as e:
            self.logger.error(
                f"Could not get process memory info from {self._process}: {e}")
            return

        prev_value = self._codes[code].get(lineno, None)
        previous_memory = prev_value[1] if prev_value else 0
        previous_inc = prev_value[0] if prev_value else 0

        prev_line_value = self._codes[code].get(
            prev_lineno, None) if prev_lineno else None
        prev_line_memory = prev_line_value[1] if prev_line_value else 0
        occ_count = self._codes[code][lineno][2] + \
            1 if lineno in self._codes[code] else 1
        self._codes[code][lineno] = (
            previous_inc + (memory - prev_line_memory),
            max(memory, previous_memory),
            occ_count,
        )

    def to_line_items(self) -> List[MemoryLineUsageItem]:
        """
        Returns the map as line items
        """
        items = []
        for (filename, code, linenos) in self._toplevel:
            results = self._codes[code]
            if not results:
                continue

            all_lines = linecache.getlines(filename)
            for line_number in linenos:
                line_mem = results.get(line_number)
                if not line_mem:
                    continue

                content = all_lines[line_number - 1]
                items.append(
                    MemoryLineUsageItem(
                        line_number=line_number,
                        content=content,
                        memory_increment=line_mem[0],
                        memory_total=line_mem[1],
                        occurrences=line_mem[2]))

        return items


class LineUsage(Measurement):

    def initialize(
        self,
        function,
        function_pid: int = None,
        process_pid: int = None,
        include_children: bool = False,
        **kwargs
    ) -> None:
        try:
            self.process = psutil.Process(function_pid)
        except psutil.Error as err:
            self._logger.warn(f"Could not set process: {err}")

        self._org_trace_function = None
        self._code_map = CodeMap(
            process=self.process,
            include_children=include_children,
            exclude_pid=process_pid)
        self._code_map.add_code(function.__code__)

        self._prevlines = []
        self._prev_lineno = None

    def start(self) -> None:
        self._org_trace_function = sys.gettrace()
        sys.settrace(self._trace_memory_usage)

    def stop(self) -> None:
        sys.settrace(self._org_trace_function)

    def _trace_memory_usage(self, frame, event, arg):
        if self._code_map.code_exists(frame.f_code):
            if event == 'call':
                self._prevlines.append(frame.f_lineno)
            elif event == 'line':
                self._code_map.trace_memory(
                    frame.f_code, self._prevlines[-1], self._prev_lineno)
                self._prev_lineno = self._prevlines[-1]
                self._prevlines[-1] = frame.f_lineno
            elif event == 'return':
                lineno = self._prevlines.pop()
                self._code_map.trace_memory(
                    frame.f_code, lineno, self._prev_lineno)
                self._prev_lineno = lineno

        if self._org_trace_function is not None:
            self._org_trace_function(frame, event, arg)

        return self._trace_memory_usage

    def results(self) -> dict:
        return MemoryLineUsage(
            line_memories=self._code_map.to_line_items()
        ).dump()


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

        self._baseline: int = 0

        self._own_process_id = process_pid
        self._function_pid = function_pid

        self._result = MemoryUsage(
            interval=interval, measuring_points=[])

        try:
            self.process = psutil.Process(self._function_pid)
        except psutil.Error as err:
            self._logger.warn(f"Could not set process: {err}")

    def start(self) -> None:
        self._baseline = self._get_memory()
        self._result.measuring_points.append(self._get_memory(
            substract_baseline=self._baseline))

    def measure(self):
        self._result.measuring_points.append(self._get_memory(
            substract_baseline=self._baseline))

    def stop(self) -> None:
        self._result.measuring_points.append(self._get_memory(
            substract_baseline=self._baseline))

    def deinitialize(self) -> None:
        del self.process

    def results(self) -> dict:
        return self._result.dump()

    def _get_memory(self, substract_baseline: int = 0) -> int:
        """
        Returns memory in bytes for given process (and children if required)
        """
        try:
            memory = get_memory(
                self.process,
                include_children=self.include_children,
                exclude_child_pids=[
                    self._own_process_id])

            return memory - substract_baseline
        except Exception as e:
            self._logger.error(
                f"Could not get process memory info from {self.process}: {e}")

        return 0
