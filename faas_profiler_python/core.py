#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for Profiler Core functionality
"""
from __future__ import annotations

import json
import sys
import os
import logging
import traceback

from typing import List, Type
from multiprocessing import Process, connection
from abc import ABC
from uuid import uuid4

from faas_profiler_core.constants import RecordDataType

from faas_profiler_python.config import MeasuringState, LoadedPlugin
from faas_profiler_python.utilis import Loggable


class BasePlugin(ABC):
    """
    Parent class for all plugins in FaaS Profiler.
    Plugins are classes that can be loaded dynamically based on the configuration.
    """

    _logger = logging.getLogger("BasePlugin")
    _logger.setLevel(logging.INFO)


class BatchExecution(Loggable):
    """
    Handels a list of plugins as batch
    """

    def __init__(
        self,
        plugins: List[LoadedPlugin],
        batch_type: RecordDataType = RecordDataType.UNCATEGORIZED
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.plugin_objs = {}

        self.batch_type = batch_type

    @property
    def has_plugins(self) -> bool:
        """
        Returns True if batch has plugins
        """
        return len(self.plugins) > 0

    def initialize(self, *args, **kwargs):
        """
        Initializes all plugins
        """
        for name, plugin_cls, parameters in self.plugins:
            try:
                plugin_obj = plugin_cls()
                plugin_obj.initialize(*args, **kwargs, **parameters)
            except Exception as err:
                self.logger.error(
                    f"Initializing {plugin_cls} failed: {err}. Traceback: {traceback.format_exc()}")
            else:
                self.plugin_objs[name] = plugin_obj

    def start(self, *args, **kwargs):
        """
        Starts all plugins.
        """
        for plugin_obj in self.plugin_objs.values():
            try:
                plugin_obj.start(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Starting {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def measure(self, *args, **kwargs):
        """
        Triggers all measuring methods.
        """
        for plugin_obj in self.plugin_objs.values():
            try:
                plugin_obj.measure(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Measuring {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def stop(self, *args, **kwargs):
        """
        Stops all plugins.
        """
        for plugin_obj in self.plugin_objs.values():
            try:
                plugin_obj.stop(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Measuring {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def export_results(self) -> dict:
        """
        Returns a list of results
        """
        results = {}
        for name, plugin_obj in self.plugin_objs.items():
            try:
                results[name] = {
                    "name": name,
                    "type": self.batch_type.name,
                    "results": plugin_obj.results()
                }
            except Exception as err:
                self.logger.error(
                    f"Exporting results for {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

        return results

    def deinitialize(self, *args, **kwargs):
        """
        deinitialize all plugins.
        """
        for plugin_obj in self.plugin_objs.values():
            try:
                plugin_obj.deinitialize(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Deinitializing {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")


class PeriodicProcess(Process):
    """
    Process to run all measurements that are to be executed in parallel to the main process.
    """

    PIPE_MAX_DATA = 33554432  # Bytes 32MiB = 3 * 2 ** 20 Bytes

    _logger = logging.getLogger("MeasurementProcess")
    _logger.setLevel(logging.INFO)

    def __init__(
        self,
        periodic_measurements: List[LoadedPlugin],
        function_pid: int,
        parent_connection: Type[connection.Connection],
        child_connection: Type[connection.Connection],
        refresh_interval: float = 0.01
    ) -> None:
        self.periodic_measurements = periodic_measurements
        self.periodic_batch = BatchExecution(self.periodic_measurements)

        self.parent_connection = parent_connection
        self.child_connection = child_connection
        self.refresh_interval = refresh_interval

        self.function_pid = function_pid
        self.process_id = os.getpid()

        self.result_storage_path = os.path.join(
            "/", "tmp", f"{uuid4()}_pid_{self.process_id}.json")

        super(PeriodicProcess, self).__init__()

    def run(self):
        """
        Process routine.

        Starts all measurements first and then generates new measurement points interval-based.
        Stops when the main process tells it to do so.
        Then stops all measurements and sends the results to the main process.
        """
        try:
            # Initialize
            self.periodic_batch.initialize(
                process_pid=self.process_id,
                function_pid=self.function_pid,
                interval=self.refresh_interval)

            # Start
            self.periodic_batch.start()
            self.child_connection.send({"state": MeasuringState.STARTED})

            # Measure
            state = MeasuringState.STARTED
            while state == MeasuringState.STARTED:
                self.periodic_batch.measure()

                if self.child_connection.poll(self.refresh_interval):
                    state = self.child_connection.recv().get("state")

            # Stop
            self.periodic_batch.stop()
            self.child_connection.send({"state": MeasuringState.STOPPED})

            # Export
            results = self.periodic_batch.export_results()
            if sys.getsizeof(results) < self.PIPE_MAX_DATA:
                self.child_connection.send({
                    "state": MeasuringState.EXPORT_DATA,
                    "data": results})
            else:
                with open(self.result_storage_path, "w+") as fp:
                    json.dump(results, fp)

                self.child_connection.send({
                    "state": MeasuringState.EXPORT_DATA,
                    "data": self.result_storage_path})

            # Deinitialize
            self.periodic_batch.deinitialize()
        except Exception as error:
            self.child_connection.send({
                "state": MeasuringState.ERROR,
                "data": (error, traceback.format_exc())
            })

    def wait_for_state(self, state: MeasuringState, timeout: int = 10):
        """
        Busy spins for a status of the parent pipe.
        Returns True if the status was reached,
        If an error occurred, the error and stacktrace is output.
        """
        if self.parent_connection.poll(timeout):
            feedback = self.parent_connection.recv()
            if feedback.get("state") == state:
                return True
            elif feedback.get("state") == MeasuringState.ERROR:
                error, tb = feedback.get("data")
                print(tb)
                raise error

        return False
