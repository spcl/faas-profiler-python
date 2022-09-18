#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for Profiler Core functionality
"""
from __future__ import annotations

import json
import sys
import os
import importlib
import importlib.util
import inspect
import logging
import traceback

from typing import List, Type
from multiprocessing import Process, connection
from abc import ABC

from faas_profiler_core.constants import RecordDataType

from faas_profiler_python.config import (
    MeasuringState,
    ProcessFeedback,
    LoadedPlugin,
    UnresolvedPlugin
)
from faas_profiler_python.utilis import Loggable, split_plugin_name


def split_plugin_list_by_subclass(plugins: list, subclass: Type) -> tuple:
    """
    Splits a list of classes into two groups based on a parent class.
    """
    subcls_group = []
    remainder = []
    for plugin in plugins:
        if issubclass(plugin.cls, subclass):
            subcls_group.append(plugin)
        else:
            remainder.append(plugin)

    return (subcls_group, remainder)


class BasePlugin(ABC):
    """
    Parent class for all plugins in FaaS Profiler.
    Plugins are classes that can be loaded dynamically based on the configuration.
    """

    _logger = logging.getLogger("BasePlugin")
    _logger.setLevel(logging.INFO)

    @classmethod
    def load(
        cls,
        requested_plugins: List[UnresolvedPlugin]
    ) -> List[BasePlugin]:
        """
        Loads a list of unresolved plugins found in the configuration.
        """
        loaded_plugins = []
        for requested_plugin in requested_plugins:
            _name = requested_plugin.name
            _modules, _klass = split_plugin_name(_name)
            _sub_module_name = ".".join(_modules)

            try:
                if requested_plugin.external_path:
                    _full_module_spec = requested_plugin.external_path
                    spec = importlib.util.spec_from_file_location(
                        _sub_module_name, requested_plugin.external_path)
                    imported_module = importlib.util.module_from_spec(spec)
                    sys.modules[_sub_module_name] = imported_module
                    spec.loader.exec_module(imported_module)
                else:
                    _full_module_spec = f"{cls.__module__}.{_sub_module_name}"
                    imported_module = importlib.import_module(
                        _full_module_spec)
            except (ImportError, OSError, ModuleNotFoundError) as err:
                cls._logger.error(
                    f"Could not import {_full_module_spec} for plugin {_name}: {err}")
                continue

            if hasattr(imported_module, _klass):
                _plugin = getattr(imported_module, _klass)
                if inspect.isclass(_plugin) and issubclass(_plugin, cls):
                    loaded_plugins.append(LoadedPlugin(
                        _name, _plugin, requested_plugin.parameters))
                    cls._logger.info(
                        f"Loaded plugin for {_name} at {_full_module_spec}")
                else:
                    cls._logger.error(
                        f"Requested attribute {_plugin} is not a class or not a subclass of {cls}")
            else:
                cls._logger.error(
                    f"In module {_full_module_spec} no attribute with {_klass} was found.")

        return loaded_plugins


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

    def export_results(self) -> list:
        """
        Returns a list of results
        """
        results = []
        for name, plugin_obj in self.plugin_objs.items():
            try:
                results.append({
                    "name": name,
                    "type": self.batch_type.name,
                    "results": plugin_obj.results()
                })
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

    _logger = logging.getLogger("MeasurementProcess")
    _logger.setLevel(logging.INFO)

    def __init__(
        self,
        batch: Type[BatchExecution],
        function_pid: int,
        result_storage_path: str,
        parent_connection: Type[connection.Connection],
        child_connection: Type[connection.Connection],
        refresh_interval: float = 0.01
    ) -> None:
        self.parent_connection = parent_connection
        self.child_connection = child_connection
        self.refresh_interval = refresh_interval
        self.batch_execution = batch
        self.function_pid = function_pid
        self.result_storage_path = result_storage_path

        super(PeriodicProcess, self).__init__()

    def run(self):
        """
        Process routine.

        Starts all measurements first and then generates new measurement points interval-based.
        Stops when the main process tells it to do so.
        Then stops all measurements and sends the results to the main process.
        """
        try:
            process_pid = os.getpid()
            self._logger.info(
                f"Measurement process started (pid={process_pid}).")

            self.batch_execution.initialize(
                process_pid=process_pid,
                function_pid=self.function_pid,
                interval=self.refresh_interval)
            self.batch_execution.start()
            self.child_connection.send(ProcessFeedback(MeasuringState.STARTED))

            self._logger.info("Measurement process started measuring.")

            state = MeasuringState.STARTED
            while state == MeasuringState.STARTED:
                self.batch_execution.measure()

                if self.child_connection.poll(self.refresh_interval):
                    state = self.child_connection.recv()

            self._logger.info("Measurement process stopped measuring.")

            self.batch_execution.stop()
            self.child_connection.send(ProcessFeedback(MeasuringState.STOPPED))

            results = self.batch_execution.export_results()
            with open(self.result_storage_path, "w+") as fp:
                json.dump(results, fp)

            self.batch_execution.deinitialize()
        except Exception as e:
            tb = traceback.format_exc()
            self.child_connection.send(ProcessFeedback(
                state=MeasuringState.ERROR,
                data=(e, tb)
            ))

    def wait_for_state(self, state: MeasuringState, timeout: int = 10):
        """
        Busy spins for a status of the parent pipe.
        Returns True if the status was reached,
        If an error occurred, the error and stacktrace is output.
        """
        if self.parent_connection.poll(timeout):
            feedback = self.parent_connection.recv()
            if feedback.state == state:
                return True
            elif feedback.state == MeasuringState.ERROR:
                error, tb = feedback.data
                print(tb)
                raise error

        return False
