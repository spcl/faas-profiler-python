#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from collections import namedtuple
from typing import List, Type
from multiprocessing import Process, connection

import os
import importlib
import inspect
import logging
import traceback

from faas_profiler_python.config import MeasuringState, ProcessFeedback, ProfileConfig, ProfileContext
from faas_profiler_python.utilis import Loggable, split_plugin_name


def _load_external_plugin(requested_plugin: Type[ProfileConfig.Entity]):
    pass


def split_plugin_list_by_subclass(plugins, subclass):
    subcls_group = []
    remainder = []
    for plugin in plugins:
        if issubclass(plugin.cls, subclass):
            subcls_group.append(plugin)
        else:
            remainder.append(plugin)

    return (subcls_group, remainder)


LoadedPlugin = namedtuple("LoadedPlugin", "cls parameters")


class BasePlugin:

    _logger = logging.getLogger("BasePlugin")
    _logger.setLevel(logging.INFO)

    @classmethod
    def load(
        cls,
        requested_plugins: List[ProfileConfig.Entity]
    ) -> List[BasePlugin]:
        """

        """
        loaded_plugins = []
        for requested_plugin in requested_plugins:
            # if requested_plugin.external_path:
            #     loaded_plugins.append(_load_external_plugin(requested_plugin))

            _name = requested_plugin.name
            _modules, _klass = split_plugin_name(_name)
            _sub_module_name = ".".join(_modules)
            _full_module_name = f"{cls.__module__}.{_sub_module_name}"
            try:
                imported_module = importlib.import_module(_full_module_name)
            except (ImportError, OSError, ModuleNotFoundError) as err:
                cls._logger.error(
                    f"Could not import {_full_module_name} for plugin {_name}: {err}")
                continue

            if hasattr(imported_module, _klass):
                _plugin = getattr(imported_module, _klass)
                if inspect.isclass(_plugin) and issubclass(_plugin, cls):
                    loaded_plugins.append(LoadedPlugin(
                        _plugin, requested_plugin.parameters))
                    cls._logger.info(
                        f"Loaded plugin for {_name} at {_full_module_name}")
                else:
                    cls._logger.error(
                        f"Requested attribute {_plugin} is not a class or not a subclass of {cls}")
            else:
                cls._logger.error(
                    f"In module {_full_module_name} no attribute with {_klass} was found.")

        return loaded_plugins


class BatchExecution(Loggable):
    """
    Handels a list of plugins as batch
    """

    def __init__(
        self,
        plugins: List[LoadedPlugin]
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.plugin_objs = []

    def initialize(self, *args, **kwargs):
        """
        Initializes all plugins
        """
        for plugin_cls, parameters in self.plugins:
            try:
                plugin_obj = plugin_cls()
                plugin_obj.initialize(*args, **kwargs, parameters=parameters)
            except Exception as err:
                self.logger.error(
                    f"Initializing {plugin_cls} failed: {err}. Traceback: {traceback.format_exc()}")
            else:
                self.plugin_objs.append(plugin_obj)

    def start(self, *args, **kwargs):
        """
        Starts all plugins.
        """
        for plugin_obj in self.plugin_objs:
            try:
                plugin_obj.start(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Starting {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def measure(self, *args, **kwargs):
        """
        Triggers all measuring methods.
        """
        for plugin_obj in self.plugin_objs:
            try:
                plugin_obj.measure(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Measuring {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def stop(self, *args, **kwargs):
        """
        Stops all plugins.
        """
        for plugin_obj in self.plugin_objs:
            try:
                plugin_obj.stop(*args, **kwargs)
            except Exception as err:
                self.logger.error(
                    f"Measuring {plugin_obj} failed: {err}. Traceback: {traceback.format_exc()}")

    def deinitialize(self, *args, **kwargs):
        """
        deinitialize all plugins.
        """
        for plugin_obj in self.plugin_objs:
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
        profile_context: Type[ProfileContext],
        parent_connection: Type[connection.Connection],
        child_connection: Type[connection.Connection],
        refresh_interval: float = 0.1
    ) -> None:
        self.profile_context = profile_context
        self.parent_connection = parent_connection
        self.child_connection = child_connection
        self.refresh_interval = refresh_interval
        self.batch_execution = batch

        super(PeriodicProcess, self).__init__()

    def run(self):
        """
        Process routine.

        Starts all measurements first and then generates new measurement points interval-based.
        Stops when the main process tells it to do so.
        Then stops all measurements and sends the results to the main process.
        """
        try:
            measurement_process_pid = os.getpid()
            self._logger.info(
                f"Measurement process started (pid={measurement_process_pid}).")
            self.profile_context.set_measurement_process_pid(
                measurement_process_pid)

            self.batch_execution.initialize(self.profile_context)
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

            self.batch_execution.deinitialize()
        except Exception as e:
            tb = traceback.format_exc()
            self.child_connection.send(ProcessFeedback(
                state=MeasuringState.ERROR,
                data=(e, tb)
            ))

    def wait_for_state(self, state: MeasuringState, timeout: int = 10):
        if self.parent_connection.poll(timeout):
            feedback = self.parent_connection.recv()
            if feedback.state == state:
                return True
            elif feedback.state == MeasuringState.ERROR:
                error, tb = feedback.data
                print(tb)
                raise error
