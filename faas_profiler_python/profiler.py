#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Entry point for all measurements and profiling.
The Profiles class handles all measurements and tracing.
"""

import json
import os

from datetime import datetime
from typing import List, Type, Callable, Any
from multiprocessing import Pipe, connection
from functools import wraps

from faas_profiler_python.config import load_configuration, MeasuringState, Function
from faas_profiler_python.function import resolve_function_context
from faas_profiler_python.measurements import load_all_measurements
from faas_profiler_python.payload import Payload
from faas_profiler_python.tracer import DistributedTracer
from faas_profiler_python.captures import load_all_captures
from faas_profiler_python.exporters import load_all_exporters
from faas_profiler_python.utilis import Loggable, invoke_instrumented_function
from faas_profiler_python.core import (
    BatchExecution,
    PeriodicProcess,
    RecordDataType
)
from faas_profiler_python.patchers import FunctionPatcher, request_patcher


def profile(config_file: str = None):
    """
    FaaS Profiler decorator.
    Use this decorator to profile a serverless function.

    Parameters
    ----------
    config : str
        Path to configuration file.
    """

    def function_profiler(func):
        @wraps(func)
        def profiler_wrapper(*args, **kwargs):
            profiler = Profiler(config_file=config_file)

            function_return = profiler(func, *args, **kwargs)

            return function_return
        return profiler_wrapper
    return function_profiler


class Profiler(Loggable):
    """
    Profiler entrypoint.
    """

    def __init__(self, config_file: str = None) -> None:
        super().__init__()
        # Resolve serverless function
        self.function_context = resolve_function_context()

        # Load user configuration
        self.config = load_configuration(config_file)

        self.default_measurements, self.periodic_measurements = load_all_measurements(
            self.config.measurements)
        self.exporters = load_all_exporters(self.config.exporters)
        self.captures = load_all_captures(self.config.captures)

        self.default_batch = BatchExecution(
            self.default_measurements,
            batch_type=RecordDataType.SIMPLE_MEASUREMENT)
        self.capture_batch = BatchExecution(
            self.captures,
            batch_type=RecordDataType.CAPTURE)

        # Distributed Tracer
        self.tracer = DistributedTracer(
            self, self.config, self.function_context.provider)

        self._active_function_patchers: List[FunctionPatcher] = {}

        self._default_measurements_started: bool = False
        self._periodic_measurements_started: bool = False
        self._captures_started: bool = False

        # Measurement process for peridic measurements
        self.child_endpoint: Type[connection.Connection] = None
        self.parent_endpoint: Type[connection.Connection] = None
        self.periodic_process: Type[PeriodicProcess] = None

        self.function_pid = os.getpid()
        self.function: Type[Function] = None
        self.payload: Type[Payload] = None

        self.logger.info((
            "[PROFILER PLAN]: \n"
            f"- Simple Measurements: {self.default_measurements} \n"
            f"- Periodic Measurements: {self.periodic_measurements} \n"
            f"- Captures: {self.captures} \n"
            f"- Exporters: {self.exporters}"
        ))

    def __call__(self, func: Callable, *args, **kwargs) -> Any:
        """
        Instrumentation wrapper to profile the given method.
        Profiles the given method and exports the results.
        """
        self.function = Function(func, args, kwargs)
        self.payload = Payload.resolve(
            function=self.function,
            provider=self.function_context.provider)

        if self.config.include_payload:
            self.function_context.arguments = self.payload.to_exportable()

        if self.config.include_environment_variables:
            self.function_context.environment_variables = dict(os.environ)

        self.start()

        self.logger.info(f"-- EXECUTING FUNCTION: {func.__name__} --")
        response, error, traceback_list, executed_at, finished_at = invoke_instrumented_function(
            func, args, kwargs, with_traceback=self.config.include_traceback)
        self.logger.info("-- FUNCTION EXCUTED --")

        self.function_context.handler_executed_at = executed_at
        self.function_context.handler_finished_at = finished_at

        if error:
            self.function_context.has_error = True
            self.function_context.error_type = error.__class__.__name__
            self.function_context.error_message = str(error)
            self.function_context.response = None
            self.function_context.traceback = traceback_list
        else:
            self.function_context.has_error = False
            self.function_context.error_type = None
            self.function_context.error_message = None
            self.function_context.traceback = []

            if self.config.include_response:
                self.function_context.response = response

        self.stop()
        self.export()

        self._deinitialize_default_measurements()
        if self.periodic_process:
            self.periodic_process.join()
            self._terminate_peridoic_process()

        return_value = self.tracer.handle_function_response(response)

        if error:
            raise error
        else:
            return return_value

    def start(self) -> None:
        """
        Starts the profiling.
        """
        self.logger.info("[PROFILER] Profiler run started.")

        self.tracer.handle_inbound_request(self.payload)
        self.tracer.start_tracing_outbound_requests()

        self._start_capturing()
        self._start_default_measurements()
        self._start_periodic_measurements()

    def stop(self) -> None:
        """
        Stops the profiling.
        """
        self.logger.info("Profile run stopped.")
        self._stop_periodic_measurements()
        self._stop_default_measurements()
        self._stop_capturing()

        self.tracer.stop_tracing_outbound_requests()

    def export(self):
        """
        Exports the profiling data.
        """
        if not self.exporters:
            self.logger.warn(
                "[EXPORT]: No exporters defined. Will discard results.")
            return

        self.logger.info("[EXPORT]: Collecting results.")

        record_data = {
            **self.default_batch.export_results(),
            **self.capture_batch.export_results(),
            **self._export_periodic_measurements()}

        self.function_context.finished_at = datetime.now()

        trace_record = {
            **self.tracer.dump_contexts(),
            "function_context": self.function_context.dump(),
            "data": record_data}

        for exporter_plugin in self.exporters:
            try:
                exporter = exporter_plugin.cls(
                    **exporter_plugin.parameters)

                exporter.export(trace_record)
            except Exception as err:
                self.logger.error(
                    f"Exporting with {exporter_plugin.cls} failed: {err}")

    def register_patcher(self, patcher_string) -> Type[FunctionPatcher]:
        """
        Registers a new patcher.
        Returns a cached one if exists.
        """
        if patcher_string in self._active_function_patchers:
            return self._active_function_patchers[patcher_string]

        patcher_cls = request_patcher(patcher_string)
        patcher_obj = patcher_cls()
        self._active_function_patchers[patcher_string] = patcher_obj

        return patcher_obj

    def _start_default_measurements(self):
        """
        Starts all default measurements
        """
        if not self.default_batch or self.default_batch.has_plugins:
            return

        self.logger.info(
            "[DEFAULT MEASUREMENTS]: Initializing and starting.")

        self.default_batch.initialize(
            function_pid=self.function_pid, function=self.function.function)
        self.default_batch.start()
        self._default_measurements_started = True

    def _start_periodic_measurements(self):
        """
        Starts all periodic measurements by creating a process with the batch execution
        """
        if len(self.periodic_measurements) == 0:
            return

        self.child_endpoint, self.parent_endpoint = Pipe()
        self.periodic_process = PeriodicProcess(
            periodic_measurements=self.periodic_measurements,
            function_pid=self.function_pid,
            child_connection=self.child_endpoint,
            parent_connection=self.parent_endpoint,
            refresh_interval=self.config.measurement_interval)

        self.logger.info(
            f"[PERIODIC MEASUREMENT]: Starting process: {self.periodic_process}")
        self.periodic_process.start()

        try:
            self.periodic_process.wait_for_state(MeasuringState.STARTED)
            self._periodic_measurements_started = True

            self.logger.info(
                "[PERIODIC MEASUREMENT]: All set up and started.")
        except Exception as err:
            self._terminate_peridoic_process()
            self._periodic_measurements_started = False

            self.logger.error(
                f"[PERIODIC MEASUREMENT]: Initializing/Setting up failed: {err}")

    def _stop_default_measurements(self):
        """
        Stops all default measurements
        """
        if not self.default_batch or self.default_batch.has_plugins:
            return

        if not self._default_measurements_started:
            self.logger.warn(
                "[DEFAULT MEASUREMENTS]: Attempts to stop measurements before they are successfully started. Skipping.")
            return

        self.logger.info(
            "[DEFAULT MEASUREMENTS]: Stopping default measurements")

        self.default_batch.stop()

    def _deinitialize_default_measurements(self):
        """
        Deinitialize all default measurements.
        """
        if not self.default_batch or self.default_batch.has_plugins:
            return

        self.logger.info(
            "[DEFAULT MEASUREMENTS]: Deinitializing default measurements")

        self.default_batch.deinitialize()

    def _stop_periodic_measurements(self):
        """
        Stops all periodic measurements.
        """
        if not self.periodic_process:
            return

        if not self._periodic_measurements_started:
            self.logger.warn(
                "[PERIODIC MEASUREMENTS]: Attempts to stop measurements before they are successfully started. Skipping.")
            return

        # Send child process request to stop
        self.parent_endpoint.send({"state": MeasuringState.STOPPED})

        try:
            self.periodic_process.wait_for_state(MeasuringState.STOPPED)
            self.logger.info(
                "[PERIODIC MEASUREMENT]: All stopped and terminated")
        except Exception as err:
            self.logger.error(
                f"[DEFAULT MEASUREMENTS]: Stopping and shutting down failed: {err}")

    def _export_periodic_measurements(self) -> dict:
        """
        Exports the data from periodic measurements
        """
        if not self.parent_endpoint:
            return {}

        if not self.parent_endpoint.poll(5):
            return {}

        child_state = self.parent_endpoint.recv()
        if child_state.get("state") == MeasuringState.EXPORT_DATA:
            return child_state.get("data", {})
        elif child_state.get("state") == MeasuringState.EXPORT_FILE:
            data_file = child_state.get("data")
            try:
                with open(data_file, "r") as fp:
                    data = json.load(fp)

                os.remove(data_file)
                return data
            except Exception as err:
                self.logger.error(
                    f"[EXPORT] Failed to load export file: {err}")
                return {}

        return {}

    def _terminate_peridoic_process(self):
        """
        Terminate periodic process
        """
        if self.periodic_process and self.periodic_process.is_alive():
            self.logger.info(
                f"Terminated Measuring process: {self.periodic_process}")
            self.periodic_process.terminate()

        if self.parent_endpoint and not self.parent_endpoint.closed:
            self.parent_endpoint.close()
            self.logger.info(f"Closed parent pipe: {self.parent_endpoint}")

        if self.child_endpoint and not self.child_endpoint.closed:
            self.child_endpoint.close()
            self.logger.info(f"Closed child pipe: {self.child_endpoint}")

        del self.periodic_process
        del self.parent_endpoint
        del self.child_endpoint

    def _start_capturing(self):
        """
        Start all capturing.
        """
        if not self.capture_batch or self.capture_batch.has_plugins:
            return

        self.logger.info(
            "[CAPTURES]: Initializing and starting.")

        self.capture_batch.initialize(profiler=self)
        self.capture_batch.start()
        self._captures_started = True

    def _stop_capturing(self):
        """
        Stops all capturing.
        """
        if not self.capture_batch or self.capture_batch.has_plugins:
            return

        if not self._captures_started:
            self.logger.warn(
                "[CAPTURES]: Attempts to stop capturings before they are successfully started. Skipping.")
            return

        self.logger.info(
            "[CAPTURES]: Stopping and deinitializing.")

        self.capture_batch.stop()
        self.capture_batch.deinitialize()
