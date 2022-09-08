#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Entry point for all measurements and profiling.
The Profiles class handles all measurements and tracing.
"""

import os

from datetime import datetime
from typing import Type, Callable, Any
from multiprocessing import Pipe, connection
from functools import wraps
from uuid import uuid4

from faas_profiler_python.config import Config, MeasuringState, Function
from faas_profiler_python.function import resolve_function_context
from faas_profiler_python.measurements import Measurement, PeriodicMeasurement
from faas_profiler_python.tracer import DistributedTracer
from faas_profiler_python.captures import Capture
from faas_profiler_python.exporters import Exporter, ResultCollector
from faas_profiler_python.core import BatchExecution, PeriodicProcess, split_plugin_list_by_subclass
from faas_profiler_python.utilis import Loggable, invoke_instrumented_function


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
        self.function_context.invoked_at = datetime.now()

        # Load user configuration
        self.config = Config.load_file(config_file)

        # Load all requested plugins
        captures = Capture.load(self.config.captures)
        measurements = Measurement.load(self.config.measurements)
        self.exporters = Exporter.load(self.config.exporters)

        periodic_measurements, default_measurements = split_plugin_list_by_subclass(
            measurements, PeriodicMeasurement)

        self.periodic_batch = BatchExecution(periodic_measurements)
        self.default_batch = BatchExecution(default_measurements)
        self.capture_batch = BatchExecution(captures)

        # Distributed Tracer
        self.tracer = DistributedTracer(
            self.config, self.function_context.provider)

        self._default_measurements_started: bool = False
        self._periodic_measurements_started: bool = False
        self._captures_started: bool = False

        # Measurement process for peridic measurements
        self.child_endpoint: Type[connection.Connection] = None
        self.parent_endpoint: Type[connection.Connection] = None
        self.periodic_process: Type[PeriodicProcess] = None

        self.function_pid = os.getpid()
        self.function: Type[Function] = None

        self.periodic_results_path = os.path.join(
            self.config.tmp_result_storage,
            f"{uuid4()}.json")

        self.logger.info((
            "[PROFILER PLAN]: \n"
            f"- Measurements: {measurements} \n"
            f"- Captures: {captures} \n"
            f"- Exporters: {self.exporters}"
        ))

    def __call__(self, func: Callable, *args, **kwargs) -> Any:
        """
        Instrumentation wrapper to profile the given method.
        Profiles the given method and exports the results.
        """
        self.function = Function(func, args, kwargs)

        self.start()

        self.logger.info(f"-- EXECUTING FUNCTION: {func.__name__} --")
        response, error, executed_at, finished_at = invoke_instrumented_function(
            func, args, kwargs)
        self.logger.info("-- FUNCTION EXCUTED --")

        self.function_context.handler_executed_at = executed_at
        self.function_context.handler_finished_at = finished_at

        self.stop()
        self.export()

        self._deinitialize_default_measurements()

        if error:
            raise error
        else:
            return response

    def start(self) -> None:
        """
        Starts the profiling.
        """
        self.logger.info("[PROFILER] Profiler run started.")

        self.tracer.handle_inbound_request(self.function)
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

        if self.periodic_process:
            self.periodic_process.join()
            self._terminate_peridoic_process()

    def export(self):
        """
        Exports the profiling data.
        """
        if not self.config.exporters:
            self.logger.warn("No exporters defined. Will discard results.")
            return

        self.logger.info(
            "[EXPORT]: Collecting results.")

        self.function_context.finished_at = datetime.now()
        results_collector = ResultCollector(
            function_context=self.function_context,
            tracing_context=self.tracer.tracing_context,
            inbound_context=self.tracer.inbound_context,
            outbound_contexts=self.tracer.outbound_contexts,
            periodic_results_file=self.periodic_results_path,
            default_batch=self.default_batch,
            capture_batch=self.capture_batch)

        for exporter_plugin in self.exporters:
            try:
                exporter = exporter_plugin.cls(
                    **exporter_plugin.parameters)

                exporter.export(results_collector)
            except Exception as err:
                self.logger.error(
                    f"Exporting with {exporter_plugin.cls} failed: {err}")

    def _start_default_measurements(self):
        """
        Starts all default measurements
        """
        if not self.default_batch:
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
        if not self.periodic_batch:
            return

        self.child_endpoint, self.parent_endpoint = Pipe()
        self.periodic_process = PeriodicProcess(
            batch=self.periodic_batch,
            function_pid=self.function_pid,
            result_storage_path=self.periodic_results_path,
            child_connection=self.child_endpoint,
            parent_connection=self.parent_endpoint)

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
        if not self.default_batch:
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
        if not self.default_batch:
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
        self.parent_endpoint.send(MeasuringState.STOPPED)

        try:
            self.periodic_process.wait_for_state(MeasuringState.STOPPED)
            self.logger.info(
                "[PERIODIC MEASUREMENT]: All stopped and terminated")
        except Exception as err:
            self.logger.error(
                f"[DEFAULT MEASUREMENTS]: Stopping and shutting down failed: {err}")

    def _terminate_peridoic_process(self):
        """
        Terminate periodic process
        """
        if self.periodic_process and self.periodic_process.is_alive():
            self.logger.info(
                f"Terminated Measuring process: {self.periodic_process}")
            self.periodic_process.terminate()

        if self.parent_endpoint and not self.parent_endpoint.closed:
            self.logger.info(f"Closed parent pipe: {self.parent_endpoint}")
            self.parent_endpoint.close()

        if self.child_endpoint and not self.parent_endpoint.closed:
            self.logger.info(f"Closed child pipe: {self.child_endpoint}")
            self.child_endpoint.close()

    def _start_capturing(self):
        """
        Start all capturing.
        """
        if not self.capture_batch:
            return

        self.logger.info(
            "[CAPTURES]: Initializing and starting.")

        self.capture_batch.initialize()
        self.capture_batch.start()
        self._captures_started = True

    def _stop_capturing(self):
        """
        Stops all capturing.
        """
        if not self.capture_batch:
            return

        if not self._captures_started:
            self.logger.warn(
                "[CAPTURES]: Attempts to stop capturings before they are successfully started. Skipping.")
            return

        self.logger.info(
            "[CAPTURES]: Stopping and deinitializing.")

        self.capture_batch.stop()
        self.capture_batch.deinitialize()
