#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TODO:
"""

from typing import Type, Callable, Any
from multiprocessing import Pipe, connection
from functools import wraps

# from faas_profiler_python.captures.base import Capture
# from faas_profiler_python.measurements import MeasurementProcess, MeasurementGroup


from faas_profiler_python.config import ProfileConfig, ProfileContext, MeasuringState, Provider
from faas_profiler_python.measurements import Measurement, PeriodicMeasurement
# from faas_profiler_python.exporter import ResultsCollector, Exporter


# from faas_profiler_python.payload import Payload
# from faas_profiler_python.tracer import DistributedTracer

from faas_profiler_python.captures import Capture
from faas_profiler_python.core import BatchExecution, PeriodicProcess, split_plugin_list_by_subclass
from faas_profiler_python.utilis import Loggable


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
        def profiler_wrapper(event, context, **kwargs):
            profiler = Profiler(config_file=config_file)

            function_return = profiler(func, event, context, **kwargs)

            return function_return
        return profiler_wrapper
    return function_profiler


class Profiler(Loggable):

    def __init__(self, config_file: str = None) -> None:
        super().__init__()
        # Load user configuration
        self.config = ProfileConfig.load_file(config_file)

        # Load all requested plugins
        captures = Capture.load(self.config.captures)
        measurements = Measurement.load(self.config.measurements)

        periodic_measurements, default_measurements = split_plugin_list_by_subclass(
            measurements, PeriodicMeasurement)

        self.periodic_batch = BatchExecution(periodic_measurements)
        self.default_batch = BatchExecution(default_measurements)
        self.capture_batch = BatchExecution(captures)

        # Determine Cloud Provider: TODO: Make this dynamic
        self.cloud_provider = Provider.AWS

        # Payload
        # self.payload: Type[Payload] = None

        # Profiler Context
        self.profile_context = ProfileContext()

        # Distributed Tracer
        # self.tracer = DistributedTracer(
        #     config=self.config,
        #     provider=self.cloud_provider,
        #     context=self.profile_context)

        self._default_measurements_started: bool = False
        self._periodic_measurements_started: bool = False
        self._captures_started: bool = False

        # Measurement process for peridic measurements
        self.child_endpoint: Type[connection.Connection] = None
        self.parent_endpoint: Type[connection.Connection] = None
        self.periodic_process: Type[PeriodicProcess] = None

        self.logger.info((
            "[PROFILER PLAN]: \n"
            f"- Measurements: {measurements} \n"
            f"- Captures: {captures} \n"
            f"- Exporters: {self.config.exporters}"
        ))

    def __call__(self, func: Type[Callable], *args, **kwargs) -> Any:
        """
        Convenience wrapper to profile the given method.
        Profiles the given method and exports the results.
        """
        # self.payload = Payload.resolve(self.cloud_provider, (args, kwargs))
        # with self.tracer.start(self.payload):
        self._start(function_args=(args, kwargs))
        self.logger.info(f"-- EXECUTING FUNCTION: {func.__name__} --")

        try:
            func_ret = func(*args, **kwargs)
        except Exception as ex:
            self.logger.error(f"Function not successfully executed: {ex}")
            func_ret = None
        finally:
            self.logger.info("-- FUNCTION EXCUTED --")
            self._stop(payload=(args, kwargs), func_return=func_ret)

        self.export()

        return func_ret

    def _start(self, function_args: tuple) -> None:
        """
        Starts the profiling.

        Internal use only. Use __call__ to start a new profile run.
        """
        self.logger.info("[PROFILER] Profiler run started.")

        self._start_capturing()
        self._start_default_measurements()
        self._start_periodic_measurements()

    def _stop(self, payload: tuple, func_return: Any) -> None:
        """
        Stops the profiling.

        Internal use only. Use __call__ to stop a new profile run.
        """
        self.logger.info("Profile run stopped.")
        self._stop_periodic_measurements()
        self._stop_default_measurements()
        self._stop_capturing()

        if self.periodic_process:
            self.periodic_process.join()
            self._terminate_peridoic_process()

    def export(self):
        """
        Exports the profiling data.
        """
        # if not self.config.exporters:
        #     self.logger.warn("No exporters defined. Will discard results.")
        #     return

        # results_collector = ResultsCollector(
        #     config=self.config,
        #     profile_context=self.profile_context,
        #     captures=self.active_captures)

        # for config_item in self.config.exporters:
        #     try:
        #         exporter = Exporter.factory(config_item.name)
        #     except ValueError:
        #         self.logger.error(
        #             f"No exporter found with name {config_item.name}")
        #         continue

        #     try:
        #         exporter(
        #             self.profile_context,
        #             config_item.parameters).dump(results_collector)
        #     except Exception as err:
        #         self.logger.error(
        # f"Exporting results with {config_item.name} failed: {err}")

    # Private methods

    def _start_default_measurements(self):
        """
        Starts all default measurements
        """
        if not self.default_batch:
            return

        self.logger.info(
            "[DEFAULT MEASUREMENTS]: Initializing and starting.")

        self.default_batch.initialize(self.profile_context)
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
            profile_context=self.profile_context,
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
            "[DEFAULT MEASUREMENTS]: Stopping and deinitializing default measurements")

        self.default_batch.stop()
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
