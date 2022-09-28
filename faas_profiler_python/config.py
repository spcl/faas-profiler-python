#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler configuration
"""
from __future__ import annotations

import logging
import ujson
import yaml

from os import environ
from os.path import exists, abspath, dirname, isabs, join
from enum import Enum, auto
from typing import List, Type
from collections import namedtuple
from faas_profiler_python.utilis import lowercase_keys
"""
Constants
"""

ALL_PATCHERS = "all_patchers"

"""
Exceptions
"""


class UnsupportedServiceError(RuntimeError):
    pass


class InjectionError(RuntimeError):
    pass


"""
Payload
"""

Function = namedtuple("FunctionPayload", "function args kwargs")

"""
Plugins Config
"""

LoadedPlugin = namedtuple(
    "LoadedPlugin",
    "name cls parameters")

"""
Configuration
"""


WILDCARD_KEY = "*"

PLUGIN_NAME_KEY = "name"
PLUGIN_FROM_KEY = "from"
PLUGIN_CFG_KEY = "parameters"

PROFILER_KEY = "profiler"

MEASUREMENTS_KEY = "measurements"
CAPTURES_KEY = "captures"
EXPORTERS_KEY = "exporters"
TRACING_KEY = "tracing"

MEASUREMENTS_ENV_KEY = "FP_MEASUREMENTS"
CAPTURES_ENV_KEY = "FP_CAPTURES"
EXPORTERS_ENV_KEY = "FP_EXPORTERS"

INTERVAL_ENV_KEY = "FP_PROCESS_INTERVAL"
INCLUDE_VARS_ENV_KEY = "FP_INCLUDE_VARS"
INCLUDE_RETURN_ENV_KEY = "FP_INCLUDE_RESPONSE"
INCLUDE_ARGS_ENV_KEY = "FP_INCLUDE_PAYLOAD"

ENABLE_TRACING_ENV_KEY = "FP_ENABLE_TRACING"
TRACE_OUTGOING_ENV_KEY = "FP_TRACE_OUTGOING"
INJECT_RESPONSE_ENV_KEY = "FP_INJECT_RESPONSE"

ENV_PLUGIN_DELIMITER = ","
ENV_PARAMETER_DELIMITER = "#"
ENV_PARAMETER_NAME_DELIMITER = 2 * ENV_PARAMETER_DELIMITER


def load_configuration(config_path: str = None) -> Type[Config]:
    """
    Loads profiler configuration
    """
    if config_path is None:
        return Config.load_by_env()
    elif str(config_path).endswith(".yml"):
        return Config.from_yaml_file(config_path)
    elif str(config_path).endswith(".json"):
        return Config.from_json_file(config_path)
    else:
        return Config()


class Config:
    """
    Representation of the FaaS-Profiler config file or env variables
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    @classmethod
    def from_json_file(cls, json_path_file: str) -> Type[Config]:
        """
        Load the passed configuration file if it exists and is readable.
        """
        try:
            with open(json_path_file, "r") as fp:
                return Config(ujson.load(fp), json_path_file)
        except Exception as err:
            cls.logger.error(f"Loading {json_path_file} failed: {err}")
            return Config({}, json_path_file)

    @classmethod
    def from_yaml_file(cls, yaml_path_file: str) -> Type[Config]:
        """
        Load the passed configuration file if it exists and is readable.
        """
        try:
            with open(yaml_path_file, "r") as fp:
                return Config(yaml.safe_load(fp), yaml_path_file)
        except Exception as err:
            cls.logger.error(f"Loading {yaml_path_file} failed: {err}")
            return Config({}, yaml_path_file)

    @classmethod
    def load_by_env(cls) -> Type[Config]:
        """
        Loads config by env variables.
        """
        measurements = []
        exporters = []
        captures = []

        if MEASUREMENTS_ENV_KEY in environ:
            measurements = [{"name": name} for name in environ.get(
                MEASUREMENTS_ENV_KEY).split(ENV_PLUGIN_DELIMITER)]

        if EXPORTERS_ENV_KEY in environ:
            exporters = [{"name": name} for name in environ.get(
                EXPORTERS_ENV_KEY).split(ENV_PLUGIN_DELIMITER)]

        if CAPTURES_ENV_KEY in environ:
            captures = [{"name": name} for name in environ.get(
                CAPTURES_ENV_KEY).split(ENV_PLUGIN_DELIMITER)]

        return cls(
            config={
                MEASUREMENTS_KEY: measurements,
                CAPTURES_KEY: captures,
                EXPORTERS_KEY: exporters,
            })

    def __init__(
        self,
        config: dict = {},
        config_file: str = None
    ) -> None:
        self.config_file = config_file
        self.config = config

        self.config_dir = None
        if self.config_file:
            try:
                self.config_dir = abspath(dirname(self.config_file))
            except Exception as err:
                self.logger.error(
                    f"Could not resolve dir of config file: {err}")

        self._profiler_settings = self.config.get(PROFILER_KEY, {})
        self._function_context_settings = self._profiler_settings.get(
            "function_context", {})

        self._measurements: List[dict] = self.config.get(MEASUREMENTS_KEY, [])
        self._captures: List[dict] = self.config.get(CAPTURES_KEY, [])
        self._exporters: List[dict] = self.config.get(EXPORTERS_KEY, [])

        self._tracing = lowercase_keys(self.config.get(TRACING_KEY, {}))

    @property
    def measurement_interval(self) -> float:
        """
        Returns the interval of the measurement process in seconds
        """
        if INTERVAL_ENV_KEY in environ:
            return float(environ.get(INTERVAL_ENV_KEY))

        return float(
            self._profiler_settings.get(
                "measurement_interval",
                0.1))

    @property
    def include_environment_variables(self) -> bool:
        """
        Returns True if environment variables should be included
        """
        if INCLUDE_VARS_ENV_KEY in environ:
            return bool(environ.get(INCLUDE_VARS_ENV_KEY))

        return self._function_context_settings.get(
            "environment_variables", False)

    @property
    def include_response(self) -> bool:
        """
        Returns True if response should be included
        """
        if INCLUDE_RETURN_ENV_KEY in environ:
            return bool(environ.get(INCLUDE_RETURN_ENV_KEY))

        return self._function_context_settings.get("response", False)

    @property
    def include_payload(self) -> bool:
        """
        Returns True if payload should be included
        """
        if INCLUDE_ARGS_ENV_KEY in environ:
            return bool(environ.get(INCLUDE_ARGS_ENV_KEY))

        return self._function_context_settings.get("payload", False)

    @property
    def include_traceback(self) -> bool:
        """
        Returns True if traceback should be included
        """
        return self._function_context_settings.get("traceback", False)

    @property
    def tracing_enabled(self) -> bool:
        """
        Returns True if tracing is enabled.
        """
        if ENABLE_TRACING_ENV_KEY in environ:
            return bool(environ.get(ENABLE_TRACING_ENV_KEY))

        return self._tracing.get("enabled", False)

    @property
    def trace_outgoing_requests(self) -> List[str]:
        """
        Returns a list of outgoing request types which should be traced.
        """
        if TRACE_OUTGOING_ENV_KEY in environ:
            env_trace_outgoing = str(environ.get(TRACE_OUTGOING_ENV_KEY))
            if env_trace_outgoing == WILDCARD_KEY:
                return ALL_PATCHERS

            return env_trace_outgoing.split(ENV_PLUGIN_DELIMITER)

        trace_out_requests = self._tracing.get(
            "trace_outgoing_requests", [])
        if trace_out_requests == WILDCARD_KEY:
            return ALL_PATCHERS

        if isinstance(trace_out_requests, list):
            return [str(lib) for lib in trace_out_requests]

        return []

    @property
    def inject_response(self) -> bool:
        """
        Returns True if tracer should inject response.
        Experimental: allows tracing of step functions/workflows until another type is found.
        """
        if INJECT_RESPONSE_ENV_KEY in environ:
            return bool(environ.get(INJECT_RESPONSE_ENV_KEY))

        return self._tracing.get("inject_response", False)

    @property
    def measurements(self) -> List[dict]:
        """
        Returns a List of Entities for each requested measurement
        """
        return self._measurements

    @property
    def captures(self) -> List[dict]:
        """
        Returns a List of Entities for each requested capture
        """
        return self._captures

    @property
    def exporters(self) -> List[dict]:
        """
        Returns a List of Entities for each requested exporter
        """
        return self._exporters

    def _resolve_external_path(self, external_path: str) -> str:
        """
        Makes the external path for a plugin absolute.
        """
        if external_path is None:
            return

        _external_path = external_path
        if not isabs(_external_path) and self.config_dir:
            _external_path = join(self.config_dir, external_path)

        if not exists(_external_path):
            return None

        return _external_path


"""
Process Data structures and feedback
"""


class MeasuringState(Enum):
    """
    Enumeration of different measuring states.
    """
    STARTED = auto()
    STOPPED = auto()
    EXPORT_FILE = auto()
    EXPORT_DATA = auto()
    ERROR = auto()
