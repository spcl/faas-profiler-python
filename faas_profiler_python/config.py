#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler configuration
"""
from __future__ import annotations

import logging
import yaml

from os.path import exists, abspath, dirname, isabs, join
from enum import Enum
from dataclasses import dataclass
from typing import Any, Dict, List, Type
from collections import namedtuple
from faas_profiler_python.utilis import lowercase_keys
from faas_profiler_core.constants import Provider

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

UnresolvedPlugin = namedtuple(
    'UnresolvedPlugin',
    'name parameters external_path')
LoadedPlugin = namedtuple(
    "LoadedPlugin",
    "name cls parameters")

"""
Configuration
"""


class ConfigSyntaxError(SyntaxError):
    pass


class Config:
    """
    Representation of the FaaS-Profiler config file (fp_config.yml)
    """

    _logger = logging.getLogger("Config")
    _logger.setLevel(logging.INFO)

    WILDCARD_KEY = "*"

    PLUGIN_NAME_KEY = "name"
    PLUGIN_FROM_KEY = "from"
    PLUGIN_CFG_KEY = "parameters"

    MEASUREMENTS_KEY = "measurements"
    CAPTURES_KEY = "captures"
    EXPORTERS_KEY = "exporters"
    TRACING_KEY = "tracing"

    OUTBOUND_REQUESTS_TABLES_KEY = "outbound_requests_tables"

    @classmethod
    def load_file(cls, fp_config_file: str) -> Type[Config]:
        """
        Load the passed configuration file if it exists and is readable.
        """
        cls._logger.info(f"Load configuration: {fp_config_file}")
        # Default config if file does not exists
        if fp_config_file is None or not exists(fp_config_file):
            cls._logger.warn(
                "No profile configuration file found. Take default configuration")
            return cls(fp_config_file, config={})

        try:
            with open(fp_config_file, "r") as fp:
                try:
                    config = yaml.safe_load(fp)
                except yaml.YAMLError as err:
                    cls._logger.error(
                        f"Could not parse profiler config file: {err}")
                else:
                    if not isinstance(config, dict):
                        cls._logger.error(
                            f"Profiler configuration {fp_config_file} must be a dict, but got {type(config)}")
                        config = {}

                    return cls(fp_config_file, config)
        except IOError as err:
            cls._logger.error(f"Could not open profiler config file: {err}")

        return cls(fp_config_file, config={})

    def __init__(
        self,
        config_file: str = None,
        config: dict = {}
    ) -> None:
        self.config_file = config_file
        self.config = lowercase_keys(config)

        try:
            self.config_dir = abspath(dirname(self.config_file))
        except Exception as err:
            self._logger.error(f"Could not resolve dir of config file: {err}")
            self.config_dir = None

        self._measurements: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.MEASUREMENTS_KEY)
        self._captures: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.CAPTURES_KEY)
        self._exporters: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.EXPORTERS_KEY)

        self._tracing = lowercase_keys(self.config.get(self.TRACING_KEY, {}))

        self._outbound_requests_tables = self._parse_outbound_requests_tables(
            self.OUTBOUND_REQUESTS_TABLES_KEY)

    @property
    def tracing_enabled(self) -> bool:
        """
        Returns True if tracing is enabled.
        """
        return self._tracing.get("enabled", True)

    @property
    def trace_outgoing_requests(self) -> List[str]:
        """
        Returns a list of outgoing request types which should be traced.
        """
        trace_out_requests = self._tracing.get(
            "trace_outgoing_requests", self.WILDCARD_KEY)
        if trace_out_requests == self.WILDCARD_KEY:
            return ALL_PATCHERS

        if isinstance(trace_out_requests, list):
            return [str(lib) for lib in trace_out_requests]

        return []

    @property
    def outbound_requests_tables(self) -> Dict[Provider, dict]:
        """
        Returns a dict for each configured outbound request table with parameters
        """
        return self._outbound_requests_tables

    @property
    def measurements(self) -> List[UnresolvedPlugin]:
        """
        Returns a List of Entities for each requested measurement
        """
        return self._measurements

    @property
    def captures(self) -> List[UnresolvedPlugin]:
        """
        Returns a List of Entities for each requested capture
        """
        return self._captures

    @property
    def exporters(self) -> List[UnresolvedPlugin]:
        """
        Returns a List of Entities for each requested exporter
        """
        return self._exporters

    @property
    def tmp_result_storage(self) -> str:
        """
        Returns path to temporaly result storge
        """
        return abspath("/tmp")

    def _parse_to_plugins(self, key: str) -> List[UnresolvedPlugin]:
        """
        Creates a list of unresolved plugins based on the list of requested plugins.
        """
        entities = []
        config_list = self.config.get(key, [])
        if config_list is None:
            config_list = []

        if not isinstance(config_list, list):
            raise ConfigSyntaxError(
                f"Config of {key} must be a list, got {type(config_list)}")

        for config_item in config_list:
            if self.PLUGIN_NAME_KEY not in config_item:
                continue

            if self.PLUGIN_FROM_KEY in config_item:
                _external_path = self._resolve_external_path(
                    config_item[self.PLUGIN_FROM_KEY])

                if not _external_path:
                    self._logger.error(
                        f"File {config_item[self.PLUGIN_FROM_KEY]} for external plugin does not exists.")
            else:
                _external_path = None

            entities.append(UnresolvedPlugin(
                config_item[self.PLUGIN_NAME_KEY],
                config_item.get(self.PLUGIN_CFG_KEY, {}),
                _external_path))

        return entities

    def _parse_outbound_requests_tables(
        self,
        key: str
    ) -> Dict[Provider, dict]:
        tables = {}
        tables_config = self._tracing.get(key, [])
        if not isinstance(tables_config, list):
            raise ConfigSyntaxError(
                f"Config of {key} must be a list, got {type(tables_config)}")

        for table_config in tables_config:
            provider_str = str(table_config.get("provider")).lower()
            try:
                provider = Provider(provider_str)
            except ValueError:
                pass
            else:
                if provider in tables:
                    raise ConfigSyntaxError(
                        f"Duplicate key for {provider}. Outbound Request Table for {provider} already defined.")

                tables[provider] = table_config.get("parameters", {})

        return tables

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
    STARTED = 1
    STOPPED = 2
    ERROR = -1


@dataclass
class ProcessFeedback:
    """
    Dataclass for feeback sending between Measurement process and main process.
    """
    state: MeasuringState
    data: Any = None
