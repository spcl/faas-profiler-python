#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler configuration
"""
from __future__ import annotations

import logging
import yaml

from os.path import exists, abspath
from enum import Enum
from dataclasses import dataclass
from typing import Any, Dict, List, Type
from collections import namedtuple

from faas_profiler_python.utilis import lowercase_keys
from faas_profiler_core.constants import Provider

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

    MEASUREMENTS_KEY = "measurements"
    CAPTURES_KEY = "captures"
    EXPORTERS_KEY = "exporters"

    OUTBOUND_REQUESTS_TABLES_KEY = "outbound_requests_tables"

    @classmethod
    def load_file(cls, fp_config_file: str) -> Type[Config]:
        cls._logger.info(f"Load configuration: {fp_config_file}")
        # Default config if file does not exists
        if fp_config_file is None or not exists(fp_config_file):
            cls._logger.warn(
                "No profile configuration file found. Take default configuration")
            return cls(config={})

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

                    return cls(config)
        except IOError as err:
            cls._logger.error(f"Could not open profiler config file: {err}")

        return cls(config={})

    def __init__(self, config: dict = {}) -> None:
        self.config = lowercase_keys(config)

        self._measurements: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.MEASUREMENTS_KEY)
        self._captures: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.CAPTURES_KEY)
        self._exporters: List[UnresolvedPlugin] = self._parse_to_plugins(
            self.EXPORTERS_KEY)

        self._outbound_requests_tables = self._parse_outbound_requests_tables(
            self.OUTBOUND_REQUESTS_TABLES_KEY)

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
        entities = []
        config_list = self.config.get(key, [])
        if not isinstance(config_list, list):
            raise ConfigSyntaxError(
                f"Config of {key} must be a list, got {type(config_list)}")

        for config_item in config_list:
            name = config_item.get("name")
            if name:
                entities.append(UnresolvedPlugin(
                    name,
                    config_item.get("parameters", {}),
                    config_item.get("from", None)))

        return entities

    def _parse_outbound_requests_tables(
            self, key: str) -> Dict[Provider, dict]:
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


"""
Process Data structures and feedback
"""


class MeasuringState(Enum):
    STARTED = 1
    STOPPED = 2
    ERROR = -1


@dataclass
class ProcessFeedback:
    state: MeasuringState
    data: Any = None
