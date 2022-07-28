#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler configuration
"""
from __future__ import annotations

import logging
from uuid import uuid4
import pkg_resources
import yaml
import inspect

from datetime import datetime
from os.path import abspath, exists
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Type
from collections import namedtuple

from faas_profiler_python.utilis import lowercase_keys
from functools import reduce

# TODO: make case dest for AWS, local usw
TMP_RESULT_DIR = abspath("/tmp")


def get_faas_profiler_version():
    try:
        return pkg_resources.get_distribution("py_faas_profiler").version
    except pkg_resources.DistributionNotFound:
        return "-"


"""
Plugins Config
"""
UnresolvedPlugin = namedtuple(
    'UnresolvedPlugin',
    'name parameters external_path')
LoadedPlugin = namedtuple("LoadedPlugin", "cls parameters")


class TriggerSynchronicity(Enum):
    """
    Enumeration of different trigger synchronicities
    """
    UNIDENTIFIED = 'unidentified'
    ASYNC = "async"
    SYNC = "sync"


class Provider(Enum):
    """
    Enumeration of different cloud providers.
    """
    UNIDENTIFIED = "unidentified"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class Service(Enum):
    """
    Base class for provider services
    """


class Operation(Enum):
    """
    Base class for operations on provider services.
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
    TRACING_KEY = "tracing"

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

        self._tracing = lowercase_keys(self.config.get(self.TRACING_KEY, {}))

        self._outbound_requests_tables = self._parse_outbound_requests_tables(
            self.OUTBOUND_REQUESTS_TABLES_KEY)

    @property
    def tracing_enabled(self) -> bool:
        """
        Returns True if tracing is enabled by user.
        Default: False
        """
        return self._tracing.get("enabled", True)

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


@dataclass
class ProfileContext:
    config: Type[Config]
    pid: int

    function_name: str = None
    module_name: str = None
    periodic_process_pid: int = None

    def set_function(self, func):
        self.function_name = func.__name__
        try:
            module = inspect.getmodule(func)
            self.module_name = module.__name__
        except Exception:
            self.module_name = None


@dataclass
class MeasuringPoint:
    """
    Data class for measuring points during parallel measurements
    """
    timestamp: int
    data: Any


def average_measuring_points(points: List[MeasuringPoint]) -> Any:
    """
    Calculates the average value of a list of measurement points,
    with the assumption that the "data" property is addable.
    """
    return reduce(
        lambda total, point: total + point.data,
        points,
        0) / len(points)


class MeasuringState(Enum):
    STARTED = 1
    STOPPED = 2
    ERROR = -1


@dataclass
class ProcessFeedback:
    state: MeasuringState
    data: Any = None


"""
Distrubted Tracing Config
"""

# https://specs.openstack.org/openstack/api-wg/guidelines/headers.html
TRACE_ID_HEADER = "FaaS-Profiler-Trace-ID"
INVOCATION_ID_HEADER = "FaaS-Profiler-Invocation-ID"
PARENT_ID_HEADER = "FaaS-Profiler-Parent-ID"

TRACE_CONTEXT_KEY = "_faas_profiler_context"


@dataclass
class TracingContext:
    trace_id: str = None
    invocation_id: str = None
    parent_id: str = None

    @classmethod
    def create_from_payload_tracing_context(
        cls,
        payload_tracing_context: Type[TracingContext]
    ) -> Type[TracingContext]:
        """
        Creates a new context based on the received tracing context.
        """
        if payload_tracing_context.trace_id:
            trace_id = payload_tracing_context.trace_id
        else:
            trace_id = uuid4()

        if payload_tracing_context.invocation_id:
            parent_id = payload_tracing_context.invocation_id
        else:
            parent_id = None

        return cls(
            trace_id=trace_id,
            invocation_id=uuid4(),
            parent_id=parent_id)

    @property
    def is_complete(self) -> bool:
        """
        Returns True if trace context is complete
        """
        return (
            self.trace_id is not None and
            self.invocation_id is not None and
            self.parent_id is not None)

    def to_injectable(self) -> dict:
        """
        Returns the context as injectable context.
        """
        ctx = {}
        if self.trace_id:
            ctx[TRACE_ID_HEADER] = str(self.trace_id)
        if self.invocation_id:
            ctx[INVOCATION_ID_HEADER] = str(self.invocation_id)
        if self.parent_id:
            ctx[PARENT_ID_HEADER] = str(self.parent_id)

        return ctx


@dataclass
class InboundContext:
    provider: Provider
    service: Service
    operation: Operation
    trigger_synchronicity: TriggerSynchronicity = TriggerSynchronicity.UNIDENTIFIED

    identifier: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)

    def set_identifier(self, key: Any, value: Any) -> None:
        """
        Sets a new context identifier
        """
        self.identifier[key] = value

    def set_tags(self, tags: dict) -> None:
        """
        Merges tags into stored tags
        """
        self.tags.update(tags)


# UnresolvedInboundContext = InboundContext(Provider.)


@dataclass
class OutboundContext:
    """
    Base data class for all patch invocations
    """
    module_name: str
    function_name: str

    instance: Any
    original_function: Type[Callable]
    original_args: tuple
    original_kwargs: dict

    response: Any = None

    identifier: dict = field(default_factory=dict)
    execution_time: float = None
    invoked_at: Type[datetime] = None
    has_error: bool = False
    error: Type[Exception] = None

    tags: dict = field(default_factory=dict)

    def set_identifier(self, key: Any, value: Any) -> None:
        """
        Sets a new context identifier
        """
        self.identifier[key] = value

    def set_tags(self, tags: dict) -> None:
        """
        Merges tags into stored tags
        """
        self.tags.update(tags)

    def set_tag(self, key: Any, value: Any) -> None:
        """
        Sets a single tag.
        """
        self.tags[key] = value

    def to_record(self) -> dict:
        """
        Return the context as dict such that it can be stored in a database
        """
        return {
            "identifier": {str(k): str(v) for k, v in self.identifier.items()},
            "invoked_at": self.invoked_at.isoformat(),
            "execution_time": self.execution_time,
            "has_error": str(self.has_error),
            "error_message": str(self.error)
        }
