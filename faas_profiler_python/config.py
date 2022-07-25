#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler configuration
"""
from __future__ import annotations

import logging
import pkg_resources
import yaml
import inspect

from os import getpid, mkdir, environ
from os.path import dirname, join, abspath, exists
from uuid import uuid4
from json import load
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, List, Type
from functools import reduce, cached_property
from collections import namedtuple

from faas_profiler_python.utilis import lowercase_keys

ROOT_DIR = abspath(dirname(__file__))
SHARED_DIR = join(dirname(ROOT_DIR), "shared")
SCHEMAS_DIR = join(SHARED_DIR, "schemas")

# TODO: make case dest for AWS, local usw
TMP_RESULT_DIR = abspath("/tmp")


def get_faas_profiler_version():
    try:
        return pkg_resources.get_distribution("py_faas_profiler").version
    except pkg_resources.DistributionNotFound:
        return "-"


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


class ProfileConfig:
    """
    Representation of the FaaS-Profiler config file (fp_config.yml)
    """

    _logger = logging.getLogger("ProfileConfig")
    _logger.setLevel(logging.INFO)

    Entity = namedtuple('Entity', 'name parameters external_path')

    MEASUREMENTS_KEY = "measurements"
    CAPTURES_KEY = "captures"
    EXPORTERS_KEY = "exporters"
    TRACING_KEY = "tracing"

    @classmethod
    def load_file(cls, fp_config_file: str) -> Type[ProfileConfig]:
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

        self._measurements: List[ProfileConfig.Entity] = self._parse_to_entities(
            self.MEASUREMENTS_KEY)
        self._captures: List[ProfileConfig.Entity] = self._parse_to_entities(
            self.CAPTURES_KEY)
        self._exporters: List[ProfileConfig.Entity] = self._parse_to_entities(
            self.EXPORTERS_KEY)

        self._tracing = lowercase_keys(self.config.get(self.TRACING_KEY, {}))

    @property
    def tracing_enabled(self) -> bool:
        """
        Returns True if tracing is enabled by user.
        Default: False
        """
        return self._tracing.get("enabled", True)

    @property
    def measurements(self) -> List[ProfileConfig.Entity]:
        """
        Returns a List of Entities for each requested measurement
        """
        return self._measurements

    @property
    def captures(self) -> List[ProfileConfig.Entity]:
        """
        Returns a List of Entities for each requested capture
        """
        return self._captures

    @property
    def exporters(self) -> List[ProfileConfig.Entity]:
        """
        Returns a List of Entities for each requested exporter
        """
        return self._exporters

    def _parse_to_entities(self, key: str) -> List[ProfileConfig.Entity]:
        entities = []
        config_list = self.config.get(key, [])
        if not isinstance(config_list, list):
            raise ConfigSyntaxError(
                f"Config of {key} must be a list, got {type(config_list)}")

        for config_item in config_list:
            name = config_item.get("name")
            if name:
                entities.append(ProfileConfig.Entity(
                    name,
                    config_item.get("parameters", {}),
                    config_item.get("from", None)))

        return entities


class ProfileContext:
    """
    TODO:
    """

    _logger = logging.getLogger("ProfileContext")
    _logger.setLevel(logging.INFO)

    def __init__(self) -> None:
        self._profile_run_id = uuid4()
        self._pid: int = getpid()
        self._measurement_process_pid: int = None
        self._tmp_dir = join(TMP_RESULT_DIR,
                             f"faas_profiler_{self.profile_run_id}_results")

        self._payload_context = None
        self._payload_event = None

        self._created_at = None

        self._function_name = None
        self._function_module = None

        mkdir(self._tmp_dir)

    def set_function_name(self, func):
        self._function_name = func.__name__
        try:
            module = inspect.getmodule(func)
            self._function_module = module.__name__
        except Exception as err:
            self._logger.error(f"Could not get module by function: {err}")
            self._function_module = None

    def set_measurement_process_pid(self, pid: int) -> None:
        self._measurement_process_pid = pid

    @cached_property
    def environment_variables(self):
        return dict(environ)

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def measurement_process_pid(self):
        return self._measurement_process_pid

    @property
    def profile_run_id(self):
        return self._profile_run_id

    @property
    def payload_context(self):
        return self._payload_context

    @property
    def payload_event(self):
        return self._payload_event

    @property
    def function_name(self):
        return self._function_name

    @property
    def function_module(self):
        return self._function_module

    @property
    def created_at(self):
        return self._created_at

    @property
    def tmp_results_dir(self):
        return self._tmp_dir


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


def load_schema_by_measurement_name(
    name: str,
    file_ext: str = ".schema.json"
) -> dict:
    """
    Loads a measurement result scheme for the given measurement names.
    """
    schema_file = join(SCHEMAS_DIR, *name) + file_ext
    if exists(schema_file):
        with open(schema_file, "r") as fh:
            try:
                return load(fh)
            except ValueError:
                # TODO: Log that file is not json loadable
                return {}
    else:
        # TODO: Log that file not found
        return {}


"""
Distrubted Tracing Config
"""

# https://specs.openstack.org/openstack/api-wg/guidelines/headers.html
TRACE_ID_HEADER = "FaaS-Profiler-Trace-ID"
INVOCATION_ID_HEADER = "FaaS-Profiler-Invocation-ID"
PARENT_ID_HEADER = "FaaS-Profiler-Parent-ID"

TRACE_CONTEXT_KEY = "_faas_profiler_context"


@dataclass
class TraceContext:
    trace_id: str = None
    invocation_id: str = None
    parent_id: str = None

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
class TriggerContext:
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
