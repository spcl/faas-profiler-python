#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patching functionality
"""

from __future__ import annotations

import logging
import importlib

from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from contextlib import contextmanager
from threading import Lock
from time import time
from typing import TYPE_CHECKING, Any, Callable, List, Set, Type
from collections import namedtuple
from wrapt import wrap_function_wrapper

from faas_profiler_python.utilis import Loggable
from faas_profiler_python.core import BasePlugin

if TYPE_CHECKING:
    from faas_profiler_python.captures import Capture
    from faas_profiler_python.tracer import DistributedTracer

ACTIVE_FUNCTION_PATCHERS = dict()

_logger = logging.getLogger("Patchers")
_logger.setLevel(logging.INFO)

PatchEvent = namedtuple("PatchEvent", [
    "instance", "function", "args", "kwargs"])


@dataclass
class InvocationContext:
    """
    Base data class for all patch invocations
    """
    function_patcher: Type[FunctionPatcher]
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


class FunctionPatcher(ABC, BasePlugin, Loggable):
    patch_on_import: bool = True
    module_name: str = None
    submodules: List[str] = []
    function_name: str = None

    __key__: str = None

    def __new__(cls: type[FunctionPatcher]) -> FunctionPatcher:
        if cls.module_name is None or cls.function_name is None:
            raise ValueError(
                f"Cannot initialize patcher {cls} without module name and function name.")

        cls.__key__ = ".".join([
            cls.module_name, *cls.submodules, cls.function_name])
        cls._complete_module_name = ".".join(
            [cls.module_name, *cls.submodules])

        if any(active_patcher.__key__ ==
               cls.__key__ for active_patcher in ACTIVE_FUNCTION_PATCHERS):
            raise ValueError(
                f"Cannot initialize patcher {cls}. A active patcher for {cls.__key__} already exists.")

        obj = ABC.__new__(cls)

        return obj

    def __del__(self):
        """
        Unpatch the function.
        """
        self._deinitialize_patch()

    def __init__(self) -> None:
        """
        Initializes the patcher.
        """
        self._lock = Lock()
        self.active: str = False
        self._patched: bool = False

        self._registered_captures: Set[Type[Capture]] = set()
        self._tracer: Type[DistributedTracer] = None

        super().__init__()

    def _initialize_patch(self) -> bool:
        """
        Wraps the function with the patch
        """
        if self._patched:
            return True

        with self._lock:
            try:
                wrap_function_wrapper(
                    module=self._complete_module_name,
                    name=self.function_name,
                    wrapper=self._function_wrapper)
                self.logger.info(
                    f"Patchted successfully function {self.function_name} in module {self._complete_module_name}")

                return True
            except Exception as err:
                self.logger.error(
                    f"Could not patch function {self.function_name} in module {self._complete_module_name}: {err}")
                return False

    def _deinitialize_patch(self) -> bool:
        """
        Removes the wrapper
        """
        if not self._patched:
            return True

        with self._lock:
            module = importlib.import_module(self._complete_module_name)
            a, *b = self.function_name.split(".")
            _function_name = b[0] if b else a
            _class_name = a if b else None

            try:
                if _class_name:
                    klass = getattr(module, _class_name)
                    func_wrapper = getattr(klass, _function_name)
                    setattr(
                        klass,
                        self.function_name,
                        func_wrapper.__wrapped__)
                else:
                    func_wrapper = getattr(module, self.function_name)
                    setattr(
                        module,
                        self.function_name,
                        func_wrapper.__wrapped__)

                self.logger.info(
                    f"Patch successfully removed for function {self.function_name} in module {self._complete_module_name}")
                return True
            except Exception as err:
                self.logger.error(
                    f"Removing patch on function {self.function_name} in module {self._complete_module_name} failed: {err}")
                return False

    def _function_wrapper(
        self,
        original_function: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ) -> Any:
        """
        Wrapper function for the pachted function.
        """
        if not self.active:
            return original_function(*args, **kwargs)

        invocation_context = InvocationContext(
            function_patcher=self,
            module_name=self._complete_module_name,
            function_name=self.function_name,
            instance=instance,
            original_function=original_function,
            original_args=args,
            original_kwargs=kwargs)

        try:
            execution_start = time()
            invocation_context.invoked_at = datetime.now()
            with self._modified_payload(
                original_function, instance, args, kwargs
            ) as (mod_args, mod_kwargs):
                response = original_function(*mod_args, **mod_kwargs)
        except Exception as error:
            invocation_context.execution_time = time() - execution_start
            invocation_context.has_error = True
            invocation_context.error = error

            self._execute_extract_context(invocation_context)
            self._notify_captures(invocation_context)

            if self._tracer:
                self._tracer.record_outbound_request()

            raise
        else:
            invocation_context.execution_time = time() - execution_start
            invocation_context.has_error = False
            invocation_context.response = response

            self._execute_extract_context(invocation_context)
            self._notify_captures(invocation_context)

            if self._tracer:
                self._tracer.record_outbound_request()

            return response

    def _notify_captures(self, invocation_context: Type[InvocationContext]):
        """
        Notifies all registered captures.
        """
        for capture in self._registered_captures:
            try:
                capture.capture(invocation_context)
            except Exception as err:
                self.logger.error(f"Notifying {capture} failed: {err}")

    def _execute_extract_context(
        self,
        invocation_context: Type[InvocationContext]
    ) -> Any:
        """
        Safely executes the extract context hook
        """
        try:
            self.extract_context(invocation_context)
        except Exception as err:
            self.logger.error(
                f"Execution after invocation for patched function "
                f"{self.function_name} in module {self._complete_module_name} failed: {err}")

    @contextmanager
    def _modified_payload(
        self,
        original_function: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ):
        """
        Calls the tracer to modify the payload if required.
        """
        if self._tracer:
            patch_event = PatchEvent(instance, original_function, args, kwargs)
            org_args = tuple(args)
            org_kwargs = dict(kwargs)
            try:
                self.modify_function_args(patch_event)
            except Exception as err:
                self._logger.error(
                    f"Injection failed: {err}. Take unmodified parameters.")
                args = org_args
                kwargs = org_kwargs

        yield args, kwargs

    def register_capture(self, capture) -> None:
        """
        Registers a new capture for the patcher.
        """
        self._registered_captures.add(capture)

    def set_tracer(self, tracer) -> None:
        """
        Sets the current tracer.
        """
        self._tracer = tracer

    def activate(self) -> None:
        """
        Activates patcher.
        """
        if self._initialize_patch():
            self._patched = True

        self.active = True

    def deactivate(self) -> None:
        """
        Deactivates patcher.
        """
        if self._deinitialize_patch():
            self._patched = False

        self.active = False

    @abstractmethod
    def extract_context(
        self,
        invocation_context: Type[InvocationContext]
    ) -> None:
        pass

    def modify_function_args(
        self,
        patch_event: Type[PatchEvent]
    ) -> tuple:
        raise NotImplementedError


def request_patcher(
    patch_cls: FunctionPatcher
) -> Type[FunctionPatcher]:
    """
    Returns a patcher instance for the requested patcher class.

    Makes sure, that only one patcher exists.
    """
    global ACTIVE_FUNCTION_PATCHERS
    if patch_cls in ACTIVE_FUNCTION_PATCHERS:
        _logger.info(
            f"Patcher for {patch_cls} already exists. Return cached one.")
        return ACTIVE_FUNCTION_PATCHERS[patch_cls]

    _logger.info(
        f"Creating new patcher for requested {patch_cls}.")
    patcher = patch_cls()
    ACTIVE_FUNCTION_PATCHERS[patch_cls] = patcher

    return patcher
