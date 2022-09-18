#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patching functionality
"""

from __future__ import annotations

import sys
import logging
import importlib

from threading import Lock
from typing import Any, Callable, List, Set, Type
from wrapt import wrap_function_wrapper, when_imported
from dataclasses import dataclass

from faas_profiler_core.models import OutboundContext, TracingContext

from faas_profiler_python.utilis import Loggable, invoke_instrumented_function
from faas_profiler_python.core import BasePlugin

IGNORE_PATCH_FLAG = "__ignore_patch"
ACTIVE_FUNCTION_PATCHERS = dict()

_logger = logging.getLogger("Patchers")
_logger.setLevel(logging.INFO)


@dataclass
class PatchContext:
    instance: Any
    function: Callable
    args: tuple
    kwargs: dict
    response: Any
    error: Exception


class FunctionPatcher(BasePlugin, Loggable):
    patch_on_import: bool = True
    module_name: str = None
    submodules: List[str] = []
    function_name: str = None

    __key__: str = None

    def __new__(cls: type[FunctionPatcher]) -> FunctionPatcher:
        """
        Creates new Patcher for given function.

        Makes sure that only one patcher exists for given function in given module.
        """
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

        obj = BasePlugin.__new__(cls)
        ACTIVE_FUNCTION_PATCHERS[cls] = obj

        return obj

    def __init__(self) -> None:
        """
        Initializes the patcher.
        """
        super().__init__()

        self._lock = Lock()
        self._active: str = False
        self._patched: bool = False

        self._tracing_context: Type[TracingContext] = None

        self._registered_observers: Set[Callable] = set()

    def __del__(self):
        """
        Unpatch the function.
        """
        self._deinitialize_patch()

    """
    Public Interfaces
    - register_observer
    - activate
    - deactivate
    - set_trace_context_to_inject

    """

    def register_observer(self, observe_function: Callable) -> None:
        """
        Registers a oberserver for the patcher
        """
        self._registered_observers.add(observe_function)

    def activate(self) -> None:
        """
        Activates patcher.
        """
        if self._initialize_patch():
            self._patched = True

        self._active = True

    def deactivate(self) -> None:
        """
        Deactivates patcher.
        """
        if self._deinitialize_patch():
            self._patched = False

        self._active = False

    def set_trace_context_to_inject(
        self,
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Sets the trace context to inject
        """
        self._tracing_context = tracing_context

    """
    Interfaces for patcher specific logic
    """

    def initialize(
        self,
        patch_context: Type[PatchContext]
    ) -> None:
        """
        Setup new patcher context.

        Override this method with the patch specific logic.
        """
        pass

    def extract_outbound_context(self) -> Type[OutboundContext]:
        """
        Extracts Outbound Context from patch context.

        Override this method with the patch specific logic.
        """
        pass

    def inject_tracing_context(
        self,
        tracing_context: Type[TracingContext]
    ) -> None:
        """
        Inject tracing context to payload.

        Override this method if the patcher should support payload modification.
        """
        pass

    """
    Private methods
    """

    def _initialize_patch(self) -> bool:
        """
        Wraps the function with the patch
        """
        if self._patched:
            return True

        if self.module_name not in sys.modules:
            self.logger.info(
                f"Module {self.module_name} not yet imported. Set import hook.")
            when_imported(
                self.module_name)(
                lambda *args,
                **kwargs: self._wrap_function())
        else:
            self._wrap_function()

    def _wrap_function(self) -> None:
        """
        Wraps the requsted function with the function wrapper.
        Executed with lock.
        """
        with self._lock:
            try:
                wrap_function_wrapper(
                    module=self._complete_module_name,
                    name=self.function_name,
                    wrapper=self._function_wrapper)
                self.logger.info(
                    f"Patchted successfully function {self.function_name} in module {self._complete_module_name}")

                self._patched = True
            except Exception as err:
                self.logger.error(
                    f"Could not patch function {self.function_name} in module {self._complete_module_name}: {err}")
                self._patched = False

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
        function: Type[Callable],
        function_instance: Any,
        function_args: tuple,
        function_kwargs: dict
    ) -> Any:
        """
        Wrapper function for the pachted function.
        """
        if not self._active:
            return function(*function_args, **function_kwargs)

        ignore_patch = bool(
            getattr(
                function_instance,
                IGNORE_PATCH_FLAG,
                False))
        if ignore_patch:
            self.logger.info(
                f"Ignored call {function} on {function_instance}: {IGNORE_PATCH_FLAG} flag was True.")
            return function(*function_args, **function_kwargs)

        patch_context = PatchContext(
            function_instance,
            function,
            function_args,
            function_kwargs,
            error=None,
            response=None)
        self.initialize(patch_context)

        self._modify_payload()
        response, error, _, invoked_at, finished_at = invoke_instrumented_function(
            function, patch_context.args, patch_context.kwargs)

        patch_context.response = response
        patch_context.error = error

        outbound_contexts = self._execute_extract_outbound_context()
        if outbound_contexts:
            for out_ctx in outbound_contexts:
                out_ctx.invoked_at = invoked_at
                out_ctx.finished_at = finished_at

                out_ctx.has_error = error is not None
                out_ctx.error_message = str(error) if error else ""

            self._notify_observers(outbound_contexts)

        if error:
            raise error
        else:
            return patch_context.response

    def _notify_observers(self,
                          outbound_contexts: List[Type[OutboundContext]]):
        """
        Notifies all registered oberservers.
        """
        for oberserver_function in self._registered_observers:
            if outbound_contexts is None:
                continue

            for outbound_context in outbound_contexts:
                if outbound_context is None:
                    continue
                try:
                    oberserver_function(outbound_context)
                except Exception as err:
                    self.logger.error(
                        f"Notifying {oberserver_function} failed: {err}")

    def _execute_extract_outbound_context(self) -> Any:
        """
        Safely executes the extract context hook
        """
        try:
            return self.extract_outbound_context()
        except Exception as err:
            self.logger.error(
                f"Execution outbound context extraction for patched function "
                f"{self.function_name} in module {self._complete_module_name} failed: {err}")

    def _modify_payload(self) -> None:
        """
        Calls the tracer to modify the payload if required.
        """
        if not self._tracing_context:
            return

        try:
            self.inject_tracing_context(self._tracing_context)
        except Exception as err:
            self._logger.error(
                f"Injection failed: {err}. Take unmodified parameters.")


"""
Request new patcher.
"""


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


def ignore_instance_from_patching(instance: Any) -> None:
    """
    Sets a flag to ignore this instance during patching.
    """
    setattr(instance, IGNORE_PATCH_FLAG, True)
