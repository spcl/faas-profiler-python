#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patching functionality
"""

from __future__ import annotations

import sys
import logging

from typing import Any, Callable, List, Set, Type
from wrapt import when_imported, resolve_path, apply_patch, FunctionWrapper
from dataclasses import dataclass
from collections import namedtuple

from faas_profiler_core.models import OutboundContext, TracingContext

from faas_profiler_python.utilis import Loggable, invoke_instrumented_function
from faas_profiler_python.core import BasePlugin

_logger = logging.getLogger("Patchers")
_logger.setLevel(logging.INFO)


# @dataclass
# class PatchContext:
#     instance: Any
#     function: Callable
#     args: tuple
#     kwargs: dict
#     response: Any
#     error: Exception

PatchContext = namedtuple("PatchContext", "instance function args kwargs")
ReturnContext = namedtuple("ReturnContext", "response error")


class FunctionPatcher(BasePlugin, Loggable):
    module_name: str = None
    submodules: List[str] = []
    function_name: str = None

    def __init__(self) -> None:
        """
        Initializes the patcher.
        """
        super().__init__()

        self._active: str = False
        self._patched: bool = False
        self._original_method = None

        self._data_to_inject: dict = None
        self._registered_observers: Set[Callable] = set()

    def __del__(self):
        """
        Unpatch the function.
        """
        self._deinitialize_patch()


    def register_observer(self, observe_function: Callable) -> None:
        """
        Registers a oberserver for the patcher
        """
        self._registered_observers.add(observe_function)

    def activate(self) -> None:
        """
        Activates patcher.
        """
        self._initialize_patch()
        self._active = True

    def deactivate(self) -> None:
        """
        Deactivates patcher.
        """
        self._deinitialize_patch()
        self._active = False

    def set_data_to_inject(self, data: dict) -> None:
        """
        Sets the trace context to inject
        """
        self._data_to_inject = data

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

    def extract_outbound_context(
        self,
        patch_context: PatchContext,
        return_context: ReturnContext
    ) -> List[Type[OutboundContext]]:
        """
        Extracts Outbound Context from patch context.

        Override this method with the patch specific logic.
        """
        return []

    def inject_tracing_context(
        self,
        patch_context: PatchContext,
        data: dict
    ) -> None:
        """
        Inject tracing context to payload.

        Override this method if the patcher should support payload modification.
        """
        pass

    """
    Private methods
    """

    def _initialize_patch(self) -> None:
        """
        Wraps the function with the patch
        """
        if self._patched:
            return

        parent, attribute, original = resolve_path(self.module_name, self.function_name)
        if self.module_name not in sys.modules:
            self.logger.info(
                f"Module {self.module_name} not yet imported. Set import hook.")
            when_imported(
                self.module_name)(
                lambda *args, **kwargs: self._wrap_function(
                    parent, attribute, original))
        else:
            self._wrap_function(parent, attribute, original)

    def _wrap_function(self, parent, attribute, original) -> None:
        """
        Wraps the requsted function with the function wrapper.
        """
        try:
            wrapper = FunctionWrapper(original, self._function_wrapper)
            if isinstance(original, FunctionWrapper):
                self.logger.info(
                    f"{self.module_name}.{self.function_name} already instrumented, skipping")

            apply_patch(parent, attribute, wrapper)
            self.logger.info(
                f"Patchted successfully function {self.function_name}")

            self._original_method = original
            self._patched = True
        except Exception as err:
            self.logger.error(
                f"Could not patch function {self.function_name}: {err}")
            self._patched = False

    def _deinitialize_patch(self) -> None:
        """
        Removes the wrapper
        """
        if not self._patched:
            return

        try:
            parent, attribute, _ = resolve_path(self.module_name, self.function_name)
            apply_patch(parent, attribute, self._original_method)

            self.logger.info(
                f"Patch successfully removed for function {self.function_name} in module {self.module_name}")
            
            self._patched = False
        except Exception as err:
            self.logger.error(
                f"Removing patch on function {self.function_name} in module {self.module_name} failed: {err}")

    def _function_wrapper(
        self,
        func: Type[Callable],
        instance: Any,
        args: tuple,
        kwargs: dict
    ) -> Any:
        """
        Wrapper function for the pachted function.
        """
        if not self._active:
            return func(*args, **kwargs)

        patch_context = PatchContext(instance, func, args, kwargs)

        self._inject_tracing_context(patch_context)
        breakpoint()
        response, error, _, invoked_at, finished_at = invoke_instrumented_function(
            func, patch_context.args, patch_context.kwargs, with_traceback=False)

        return_context = ReturnContext(response, error)

        try:
            outbound_contexts = self.extract_outbound_context(patch_context, return_context)
        except Exception as err:
            self.logger.error(
                f"Execution outbound context extraction for patched function "
                f"{self.function_name} in module {self.module_name} failed: {err}")
            outbound_contexts = []

        self._notify_observers(outbound_contexts, invoked_at, finished_at)

        if error:
            raise error
        else:
            return response

    def _notify_observers(self,
        outbound_contexts: List[Type[OutboundContext]],
        invoked_at,
        finished_at
    ) -> None:
        """
        Notifies all registered oberservers.
        """
        if not self._registered_observers or len(self._registered_observers) == 0:
            return

        if not outbound_contexts or len(outbound_contexts) == 0:
            return

        for out_ctx in outbound_contexts:
            out_ctx.invoked_at = invoked_at
            out_ctx.finished_at = finished_at

            for oberserver_function in self._registered_observers:
                try:
                    oberserver_function(out_ctx)
                except Exception as err:
                    self.logger.error(
                        f"Notifying {oberserver_function} failed: {err}")


    def _inject_tracing_context(self, patch_context: PatchContext) -> None:
        """
        Calls to modify the payload if required.
        """
        if not self._data_to_inject:
            return

        try:
            self.inject_tracing_context(patch_context, self._data_to_inject)
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
    # if patch_cls in ACTIVE_FUNCTION_PATCHERS:
    #     _logger.info(
    #         f"Patcher for {patch_cls} already exists. Return cached one.")
    #     return ACTIVE_FUNCTION_PATCHERS[patch_cls]

    _logger.info(
        f"Creating new patcher for requested {patch_cls}.")
    patcher = patch_cls()
    # ACTIVE_FUNCTION_PATCHERS[patch_cls] = patcher

    return patcher