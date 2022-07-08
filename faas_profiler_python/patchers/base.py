#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for base patchers.
"""

from __future__ import annotations
from abc import ABC, abstractproperty

import logging
import importlib

from dataclasses import dataclass
from time import time
from typing import Any, Callable, List, Set, Type, Dict
from functools import partial
from wrapt import wrap_function_wrapper


class RequiredModuleMissingError(RuntimeError):
    pass


@dataclass
class PatchEvent:
    function_name: str
    instance_name: str
    execution_time: int


@dataclass(frozen=True)
class PatchedFunction:
    module_name: str
    function_name: str
    before_invocation: Callable = None
    after_invocation: Callable = None


class BasePatcher(ABC):

    _logger = logging.getLogger("BasePatcher")
    _logger.setLevel(logging.INFO)

    def __init__(self) -> None:
        self._active: bool = False

        self._event_observers: Dict[Type[PatchedFunction], Set[Callable]] = {}
        self._wildcard_observers: Set[Callable] = set()

    @abstractproperty
    def patched_functions(self) -> List[PatchedFunction]:
        pass

    def start(self) -> None:
        """
        Starts the patcher
        """
        if self._active:
            return

        for patched_function in self.patched_functions:
            try:
                wrap_function_wrapper(
                    module=patched_function.module_name,
                    name=patched_function.function_name,
                    wrapper=partial(
                        self._function_wrapper,
                        patched_context=patched_function))
            except Exception as err:
                self._logger.error(
                    f"Could not patch function {patched_function}: {err}")

        self._active = True

    def stop(self) -> None:
        """
        Stops the patcher
        """
        if not self._active:
            return

        for patched_function in self.patched_functions:
            module = importlib.import_module(patched_function.module_name)
            a, *b = patched_function.function_name.split(".")
            _function_name = b[0] if b else a
            _class_name = a if b else None

            if _class_name:
                klass = getattr(module, _class_name)
                func_wrapper = getattr(klass, _function_name)

                setattr(
                    klass,
                    patched_function.function_name,
                    func_wrapper.__wrapped__)
            else:
                func_wrapper = getattr(module, patched_function.function_name)
                setattr(
                    module,
                    patched_function.function_name,
                    func_wrapper.__wrapped__)

        self._active = False

    #
    #   Function Wrapper (the actual Patch)
    #

    def _function_wrapper(
        self,
        original_func: Type[Callable],
        instance: Type[Any],
        args: tuple,
        kwargs: dict,
        patched_context: Type[PatchedFunction] = None
    ) -> Any:
        """
        Function wrapper which gets executed for each patched function.

        Executed the before_invocation and after_invocation if requested.
        Notifies the observers.
        """
        event = PatchEvent(original_func.__name__, str(instance), 0)

        before_result = None
        if patched_context and patched_context.before_invocation:
            try:
                before_result = patched_context.before_invocation(
                    original_func, instance, args, kwargs)
            except Exception as err:
                self._logger.error(f"Before invocation patcher failed: {err}")

        invocation_start = time()
        func_return = original_func(*args, **kwargs)
        event.execution_time = time() - invocation_start

        after_result = None
        if patched_context and patched_context.after_invocation:
            after_result = patched_context.after_invocation(func_return)

        self._notify(patched_context, event, before_result, after_result)

        return func_return

    #
    #   Observer management
    #

    def register_observer(self, observer: Callable, on: tuple = None) -> None:
        """
        Registers an observer.
        If "on" is not given, the observer is notified for all leased events.
        If a tuple of module name and function name is passed, the observer will be notified
        if given function was patched.

        Double registrations are possible, but not for the same event.
        """
        if not callable(observer):
            raise ValueError(
                f"{observer} must be callable to act as oberserver.")

        if on is None:
            self._wildcard_observers.add(observer)
        else:
            _on = on[:2]
            if len(_on) != 2:
                raise ValueError(
                    "Event specifiction for observer is invalid.\
                    Please pass the event in the form ('module_name', 'function_name')")
            _module_name, _function_name = on
            try:
                _pachted = next(p for p in self.patched_functions if p.module_name ==
                                _module_name and p.function_name == _function_name)
                self._event_observers.setdefault(_pachted, set()).add(observer)
            except StopIteration:
                raise ValueError(
                    f"No function patched with in module {_module_name} with function name {_function_name}")

    def deregister_observer(self, observer: Callable):
        """
        Deregisters an observer by removing the callable in all event and wildcard sets.
        """
        for observer_set in self._event_observers.values():
            observer_set.discard(observer)

        self._wildcard_observers.discard(observer)

    def _notify(
        self,
        patched_function: Type[PatchedFunction],
        event: Type[PatchEvent],
        before_result: Any = None,
        after_result: Any = None
    ) -> None:
        """
        Notifies all observers.
        """
        for observer in self._wildcard_observers:
            try:
                observer(event, before_result, after_result)
            except Exception as err:
                self._logger.error(f"Notifying {observer} failed: {err}")

        for event_observer in self._event_observers.get(
                patched_function, set()):
            try:
                event_observer(event, before_result, after_result)
            except Exception as err:
                self._logger.error(f"Notifying {event_observer} failed: {err}")

    # def _import_target_module(self):
    #     with self._lock:
    #         try:
    #             return importlib.import_module(self.target_module)
    #         except ImportError:
    #             raise RequiredModuleMissingError(
    #                 f"Required modules are missing: {self.target_module}")
