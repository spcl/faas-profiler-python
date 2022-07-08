#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for base patchers.
"""

from __future__ import annotations
from abc import ABC, abstractproperty
from contextlib import contextmanager

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

        self._injection: Callable = None
        self._injection_event: tuple = None

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

        with self.call_with_injection(
            func_args=(args, kwargs),
            event=event,
            before_result=before_result,
            patched_context=patched_context
        ) as (mod_args, mod_kwargs):
            invocation_start = time()
            func_return = original_func(*mod_args, **mod_kwargs)
            event.execution_time = time() - invocation_start

        after_result = None
        if patched_context and patched_context.after_invocation:
            after_result = patched_context.after_invocation(func_return)

        self._notify(patched_context, event, before_result, after_result)

        return func_return

    @contextmanager
    def call_with_injection(
        self,
        func_args: tuple,
        event: PatchEvent,
        before_result: Any = None,
        patched_context: Type[PatchedFunction] = None
    ):
        """
        Inject function arguments to allow modification.
        """
        if self._should_inject_patched_function(patched_context):
            org_func_args = tuple(func_args)
            try:
                self._injection(func_args, event, before_result)
            except Exception as err:
                self._logger.error(
                    f"Injected return is unpackable: {err}. Take unmodified parameters.")
                func_args = org_func_args

        yield func_args[0], func_args[1]

    def _should_inject_patched_function(
        self,
        patched_context: Type[PatchedFunction] = None
    ) -> bool:
        if not self._injection:
            return False

        if self._injection_event is None:
            return True

        return patched_context == self._injection_event

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
        self._check_callable(observer)

        if on is None:
            self._wildcard_observers.add(observer)
        else:
            _patched = self._find_patched_function(on)
            self._event_observers.setdefault(_patched, set()).add(observer)

    def deregister_observer(self, observer: Callable):
        """
        Deregisters an observer by removing the callable in all event and wildcard sets.
        """
        for observer_set in self._event_observers.values():
            observer_set.discard(observer)

        self._wildcard_observers.discard(observer)

    def inject_with(
        self,
        injection: Callable,
        on: tuple = None
    ) -> None:
        """
        Registers an injection, which is a special observer allowed to modify the functions args.
        Only one injection per patcher is allowed.

        Parameters
        ----------
        injection : Callable
            Function to be called to inject the function parameters
        on : tuple
            Tuple consisting of module name and function name to specifiy when the injection should be called.
            If None, it will be triggerd every time
        """
        self._check_callable(injection)

        if self._injection is not None:
            raise RuntimeError(
                f"This patcher has already an injection function: {self._injection}")

        self._injection_event = self._find_patched_function(on)
        self._injection = injection

    def reset_injection(self) -> None:
        """
        Resets the injection function.
        """
        self._injection = None

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

    def _check_callable(self, func: Callable):
        """
        Raises Error if func is not callable
        """
        if not callable(func):
            raise ValueError(
                f"{func} must be callable to act as callback.")

    def _find_patched_function(self, on: tuple = None):
        if on is None:
            return None

        _on = on[:2]
        if len(_on) != 2:
            raise ValueError(
                "Event specifiction for observer is invalid.\
                Please pass the event in the form ('module_name', 'function_name')")

        _module_name, _function_name = on[:2]

        try:
            return next(p for p in self.patched_functions if p.module_name ==
                        _module_name and p.function_name == _function_name)
        except StopIteration:
            raise ValueError(
                f"No function patched with in module {_module_name} with function name {_function_name}")

    # def _import_target_module(self):
    #     with self._lock:
    #         try:
    #             return importlib.import_module(self.target_module)
    #         except ImportError:
    #             raise RequiredModuleMissingError(
    #                 f"Required modules are missing: {self.target_module}")
