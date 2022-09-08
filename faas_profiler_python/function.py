#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Function Context resolving
"""

import os
from typing import Type

from faas_profiler_core.models import FunctionContext
from faas_profiler_core.constants import Provider, Runtime


def create_aws_lambda_function_context() -> Type[FunctionContext]:
    """
    Creates function context for AWS Lambda
    """
    _function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unidentified")
    _handler = os.environ.get("_HANDLER", "unidentified")
    _region = os.environ.get("AWS_REGION", "unidentified")
    _max_memory = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", None)

    return FunctionContext(
        provider=Provider.AWS,
        runtime=Runtime.PYTHON,
        region=_region,
        function_name=_function_name,
        handler=_handler,
        max_memory=_max_memory)


def create_gcp_function_context() -> Type[FunctionContext]:
    """
    Creates function context for GCP Function
    """
    _function_name = os.environ.get("K_SERVICE", "unidentified")
    _handler = os.environ.get("FUNCTION_TARGET", "unidentified")
    _region = os.environ.get("FUNCTION_REGION", "unidentified")
    _max_memory = os.environ.get("FUNCTION_MEMORY_MB", None)
    _max_execution_time = os.environ.get("FUNCTION_TIMEOUT_SEC", None)

    return FunctionContext(
        provider=Provider.GCP,
        runtime=Runtime.PYTHON,
        region=_region,
        function_name=_function_name,
        handler=_handler,
        max_memory=_max_memory,
        max_execution_time=_max_execution_time)


def resolve_function_context() -> Type[FunctionContext]:
    """
    Returns a function context based on the provider
    """
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None:
        return create_aws_lambda_function_context()
    elif os.environ.get("K_SERVICE") is not None:
        return create_gcp_function_context()
    else:
        return FunctionContext(
            provider=Provider.UNIDENTIFIED,
            runtime=Runtime.PYTHON,
            function_name="unidentified",
            handler="unidentified")
