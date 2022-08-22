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

    return FunctionContext(
        provider=Provider.AWS,
        runtime=Runtime.PYTHON,
        function_name=_function_name,
        handler=_handler)


def create_gcp_function_context() -> Type[FunctionContext]:
    """
    Creates function context for GCP Function
    """
    _function_name = os.environ.get("K_SERVICE", "unidentified")
    _handler = os.environ.get("FUNCTION_TARGET", "unidentified")

    return FunctionContext(
        provider=Provider.GCP,
        runtime=Runtime.PYTHON,
        function_name=_function_name,
        handler=_handler)


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
