#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS testing helper
Provides helper to mock AWS events and context payloads
"""

import json
from os.path import abspath, dirname, join
from dataclasses import dataclass
from typing import Type

TESTS_DIR = abspath(dirname(__file__))
STATIC_DIR = join(TESTS_DIR, "static")


@dataclass
class ClientContext:
    custom: dict


@dataclass
class LambdaContext:
    function_name: str
    function_version: str
    invoked_function_arn: str
    memory_limit_in_mb: float
    aws_request_id: str
    log_group_name: str
    log_stream_name: str
    client_context: ClientContext


def get_aws_event_payload(payload_name: str) -> dict:
    """
    Loads an AWS event payload example by name.
    """
    with open(join(STATIC_DIR, "aws_events", f"{payload_name}.json")) as fp:
        return json.load(fp)


def get_aws_context_payload(
        aws_request_id="765642b1-1c09-4337-802e-b8b1d0295966",
        log_group_name="/aws/lambda/foo_function",
        log_stream_name="1900/01/01/[$LATEST]89dab19e70374de09e8bdd84eff7757c",
        function_name="foo_function",
        memory_limit_in_mb=128,
        function_version="$LATEST",
        invoked_function_arn="arn:aws:lambda:eu-central-1:123456789012:function:foo_function",
        custom: dict = {}) -> Type[LambdaContext]:
    client_context = ClientContext(custom=custom)
    return LambdaContext(
        function_name=function_name,
        function_version=function_version,
        invoked_function_arn=invoked_function_arn,
        memory_limit_in_mb=memory_limit_in_mb,
        aws_request_id=aws_request_id,
        log_group_name=log_group_name,
        log_stream_name=log_stream_name,
        client_context=client_context)
