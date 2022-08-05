#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler utilis
"""

from __future__ import annotations

import json
import logging

from typing import Any
from base64 import b64decode, b64encode


def get_arg_by_key_or_pos(args, kwargs, pos, kw, default: Any = None):
    try:
        return kwargs[kw]
    except KeyError:
        try:
            return args[pos]
        except IndexError:
            return default


def lowercase_keys(dict: dict) -> dict:
    return {k.lower(): v for k, v in dict.items()}


def get_idx_safely(arr: list, idx: int, default: Any = None) -> Any:
    try:
        return arr[idx]
    except IndexError:
        return default


def split_plugin_name(name: str, delimiter: str = "::") -> tuple:
    parts = name.split(delimiter)
    return (parts[:-1], get_idx_safely(parts, -1))


def decode_base64_json_to_dict(base64_json: Any) -> dict:
    """
    Helper method to decode a base64-encoded json object to a dict.

    Details: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
    """
    try:
        json_string = b64decode(base64_json)
    except Exception as err:
        raise ValueError(f"Base64 decoding bytes-like object failed: {err}")
    else:
        try:
            return json.loads(json_string.decode("utf-8"))
        except Exception as err:
            raise ValueError(f"JSON load of encoded object failed: {err}")


def encode_dict_to_base64_json(dict: dict) -> Any:
    """
    Helper method to encode a dict to a base64-encoded json object.

    Details: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax
    """
    try:
        json_string = json.dumps(dict)
    except Exception as err:
        raise ValueError(f"Could not convert dict to json: {err}")
    else:
        try:
            return b64encode(json_string.encode("utf-8")).decode("utf-8")
        except Exception as err:
            raise ValueError(f"Could not encode to Base64: {err}")


class Loggable:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
