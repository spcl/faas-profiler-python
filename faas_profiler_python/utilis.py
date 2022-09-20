#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler utilis
"""

from __future__ import annotations

import json
import logging
import traceback
import yaml
import re

from os import path
from typing import Any, Callable
from datetime import datetime
from base64 import b64decode, b64encode


URL_REGES = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    # domain...
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def invoke_instrumented_function(
    func: Callable,
    func_args: tuple,
    func_kwargs: dict
) -> tuple:
    """
    Executes a function with timing and error capturing.

    Returns
    -------
    tuple = response, error, traceback_list, invoked_at, finished_at
    """
    error = None
    response = None
    invoked_at = datetime.now()
    traceback_list = []
    try:
        response = func(*func_args, **func_kwargs)
    except Exception as exc:
        traceback_list = traceback.format_exc().split("\n")
        error = exc
    finally:
        finished_at = datetime.now()

    return response, error, traceback_list, invoked_at, finished_at


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


def combine_list_and_dict(
    a_list: list,
    a_dict: dict
) -> dict:
    """
    Merges list und dict to dict
    """
    list_as_dict = {idx: val for idx, val in enumerate(a_list)}
    return {**list_as_dict, **a_dict}


def file_exsits_yaml_parseable(filename: str) -> dict:
    """
    Returns parsed yaml if it exsits and it is valid.
    If not, returns None
    """
    if filename is None or not path.exists(filename):
        return None

    try:
        with open(filename, "r") as fp:
            config = yaml.safe_load(fp)

        if isinstance(config, dict):
            return config
    except (IOError, yaml.YAMLError):
        pass

    return None


def is_url(url: str) -> bool:
    """
    Returns True if url is a valid url
    """
    return re.match(URL_REGES, url) is not None


class Loggable:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
