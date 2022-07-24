#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import logging

from typing import Any, Dict
from inflection import underscore
from base64 import b64decode, b64encode


def get_arg_by_key_or_pos(args, kwargs, pos, kw):
    try:
        return kwargs[kw]
    except KeyError:
        try:
            return args[pos]
        except IndexError:
            return None


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


def registerable_name_parts(name, delimiter: str = "::") -> tuple:
    return tuple(underscore(part) for part in name.split(delimiter))


def registerable_key(name, delimiter: str = "::", ) -> str:
    return "_".join(registerable_name_parts(name, delimiter))


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


class Registerable:

    _names_: Dict[str, Registerable] = {}

    name: str = ""
    name_parts: tuple = tuple()
    key: str = ""

    @classmethod
    def register(cls, name, module_delimiter: str = "::"):
        def decorator(subclass):
            cls._names_[name] = subclass
            subclass.name = name
            if module_delimiter:
                subclass.name_parts = registerable_name_parts(
                    name, module_delimiter)
                subclass.key = registerable_key(name, module_delimiter)

            return subclass
        return decorator

    @classmethod
    def factory(cls, name):
        try:
            return cls._names_[name]
        except KeyError:
            raise ValueError(
                f"Unknown measurement name {name}. Available measurements: {list(cls._names_.keys())}")


class Loggable:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)


def plugin_loader(

) -> list:
    pass
