#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testing utilities
"""

import json
from os.path import abspath, dirname, join

TESTS_DIR = abspath(dirname(__file__))
STATIC_DIR = join(TESTS_DIR, "static")


def aws_event_payload(payload_name: str) -> dict:
    """
    Loads an AWS event payload example by name.
    """
    with open(join(STATIC_DIR, "aws_events", f"{payload_name}.json")) as fp:
        return json.load(fp)
