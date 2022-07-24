#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaaS-Profiler for python package
"""

import logging
import sys

from faas_profiler_python.profiler import profile, Profiler  # noqa

logging.basicConfig(stream=sys.stdout)


del logging
del sys
