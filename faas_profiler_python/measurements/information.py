#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for information extraction:
- Environment
- OperatingSystem
"""

import sys
import platform
import os
import pkg_resources
import psutil

from datetime import datetime

from faas_profiler_python.measurements import Measurement
from faas_profiler_core.models import (
    InformationEnvironment,
    InformationOperatingSystem
)


class Environment(Measurement):

    def results(self) -> dict:
        return InformationEnvironment(
            runtime_name="python",
            runtime_version=sys.version,
            runtime_implementation=platform.python_implementation(),
            runtime_compiler=platform.python_compiler(),
            byte_order=sys.byteorder,
            platform=sys.platform,
            interpreter_path=sys.executable,
            packages=self._installed_packages()
        ).dump()

    def _installed_packages(self) -> list:
        try:
            installed_packages = pkg_resources.working_set
            return sorted(["%s==%s" % (i.key, i.version)
                          for i in installed_packages])
        except Exception as exc:
            self._logger.warn(f"Could not get installed packages: {exc}")
            return []


class OperatingSystem(Measurement):

    def results(self) -> dict:
        uname = os.uname()
        return InformationOperatingSystem(
            boot_time=datetime.fromtimestamp(psutil.boot_time()),
            system=uname.sysname,
            node_name=uname.nodename,
            release=uname.release,
            machine=uname.machine
        ).dump()
