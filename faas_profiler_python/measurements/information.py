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
    InformationOperatingSystem,
    InformationIsWarm
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


class IsWarm(Measurement):
    """

    """

    WARM_IDENT_FILE = os.path.join(os.path.abspath("/tmp"), "is-warm.txt")

    def initialize(self, *args, **kwargs) -> None:
        self.is_warm = self._is_warm()
        self.warm_since = self._warm_since()
        self.warm_for = self._warm_for()

        self._set_warm()

    def results(self) -> dict:
        return InformationIsWarm(
            is_warm=self.is_warm,
            warm_since=self.warm_since,
            warm_for=self.warm_for
        ).dump()

    def _is_warm(self) -> bool:
        """
        Returns True if function is warm.
        """
        if not os.path.exists(self.WARM_IDENT_FILE):
            return False

        if not os.access(self.WARM_IDENT_FILE, os.R_OK):
            return False

        return True

    def _warm_since(self) -> datetime:
        """
        Returns the datetime since when the function is warm
        """
        if not self._is_warm():
            return None

        warm_since_ts = os.path.getmtime(self.WARM_IDENT_FILE)
        return datetime.fromtimestamp(warm_since_ts)

    def _warm_for(self) -> int:
        """
        Returns the seconds since when the function is warm
        """
        warm_since = self._warm_since()
        if not warm_since:
            return 0

        return (datetime.now() - warm_since).total_seconds()

    def _set_warm(self) -> None:
        """
        Marks the function as warm.
        """
        if self._is_warm():
            return

        try:
            with open(self.WARM_IDENT_FILE, 'a'):
                os.utime(self.WARM_IDENT_FILE, None)
        except Exception as err:
            self.logger.error(f"Could not set function to warm: {err}")
