#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common exporters
"""

from faas_profiler_python.exporters import Exporter


class Console(Exporter):
    """
    Prints results to console
    """

    def export(self, trace_record: dict):
        """
        Prints raw data to std out.
        """
        print(trace_record)
