#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module for network measurements:
- NetworkConnections
- NetworkIOCounters
"""

import psutil

from typing import Dict, Set, Type

from faas_profiler_core.models import (
    NetworkConnectionItem,
    NetworkConnections,
    NetworkIOCounters
)
from faas_profiler_python.measurements import Measurement, PeriodicMeasurement


class Connections(PeriodicMeasurement):

    def initialize(
        self,
        function_pid: int = None,
        **kwargs
    ) -> None:
        self.process = None

        self._remote_connections: Dict[str, NetworkConnectionItem] = {}
        self._socket_descriptors: Set[int] = set()

        try:
            self.process = psutil.Process(function_pid)
        except psutil.Error as err:
            self._logger.warn(f"Could not set process: {err}")

    def measure(self):
        self._update_connection()

    def deinitialize(self) -> None:
        del self.process

    def results(self) -> dict:
        return NetworkConnections(
            connections=list(self._remote_connections.values())).dump()

    def _update_connection(self):
        if self.process is None:
            return

        for conn in self.process.connections(kind='all'):
            if conn.fd in self._socket_descriptors:
                continue

            _remote_address = getattr(conn, "raddr", None)
            if not _remote_address:
                continue

            _remote_ip = getattr(_remote_address, "ip", None)
            _remote_port = getattr(_remote_address, "port", None)
            if not _remote_ip or not _remote_port:
                continue

            _remote_full_address = "{ip}:{port}".format(
                ip=_remote_ip, port=_remote_port)

            conn_item = self._remote_connections.setdefault(
                _remote_full_address, NetworkConnectionItem(
                    socket_family=conn.family,
                    remote_address=_remote_full_address,
                    number_of_connections=0))

            conn_item.number_of_connections += 1

            self._socket_descriptors.add(conn.fd)


class IOCounters(Measurement):

    def initialize(
        self,
        **kwargs
    ) -> None:
        self._start_snapshot: Type[psutil.snetio] = None
        self._end_snapshot: Type[psutil.snetio] = None

        self._interfaces_counters = []
        self._total_counters = {}

    def start(self) -> None:
        self._start_snapshot = psutil.net_io_counters(pernic=False)

    def stop(self) -> None:
        self._end_snapshot = psutil.net_io_counters(pernic=False)

    def results(self) -> dict:
        return get_snapshot_io_delta(
            self._start_snapshot,
            self._end_snapshot
        ).dump()


def get_snapshot_io_delta(
    start_snapshot: Type[psutil._common.snetio],
    end_snapshot: Type[psutil._common.snetio]
) -> Type[NetworkIOCounters]:
    return NetworkIOCounters(
        bytes_sent=int(end_snapshot.bytes_sent - start_snapshot.bytes_sent),
        bytes_received=int(end_snapshot.bytes_recv - start_snapshot.bytes_recv),
        packets_sent=int(end_snapshot.packets_sent - start_snapshot.packets_sent),
        packets_received=int(end_snapshot.packets_recv - start_snapshot.packets_recv),
        error_in=int(end_snapshot.errin - start_snapshot.errin),
        error_out=int(end_snapshot.errout - start_snapshot.errout),
        drop_in=int(end_snapshot.dropin - start_snapshot.dropin),
        drop_out=int(end_snapshot.dropout - start_snapshot.dropout))
