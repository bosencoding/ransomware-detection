# src/collectors/network_collector.py
import psutil
from datetime import datetime
from typing import Dict, Any
from src.core.interfaces.collector import IMetricsCollector
import logging
from src.core.models.data_models import NetworkMetrics


class NetworkCollector(IMetricsCollector):
    def __init__(self):
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_time = datetime.now()

    def collect(self) -> NetworkMetrics:
        try:
            network = psutil.net_io_counters()
            current_time = datetime.now()
            
            # Hitung network rate dalam KB/s
            time_delta = (current_time - self.last_time).total_seconds()
            if time_delta > 0:
                send_rate = (network.bytes_sent - self.last_bytes_sent) / time_delta / 1024
                recv_rate = (network.bytes_recv - self.last_bytes_recv) / time_delta / 1024
            else:
                send_rate = 0
                recv_rate = 0

            # Update nilai terakhir
            self.last_bytes_sent = network.bytes_sent
            self.last_bytes_recv = network.bytes_recv
            self.last_time = current_time

            return NetworkMetrics(
                bytes_sent=network.bytes_sent,
                bytes_recv=network.bytes_recv,
                packets_sent=network.packets_sent,
                packets_recv=network.packets_recv,
                send_rate_kb=send_rate,
                recv_rate_kb=recv_rate,
                timestamp=current_time
            )
            
        except Exception as e:
            logging.error(f"Error collecting network metrics: {str(e)}")
            return NetworkMetrics(
                bytes_sent=0,
                bytes_recv=0,
                packets_sent=0,
                packets_recv=0,
                send_rate_kb=0.0,
                recv_rate_kb=0.0,
                timestamp=datetime.now()
            )