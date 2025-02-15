import psutil
from datetime import datetime
import logging
from typing import Dict, Any
from src.core.interfaces.collector import IMetricsCollector
from src.core.models.data_models import SystemMetrics
import time

class SystemMetricsCollector(IMetricsCollector):
    def __init__(self):
        self.last_read_bytes = 0
        self.last_write_bytes = 0
        self.last_time = time.time()

    def collect(self) -> SystemMetrics:
        """Monitor metrics dengan I/O rate per detik"""
        try:
            current_time = time.time()
            disk_io = psutil.disk_io_counters()
            
            # Hitung waktu sejak pengukuran terakhir
            time_delta = current_time - self.last_time
            
            # Hitung I/O rate per detik
            read_rate = (disk_io.read_bytes - self.last_read_bytes) / time_delta if time_delta > 0 else 0
            write_rate = (disk_io.write_bytes - self.last_write_bytes) / time_delta if time_delta > 0 else 0
            
            # Update nilai terakhir untuk pengukuran berikutnya
            self.last_read_bytes = disk_io.read_bytes
            self.last_write_bytes = disk_io.write_bytes
            self.last_time = current_time
            
            # Konversi ke MB/s
            read_rate_mbs = read_rate / (1024 * 1024)
            disk_write_rate = write_rate / (1024 * 1024)
            
            # Tampilkan untuk debugging
            print(f"Debug - Read Rate: {read_rate_mbs:.2f} MB/s, Write Rate: {disk_write_rate:.2f} MB/s")
            
            return SystemMetrics(
                cpu_percent=psutil.cpu_percent(interval=1),
                memory_percent=psutil.virtual_memory().percent,
                disk_read_rate=read_rate_mbs,    # Rate dalam MB/s
                disk_write_rate=disk_write_rate,  # Rate dalam MB/s
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logging.error(f"Error collecting system metrics: {str(e)}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                disk_read_rate=0.0,
                disk_write_rate=0.0,
                timestamp=datetime.now()
            )

    # def __init__(self):
    #     """Inisialisasi collector dengan atribut tracking"""
    #     # Inisialisasi nilai awal untuk tracking I/O
    #     self.last_check_time = datetime.now()
    #     self.last_read_bytes = 0
    #     self.last_write_bytes = 0
        
    #     # Get initial values
    #     try:
    #         disk_io = psutil.disk_io_counters()
    #         if disk_io:
    #             self.last_read_bytes = disk_io.read_bytes
    #             self.last_write_bytes = disk_io.write_bytes
    #     except Exception as e:
    #         logging.warning(f"Could not get initial disk I/O values: {e}")

    # def collect(self) -> SystemMetrics:
    #     """Monitor detail aktivitas sistem"""
    #     try:
    #         # Get disk I/O counters
    #         disk_io = psutil.disk_io_counters()
    #         current_time = datetime.now()
            
    #         # Hitung I/O rate
    #         time_delta = (current_time - self.last_check_time).total_seconds()
    #         if time_delta > 0 and disk_io:
    #             read_rate = (disk_io.read_bytes - self.last_read_bytes) / time_delta
    #             write_rate = (disk_io.write_bytes - self.last_write_bytes) / time_delta
    #         else:
    #             read_rate = 0
    #             write_rate = 0

    #         # Update nilai terakhir
    #         if disk_io:
    #             self.last_read_bytes = disk_io.read_bytes
    #             self.last_write_bytes = disk_io.write_bytes
    #         self.last_check_time = current_time

    #         return SystemMetrics(
    #             cpu_percent=psutil.cpu_percent(interval=1),
    #             memory_percent=psutil.virtual_memory().percent,
    #             disk_read_bytes=disk_io.read_bytes if disk_io else 0,
    #             disk_write_bytes=disk_io.write_bytes if disk_io else 0,
    #             disk_read_rate=read_rate,
    #             disk_write_rate=write_rate,
    #             disk_read_count=disk_io.read_count if disk_io else 0,
    #             disk_write_count=disk_io.write_count if disk_io else 0,
    #             disk_busy_time=disk_io.busy_time if (disk_io and hasattr(disk_io, 'busy_time')) else 0,
    #             timestamp=current_time
    #         )
    #     except Exception as e:
    #         logging.error(f"Error collecting system metrics: {str(e)}")
    #         return SystemMetrics(
    #             cpu_percent=0.0,
    #             memory_percent=0.0,
    #             disk_read_bytes=0,
    #             disk_write_bytes=0,
    #             disk_read_rate=0,
    #             disk_write_rate=0,
    #             disk_read_count=0,
    #             disk_write_count=0,
    #             disk_busy_time=0,
    #             timestamp=datetime.now()
    #         )

    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'last_check_time': self.last_check_time,
            'last_read_bytes': self.last_read_bytes,
            'last_write_bytes': self.last_write_bytes
        }