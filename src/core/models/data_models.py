# src/core/models/data_models.py
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional

@dataclass
class FileActivity:
    """Data model untuk aktivitas file"""
    path: str
    operation: str   # 'read', 'write', 'delete', 'rename'
    timestamp: datetime
    size: int
    extension: str
    original_extension: Optional[str] = None  # Untuk tracking perubahan ekstensi
    checksum: Optional[str] = None           # Untuk tracking perubahan konten
    process_id: Optional[int] = None         # PID proses yang melakukan operasi
    process_name: Optional[str] = None       # Nama proses yang melakukan operasi
    is_suspicious: bool = False

# @dataclass
# class SystemMetrics:
#     """Data model untuk metrik sistem"""
#     cpu_percent: float
#     memory_percent: float
#     disk_read_bytes: int
#     disk_write_bytes: int
#     disk_read_rate: float
#     disk_write_rate: float
#     timestamp: datetime

@dataclass
class ProcessInfo:
    """Data model untuk informasi proses"""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    created_time: datetime
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None


    
@dataclass
class SystemMetrics:
    """Model data untuk metrik sistem"""
    cpu_percent: float
    memory_percent: float
    disk_read_bytes: int
    disk_write_bytes: int
    disk_read_rate: float
    disk_write_rate: float
    disk_read_count: int
    disk_write_count: int
    disk_busy_time: int
    timestamp: datetime

@dataclass
class NetworkMetrics:
    """Model data untuk metrik jaringan"""
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    send_rate_kb: float
    recv_rate_kb: float
    timestamp: datetime

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkMetrics':
        """Membuat instance NetworkMetrics dari dictionary"""
        return cls(
            bytes_sent=data.get('bytes_sent', 0),
            bytes_recv=data.get('bytes_recv', 0),
            packets_sent=data.get('packets_sent', 0),
            packets_recv=data.get('packets_recv', 0),
            send_rate_kb=data.get('send_rate_kb', 0.0),
            recv_rate_kb=data.get('recv_rate_kb', 0.0),
            timestamp=data.get('timestamp', datetime.now())
        )
    
@dataclass
class DetectionResult:
    """Data model untuk hasil deteksi"""
    is_anomaly: bool
    score: float
    metrics: SystemMetrics
    # network_metrics: NetworkMetrics
    file_activities: List[FileActivity]
    suspicious_processes: List[ProcessInfo]
    # active_network_processes: List[ProcessInfo]  # Tambahkan ini
    timestamp: datetime
    details: Dict[str, Any]