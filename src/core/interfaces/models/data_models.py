from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

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
class FileActivity:
    """Model data untuk aktivitas file"""
    path: str
    operation: str
    timestamp: datetime
    size: int
    extension: str

@dataclass
class ProcessInfo:
    """Model data untuk informasi proses"""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    created_time: datetime

@dataclass
class DetectionResult:
    """Model data untuk hasil deteksi"""
    is_anomaly: bool
    score: float
    metrics: SystemMetrics
    file_activities: List[FileActivity]
    suspicious_processes: List[ProcessInfo]
    timestamp: datetime
    details: Dict[str, Any]
