# src/config/thresholds.py
import psutil

class SystemThresholds:
    """Konfigurasi threshold untuk metrik sistem dengan toleransi lebih tinggi"""
    
    # CPU thresholds
    CPU_HIGH_THRESHOLD = 95.0        # Threshold tinggi untuk CPU
    CPU_SUSTAINED_PERIOD = 120       # Durasi monitoring dalam detik
    CPU_NORMAL_MAX = 80.0           # Batas normal CPU
    
    # Memory thresholds
    MEMORY_HIGH_THRESHOLD = 90.0     # Threshold tinggi untuk memory
    MEMORY_NORMAL_MAX = 85.0        # Batas normal memory
    
    # Disk I/O thresholds (MB/s)
    DISK_READ_RATE_THRESHOLD = 200.0  # Threshold disk read
    DISK_WRITE_RATE_THRESHOLD = 100.0 # Threshold disk write
    DISK_READ_NORMAL_MAX = 150.0     # Batas normal disk read
    DISK_WRITE_NORMAL_MAX = 75.0     # Batas normal disk write
    
    # File operation thresholds
    FILE_OPS_PER_SECOND = 500       # Operasi file per detik
    FILE_CHANGE_THRESHOLD = 100      # Perubahan file per menit
    FILE_OPS_NORMAL_MAX = 350       # Batas normal operasi file
    
    # Process thresholds
    HIGH_CPU_PROCESS_THRESHOLD = 85.0 # CPU tinggi per proses
    MAX_NEW_PROCESSES = 20           # Maksimum proses baru
    PROCESS_CPU_NORMAL_MAX = 70.0    # Batas normal CPU per proses
    
    # Browser-specific whitelist
    BROWSER_PROCESSES = {
        'chrome.exe',
        'firefox.exe',
        'msedge.exe',
        'browser_broker.exe',
        'WebViewHost.exe',
        'chrome.exe',
        'opera.exe',
        'brave.exe',
        'vivaldi.exe',
        'iexplore.exe'
    }
    
    # Normal system processes whitelist
    SYSTEM_PROCESSES = {
        'svchost.exe',
        'explorer.exe',
        'searchui.exe',
        'RuntimeBroker.exe',
        'ShellExperienceHost.exe',
        'SearchIndexer.exe',
        'dwm.exe',
        'System',
        'Registry',
        'fontdrvhost.exe',
        'spoolsv.exe',
        'wininit.exe',
        'winlogon.exe',
        'services.exe',
        'lsass.exe',
        'csrss.exe',
        'smss.exe'
    }
    
    @classmethod
    def is_browser_process(cls, process_name: str) -> bool:
        """Cek apakah proses adalah browser"""
        return process_name.lower() in cls.BROWSER_PROCESSES
    
    @classmethod
    def is_system_process(cls, process_name: str) -> bool:
        """Cek apakah proses adalah sistem normal"""
        return process_name.lower() in cls.SYSTEM_PROCESSES