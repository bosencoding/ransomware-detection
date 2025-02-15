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
    
<<<<<<< HEAD
    # # Disk I/O thresholds (MB/s)
     # Disk I/O thresholds (MB/s)
    DISK_READ_RATE_THRESHOLD = 12.0   # Read rate yang dianggap tinggi
    DISK_WRITE_RATE_THRESHOLD = 12.0  # Write rate yang dianggap tinggi
    
    # Z-score threshold untuk anomali
    ZSCORE_THRESHOLD = 3.0  # 3 standard deviations
    
    # Score threshold untuk anomali (0-1)
    SCORE_THRESHOLD = 0.5  # 50% dari max score
    
    # Threshold untuk anomali score
    ANOMALY_SCORE_THRESHOLD = -0.7
    
    # Counters sebagai class variable
    _high_io_counter = 0
    # DISK_READ_RATE_THRESHOLD = 20.0  # Threshold disk read
    # DISK_WRITE_RATE_THRESHOLD = 20.0 # Threshold disk write
    # DISK_READ_NORMAL_MAX = 150.0     # Batas normal disk read
    # DISK_WRITE_NORMAL_MAX = 75.0     # Batas normal disk write
    
    # Durasi untuk sustained I/O (dalam detik)
    SUSTAINED_IO_DURATION = 7  # Berapa lama I/O tinggi bertahan
    # ANOMALY_SCORE_THRESHOLD = -0.7 
    # Counter untuk menghitung berapa lama I/O tinggi bertahan
    # high_io_counter = 0
=======
    # Disk I/O thresholds (MB/s)
    DISK_READ_RATE_THRESHOLD = 20.0  # Threshold disk read
    DISK_WRITE_RATE_THRESHOLD = 20.0 # Threshold disk write
    DISK_READ_NORMAL_MAX = 150.0     # Batas normal disk read
    DISK_WRITE_NORMAL_MAX = 75.0     # Batas normal disk write
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
    
    # Durasi untuk sustained I/O (dalam detik)
    SUSTAINED_IO_DURATION = 5  # Berapa lama I/O tinggi bertahan
    ANOMALY_SCORE_THRESHOLD = -0.7 
    # Counter untuk menghitung berapa lama I/O tinggi bertahan
    high_io_counter = 0
    
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
<<<<<<< HEAD
    def get_high_io_counter(cls):
        return cls._high_io_counter
    
    @classmethod
    def increment_high_io_counter(cls):
        cls._high_io_counter += 1
    
    @classmethod
    def reset_high_io_counter(cls):
        cls._high_io_counter = 0
    
    @classmethod
=======
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
    def reset_counters(cls):
        """Reset semua counters"""
        cls.high_io_counter = 0
        
    @classmethod
    def is_browser_process(cls, process_name: str) -> bool:
        """Cek apakah proses adalah browser"""
        return process_name.lower() in cls.BROWSER_PROCESSES
    
    @classmethod
    def is_system_process(cls, process_name: str) -> bool:
        """Cek apakah proses adalah sistem normal"""
        return process_name.lower() in cls.SYSTEM_PROCESSES