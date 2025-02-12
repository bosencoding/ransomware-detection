# src/config/system_whitelist.py
class SystemWhitelist:
    """Whitelist untuk proses normal Windows"""
    
    # Proses Windows yang normal memiliki penggunaan CPU/Memory tinggi
    WINDOWS_NORMAL_PROCESSES = {
        'svchost.exe',      # Windows Service Host
        'csrss.exe',        # Client Server Runtime Process
        'explorer.exe',     # Windows Explorer
        'winlogon.exe',     # Windows Logon
        'spoolsv.exe',      # Print Spooler
        'lsass.exe',        # Windows Security
        'dwm.exe',          # Desktop Window Manager
        'RuntimeBroker.exe',# Runtime Broker
        'SearchUI.exe',     # Windows Search
        'taskhostw.exe',    # Task Host
        'System',           # Windows System
        'Registry',         # Windows Registry
        'fontdrvhost.exe',  # Font Driver Host
        'WmiPrvSE.exe',     # WMI Provider Host
        'SearchIndexer.exe',# Windows Search Indexer
        'MsMpEng.exe',      # Windows Defender
        'WindowsDefender.exe',
        'SecurityHealthService.exe'
    }

    # Proses yang boleh mengakses disk secara intensif
    HIGH_DISK_PROCESSES = {
        'SearchIndexer.exe',
        'MsMpEng.exe',      # Windows Defender scanning
        'svchost.exe',      # Windows Update
        'System',           # System processes
    }

    """Whitelist untuk proses normal"""
    
    # Proses browser yang normal
    BROWSER_PROCESSES = {
        'chrome.exe',
        'firefox.exe',
        'msedge.exe',
        'iexplore.exe',
        'opera.exe',
        'browser_broker.exe',
        'WebViewHost.exe'
    }
    
    # Proses Microsoft Office
    OFFICE_PROCESSES = {
        'WINWORD.EXE',     # Microsoft Word
        'EXCEL.EXE',       # Microsoft Excel
        'POWERPNT.EXE',    # Microsoft PowerPoint
        'OUTLOOK.EXE',     # Microsoft Outlook
        'ONENOTE.EXE',     # Microsoft OneNote
        'MSACCESS.EXE',    # Microsoft Access
        'MSPUB.EXE',       # Microsoft Publisher
        'OneDrive.exe'     # OneDrive sync
    }
    
    # Remote Access Tools
    REMOTE_ACCESS_PROCESSES = {
        'putty.exe',
        'pageant.exe',
        'plink.exe',
        'pscp.exe',
        'kitty.exe',
        'winscp.exe'
    }
    
    # Network Rate Thresholds per aplikasi (KB/s)
    NETWORK_THRESHOLDS = {
        'BROWSER': {
            'upload': 5000,    # 5 MB/s
            'download': 10000  # 10 MB/s
        },
        'OFFICE': {
            'upload': 2000,    # 2 MB/s
            'download': 5000   # 5 MB/s
        },
        'REMOTE': {
            'upload': 1000,    # 1 MB/s
            'download': 1000   # 1 MB/s
        }
    }

    @staticmethod
    def is_whitelisted_process(process_name: str) -> bool:
        """Cek apakah proses ada dalam whitelist"""
        return (process_name in SystemWhitelist.BROWSER_PROCESSES or
                process_name in SystemWhitelist.OFFICE_PROCESSES or
                process_name in SystemWhitelist.REMOTE_ACCESS_PROCESSES)

    @staticmethod
    def get_network_threshold(process_name: str) -> dict:
        """Dapatkan threshold network untuk proses tertentu"""
        if process_name in SystemWhitelist.BROWSER_PROCESSES:
            return SystemWhitelist.NETWORK_THRESHOLDS['BROWSER']
        elif process_name in SystemWhitelist.OFFICE_PROCESSES:
            return SystemWhitelist.NETWORK_THRESHOLDS['OFFICE']
        elif process_name in SystemWhitelist.REMOTE_ACCESS_PROCESSES:
            return SystemWhitelist.NETWORK_THRESHOLDS['REMOTE']
        return {'upload': 500, 'download': 500}  # Default threshold
    
    @staticmethod
    def is_windows_normal_process(process_name: str) -> bool:
        """Cek apakah proses adalah proses normal Windows"""
        return process_name in SystemWhitelist.WINDOWS_NORMAL_PROCESSES

    @staticmethod
    def is_allowed_high_disk_usage(process_name: str) -> bool:
        """Cek apakah proses boleh menggunakan disk tinggi"""
        return process_name in SystemWhitelist.HIGH_DISK_PROCESSES