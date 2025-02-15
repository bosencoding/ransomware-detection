import psutil
from datetime import datetime
import time
from typing import List
from src.core.interfaces.collector import IMetricsCollector
from src.core.models.data_models import ProcessInfo
from src.config.system_whitelist import SystemWhitelist

class ProcessCollector(IMetricsCollector):
    def __init__(self):
        self.cpu_threshold = 80.0  # Naikkan threshold CPUs
        self.memory_threshold = 70.0  # Naikkan threshold Memory
        
    def collect(self) -> List[ProcessInfo]:
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                process_info = proc.info
                process_name = process_info['name']
                
                # Skip proses normal Windows
                if SystemWhitelist.is_windows_normal_process(process_name):
                    continue
                
                # Cek penggunaan CPU/Memory yang tinggi
                if (process_info['cpu_percent'] > self.cpu_threshold or 
                    process_info['memory_percent'] > self.memory_threshold):
                    
                    # Double check untuk memastikan bukan false positive
                    if self._verify_suspicious_behavior(proc):
                        suspicious_processes.append(ProcessInfo(
                            pid=process_info['pid'],
                            name=process_name,
                            cpu_percent=process_info['cpu_percent'],
                            memory_percent=process_info['memory_percent'],
                            created_time=datetime.fromtimestamp(proc.create_time())
                        ))
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return suspicious_processes
    
    def _verify_suspicious_behavior(self, proc) -> bool:
        """Verifikasi tambahan untuk mengurangi false positives"""
        try:
            # Cek durasi proses (skip jika sudah berjalan lama)
            process_age = time.time() - proc.create_time()
            if process_age > 3600:  # Skip jika sudah berjalan > 1 jam
                return False
            
            # Cek parent process
            parent = proc.parent()
            if parent and SystemWhitelist.is_windows_normal_process(parent.name()):
                return False
            
            # Cek command line untuk memastikan legitimate
            cmdline = proc.cmdline()
            if any(legitimate in ' '.join(cmdline).lower() 
                   for legitimate in ['windows', 'microsoft', 'program files']):
                return False
            
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False