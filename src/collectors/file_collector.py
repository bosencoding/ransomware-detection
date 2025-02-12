# src/collectors/file_collector.py
import os
from datetime import datetime
from typing import List
from src.core.interfaces.collector import IMetricsCollector
from src.core.models.data_models import FileActivity
import logging

class FileActivityCollector(IMetricsCollector):
    def __init__(self, monitored_path: str):
        self.monitored_path = monitored_path
        self.last_check = {}  # Untuk tracking perubahan file
    
    def collect(self) -> List[FileActivity]:
        activities = []
        try:
            for root, _, files in os.walk(self.monitored_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    try:
                        stats = os.stat(file_path)
                        current_time = datetime.now()
                        
                        # Get file extension
                        _, extension = os.path.splitext(filename)
                        
                        # Check if file was modified since last check
                        last_modified = datetime.fromtimestamp(stats.st_mtime)
                        if (file_path in self.last_check and 
                            last_modified > self.last_check[file_path]):
                            operation = 'write'
                        else:
                            operation = 'read'
                        
                        # Create FileActivity object
                        activity = FileActivity(
                            path=file_path,
                            operation=operation,
                            timestamp=current_time,
                            size=stats.st_size,
                            extension=extension,
                            original_extension=extension,
                            process_id=None,  # Would need additional system calls to get this
                            process_name=None,
                            is_suspicious=self._is_suspicious_activity(
                                file_path, stats, extension
                            )
                        )
                        
                        activities.append(activity)
                        self.last_check[file_path] = current_time
                        
                    except (PermissionError, FileNotFoundError):
                        continue
                        
        except Exception as e:
            logging.error(f"Error collecting file activities: {e}")
            
        return activities
    
    def _is_suspicious_activity(self, file_path: str, stats, extension: str) -> bool:
        """Check if file activity is suspicious"""
        # Check for suspicious extensions
        suspicious_extensions = ['.encrypted', '.locked', '.crypto', '.crypted', '.crypt']
        if extension.lower() in suspicious_extensions:
            return True
            
        # Check for rapid modifications
        last_modified = datetime.fromtimestamp(stats.st_mtime)
        if (file_path in self.last_check and 
            (datetime.now() - last_modified).total_seconds() < 1):
            return True
            
        # Check sensitive paths
        sensitive_paths = ['\\Windows\\', '\\Program Files\\', '\\Users\\']
        if any(path in file_path for path in sensitive_paths):
            return True
            
        return False