# src/detectors/ransomware_detector.py
from typing import List, Dict, Any
from datetime import datetime
import numpy as np
import logging
import time

from src.core.interfaces.collector import IMetricsCollector
from src.core.interfaces.analyzer import IAnalyzer
from src.core.interfaces.storage import IStorage
from src.core.models.data_models import DetectionResult, SystemMetrics, FileActivity, ProcessInfo

# Import collectors untuk type checking
from src.collectors.system_collector import SystemMetricsCollector
from src.collectors.file_collector import FileActivityCollector
from src.collectors.process_collector import ProcessCollector
from src.config.thresholds import SystemThresholds

class RansomwareDetector:
    def __init__(
        self,
        collectors: List[IMetricsCollector],
        analyzer: IAnalyzer,
        storage: IStorage
    ):
        self.collectors = collectors
        self.analyzer = analyzer
        self.storage = storage
        self.is_trained = False
        
        self.logger = logging.getLogger('detector')
        self.logger.setLevel(logging.INFO)
        self.last_alert_time = None
        self.alert_cooldown = 300 


    def _analyze_process_behavior(self, processes: List[ProcessInfo]) -> Dict[str, Any]:
        """Analisis perilaku proses dengan konteks aktivitas"""
        process_patterns = {
            'high_cpu_usage': [],
            'high_memory_usage': [],
            'suspicious_processes': []
        }
        
        browser_detected = False
        total_browser_cpu = 0
        
        # First pass: detect browsers and calculate total browser CPU
        for process in processes:
            if SystemThresholds.is_browser_process(process.name):
                browser_detected = True
                total_browser_cpu += process.cpu_percent
        
        # Adjust thresholds based on browser activity
        cpu_threshold = (
            SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD * 1.2 
            if browser_detected else 
            SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD
        )
        
        memory_threshold = (
            SystemThresholds.MEMORY_HIGH_THRESHOLD * 1.2
            if browser_detected else
            SystemThresholds.MEMORY_HIGH_THRESHOLD
        )
        
        # Second pass: analyze all processes with adjusted thresholds
        for process in processes:
            # Skip whitelisted processes
            if SystemThresholds.is_system_process(process.name):
                continue
            
            # Skip browser processes if they're not using excessive resources
            if SystemThresholds.is_browser_process(process.name):
                if process.cpu_percent <= cpu_threshold * 1.5:  # Allow higher CPU for browsers
                    continue
            
            # Check for high resource usage
            if process.cpu_percent > cpu_threshold:
                process_patterns['high_cpu_usage'].append({
                    'name': process.name,
                    'pid': process.pid,
                    'cpu_percent': process.cpu_percent
                })
            
            if process.memory_percent > memory_threshold:
                process_patterns['high_memory_usage'].append({
                    'name': process.name,
                    'pid': process.pid,
                    'memory_percent': process.memory_percent
                })
        
        return process_patterns

    def _calculate_anomaly_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate adjusted anomaly score based on context"""
        base_score = metrics.get('anomaly_score', 0)
        adjustment_factor = 1.0
        
        # Check for browser activity
        browser_active = any(
            SystemThresholds.is_browser_process(p.name) 
            for p in metrics.get('processes', [])
        )
        
        if browser_active:
            # Reduce sensitivity for browser activity
            adjustment_factor *= 0.7
        
        # Check for system updates or maintenance
        system_maintenance = any(
            p.name.lower() in ['wuauclt.exe', 'trustedinstaller.exe'] 
            for p in metrics.get('processes', [])
        )
        
        if system_maintenance:
            # Reduce sensitivity further for system maintenance
            adjustment_factor *= 0.8
        
        # Adjust based on time of day (reduce sensitivity during working hours)
        current_hour = datetime.now().hour
        if 8 <= current_hour <= 18:  # Working hours
            adjustment_factor *= 0.9
        
        return base_score * adjustment_factor

    def _create_feature_vector(self, metrics: Dict[str, Any]) -> np.ndarray:
        """
        Membuat feature vector dari metrics.
        
        Args:
            metrics: Dictionary berisi metrics dari collectors
            
        Returns:
            numpy.ndarray: Feature vector untuk analisis dalam format 2D array
        """
        try:
            features = [
                metrics['system'].cpu_percent,
                metrics['system'].memory_percent,
                metrics['system'].disk_read_bytes,
                metrics['system'].disk_write_bytes,
                len(metrics.get('files', [])),
                len([p for p in metrics.get('processes', []) 
                    if getattr(p, 'cpu_percent', 0) > SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD])
            ]
            
            # Reshape ke 2D array (1 x n_features)
            return np.array(features).reshape(1, -1)

        except Exception as e:
            self.logger.error(f"Error creating feature vector: {str(e)}")
            raise
    
    def _collect_all_metrics(self) -> Dict[str, Any]:
        """
        Mengumpulkan semua metrics dari collectors yang terdaftar.
        
        Returns:
            Dict berisi metrics dari semua collectors
        """
        metrics = {}
        try:
            for collector in self.collectors:
                collector_name = type(collector).__name__.lower()
                metrics_data = collector.collect()
                
                # Kategorikan metrics berdasarkan tipe collector
                if isinstance(collector, SystemMetricsCollector):
                    metrics['system'] = metrics_data
                elif isinstance(collector, FileActivityCollector):
                    metrics['files'] = metrics_data
                elif isinstance(collector, ProcessCollector):
                    metrics['processes'] = metrics_data
                else:
                    metrics[collector_name] = metrics_data
                    
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {str(e)}")
            raise
            
    def detect(self) -> DetectionResult:
        """Melakukan deteksi anomali dengan cooldown period"""
        if not self.is_trained:
            raise ValueError("Detector belum dilatih!")
            
        try:
            current_metrics = self._collect_all_metrics()
            feature_vector = self._create_feature_vector(current_metrics)
            analysis_result = self.analyzer.analyze(feature_vector)
            
            # Apply context-aware anomaly detection
            is_anomaly = analysis_result['is_anomaly']
            if is_anomaly:
                current_time = datetime.now()
                
                # Check cooldown period
                if hasattr(self, 'last_alert_time') and self.last_alert_time:
                    time_since_last_alert = (current_time - self.last_alert_time).total_seconds()
                    if time_since_last_alert < self.alert_cooldown:
                        is_anomaly = False  # Suppress alert during cooldown
                
                # Adjust score based on context
                adjusted_score = self._calculate_anomaly_score(analysis_result)
                
                # Update last alert time if still anomalous
                if is_anomaly:
                    self.last_alert_time = current_time
                    analysis_result['anomaly_score'] = adjusted_score
            
            return DetectionResult(
                is_anomaly=is_anomaly,
                score=analysis_result['anomaly_score'],
                metrics=current_metrics['system'],
                file_activities=current_metrics.get('files', []),
                suspicious_processes=current_metrics.get('processes', []),
                timestamp=datetime.now(),
                details={
                    **analysis_result,
                    'context_information': {
                        'browser_activity': any(
                            SystemThresholds.is_browser_process(p.name) 
                            for p in current_metrics.get('processes', [])
                        ),
                        'system_maintenance': any(
                            p.name.lower() in ['wuauclt.exe', 'trustedinstaller.exe'] 
                            for p in current_metrics.get('processes', [])
                        ),
                        'time_of_day': datetime.now().hour
                    }
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error during detection: {str(e)}")
            raise

    def train(self, duration_seconds: int = 3600) -> None:
        """
        Melatih detector dengan data normal.
        """
        training_data = []
        start_time = datetime.now()
        
        print(f"\nMemulai pengumpulan data training untuk {duration_seconds} detik...")
        
        try:
            while (datetime.now() - start_time).total_seconds() < duration_seconds:
                metrics = self._collect_all_metrics()
                # Feature vector sudah dalam format 2D tetapi kita ambil row-nya saja
                feature_vector = self._create_feature_vector(metrics)[0]
                training_data.append(feature_vector)
                self.storage.save_metrics(metrics)
                print(".", end="", flush=True)
                time.sleep(1)
            
            # Convert list of features ke 2D numpy array
            training_array = np.array(training_data)
            
            print("\nMelatih model...")
            self.analyzer.train(training_array)
            
            metadata = {
                'start_time': start_time.isoformat(),
                'duration_seconds': duration_seconds,
                'samples_collected': len(training_data),
                'features_shape': training_array.shape,
                'timestamp': datetime.now().isoformat()
            }
            
            self.storage.save_training_data(training_array, metadata)
            self.storage.save_model(self.analyzer, "model_latest.joblib")
            
            self.is_trained = True
            print("Training selesai!")
            self.logger.info("Model training completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during training: {str(e)}")
            raise
            
    def get_status(self) -> Dict[str, Any]:
        """
        Mendapatkan status current dari detector
        
        Returns:
            Dictionary berisi status detector
        """
        return {
            'is_trained': self.is_trained,
            'collectors_count': len(self.collectors),
            'collector_types': [type(c).__name__ for c in self.collectors],
            'timestamp': datetime.now().isoformat()
        }

