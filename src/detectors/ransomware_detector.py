# src/detectors/ransomware_detector.py
from typing import List, Dict, Any
from datetime import datetime
import numpy as np
import logging
import time
import os
import joblib

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
        storage: IStorage,
        data_dir: str = None
    ):
        self.collectors = collectors
        self.analyzer = analyzer
        self.storage = storage
        self.is_trained = False
        self.data_dir = data_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
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
        if 6 <= current_hour <= 23:  # Working hours
            adjustment_factor *= 0.95
        
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
            # return np.array(features).reshape(1, -1)
            return np.array(features, dtype=np.float64).reshape(1, -1)

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
        """Training detector"""
        try:
            training_data = []
            metrics_collection = []
            start_time = datetime.now()
            samples_collected = 0
            
            print(f"\nCollecting training data for {duration_seconds} seconds...")
            
            while (datetime.now() - start_time).total_seconds() < duration_seconds:
                try:
                    metrics = self._collect_all_metrics()
                    metrics_collection.append(metrics) 
                    feature_vector = self._create_feature_vector(metrics)
                    training_data.append(feature_vector[0])  # Ambil array 1D
                    self.storage.save_metrics(metrics)
                    print(".", end="", flush=True)
                    samples_collected += 1
                    if samples_collected % 10 == 0:  # Update setiap 10 sampel
                        elapsed_time = (datetime.now() - start_time).total_seconds()
                        progress = (elapsed_time / duration_seconds) * 100
                        print(f"\rProgress: {progress:.1f}% ({samples_collected} samples)", end="")
                    
                    
                    time.sleep(1)
                except Exception as e:
                    self.logger.error(f"Error collecting sample: {str(e)}")
                    continue
            
            print("\n\nPengumpulan data selesai.")
            print(f"Total sampel terkumpul: {samples_collected}")
            
            # Simpan metrik mentah untuk analisis
            metrics_path = os.path.join(self.data_dir, "training", f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.joblib")
            os.makedirs(os.path.dirname(metrics_path), exist_ok=True)
            joblib.dump(metrics_collection, metrics_path)
            print(f"Metrik mentah disimpan di: {metrics_path}")
            
            # Convert ke numpy array
            training_array = np.array(training_data)
            
            print(f"\nMemulai training model dengan {len(training_data)} sampel...")
            print(f"Shape data training: {training_array.shape}")
            self.analyzer.train(training_array)
            
            # Save model
            model_path = os.path.join(self.data_dir, "models", "model_latest.joblib")
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            self.analyzer.save(model_path)
            
            self.is_trained = True
            print(f"Training completed! Model saved to {model_path}")
            
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

    # def load_saved_model(self, model_path: str) -> bool:
    #     """
    #     Memuat model yang tersimpan dengan validasi.
        
    #     Args:
    #         model_path: Path ke file model joblib
            
    #     Returns:
    #         bool: True jika berhasil, False jika gagal
    #     """
    #     try:
    #         # Dapatkan metrik saat ini untuk validasi
    #         current_metrics = self._collect_all_metrics()
            
    #         # Validasi model dan metrik
    #         is_valid, message, model = validate_model_and_metrics(
    #             model_path, 
    #             current_metrics
    #         )
            
    #         if not is_valid:
    #             self.logger.error(f"Validasi model gagal: {message}")
    #             return False
            
    #         # Model valid, gunakan untuk analyzer
    #         self.analyzer.model = model
    #         self.is_trained = True
    #         self.logger.info("Model berhasil dimuat dan divalidasi")
    #         return True
            
    #     except Exception as e:
    #         self.logger.error(f"Error memuat model: {str(e)}")
    #         return False