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
        # Tambahkan baseline statistics
        self.baseline_mean = 0
        self.baseline_std = 0
        self.baseline_scores = []
        self.warm_up_period = 10  # Warm up 10 detik
        self.start_time = datetime.now()
        
        


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
        adjustment_factor = 0.7
        
        # Check for browser activity
        browser_active = any(
            SystemThresholds.is_browser_process(p.name) 
            for p in metrics.get('processes', [])
        )
        
        if browser_active:
            # Reduce sensitivity for browser activity
            adjustment_factor *= 0.1

        # Check for system updates or maintenance
        system_maintenance = any(
            p.name.lower() in ['wuauclt.exe', 'trustedinstaller.exe'] 
            for p in metrics.get('processes', [])
        )
        
        if system_maintenance:
            # Reduce sensitivity further for system maintenance
            adjustment_factor *= 0.4
        
        # Adjust based on time of day (reduce sensitivity during working hours)
        current_hour = datetime.now().hour
        if 6 <= current_hour <= 23:  # Working hours
            adjustment_factor *= 0.2
        
        return base_score * adjustment_factor
    
    def _create_feature_vector(self, metrics: Dict[str, Any]) -> np.ndarray:
        """Create feature vector dari metrics"""
        try:
            features = [
                float(metrics['system'].cpu_percent),
                float(metrics['system'].memory_percent),
                float(metrics['system'].disk_read_rate),   # Gunakan disk_read_rate
                float(metrics['system'].disk_write_rate),  # Gunakan disk_write_rate
                float(len(metrics.get('files', []))),
                float(len([p for p in metrics.get('processes', []) 
                        if hasattr(p, 'cpu_percent') and p.cpu_percent > SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD]))
            ]
            
            return np.array(features, dtype=np.float64).reshape(1, -1)
            
        except Exception as e:
            self.logger.error(f"Error creating feature vector: {str(e)}")
            raise
    
    # def _create_feature_vector(self, metrics: Dict[str, Any]) -> np.ndarray:
    #     """Create feature vector dari metrics"""
    #     try:
    #         # Untuk SystemMetrics object, akses langsung atributnya
    #         if hasattr(metrics['system'], 'cpu_percent'):
    #             # Jika metrics['system'] adalah SystemMetrics object
    #             system_metrics = metrics['system']
    #             features = [
    #                 float(system_metrics.cpu_percent),
    #                 float(system_metrics.memory_percent),
    #                 float(system_metrics.disk_read_bytes),
    #                 float(system_metrics.disk_write_bytes),
    #                 float(len(metrics.get('files', []))),
    #                 float(len([p for p in metrics.get('processes', []) 
    #                         if getattr(p, 'cpu_percent', 0) > SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD]))
    #             ]
    #         else:
    #             # Jika metrics['system'] adalah dictionary (dari JSON)
    #             system_metrics = metrics['system']
    #             features = [
    #                 float(system_metrics.get('cpu_percent', 0)),
    #                 float(system_metrics.get('memory_percent', 0)),
    #                 float(system_metrics.get('disk_read_bytes', 0)),
    #                 float(system_metrics.get('disk_write_bytes', 0)),
    #                 float(len(metrics.get('files', []))),
    #                 float(len([p for p in metrics.get('processes', []) 
    #                         if float(p.get('cpu_percent', 0)) > SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD]))
    #             ]

    #         self.logger.debug(f"Created feature vector: {features}")
    #         return np.array(features, dtype=np.float64).reshape(1, -1)
            
    #     except Exception as e:
    #         self.logger.error(f"Error creating feature vector: {str(e)}")
    #         self.logger.error(f"Metrics type: {type(metrics)}")
    #         self.logger.error(f"System metrics type: {type(metrics.get('system'))}")
    #         raise
    # def _create_feature_vector(self, metrics: Dict[str, Any]) -> np.ndarray:
    #     """
    #     Membuat feature vector dari metrics.
        
    #     Args:
    #         metrics: Dictionary berisi metrics dari collectors
            
    #     Returns:
    #         numpy.ndarray: Feature vector untuk analisis dalam format 2D array
    #     """
    #     try:
    #         features = [
    #             metrics['system'].cpu_percent,
    #             metrics['system'].memory_percent,
    #             metrics['system'].disk_read_bytes,
    #             metrics['system'].disk_write_bytes,
    #             len(metrics.get('files', [])),
    #             len([p for p in metrics.get('processes', []) 
    #                 if getattr(p, 'cpu_percent', 0) > SystemThresholds.HIGH_CPU_PROCESS_THRESHOLD])
    #         ]
            
    #         # Reshape ke 2D array (1 x n_features)
    #         # return np.array(features).reshape(1, -1)
    #         return np.array(features, dtype=np.float64).reshape(1, -1)

    #     except Exception as e:
    #         self.logger.error(f"Error creating feature vector: {str(e)}")
    #         raise
    
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
        
<<<<<<< HEAD
    def detect(self) -> DetectionResult:
=======
    
    def detect(self) -> DetectionResult:
        """Melakukan deteksi anomali dengan pengecekan I/O rate per detik"""
        if not self.analyzer.is_trained:
            raise ValueError("Detector belum dilatih!")
        
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
        try:
            current_metrics = self._collect_all_metrics()
            write_rate = current_metrics['system'].disk_write_rate
            
<<<<<<< HEAD
            # Hitung z-score untuk write rate
            z_score = (write_rate - self.baseline_mean) / self.baseline_std if self.baseline_std > 0 else 0
            
            # Debug print
            print(f"\nDEBUG - Detection Metrics:")
            print(f"Current Write Rate: {write_rate:.2f} MB/s")
            print(f"Baseline Mean: {self.baseline_mean:.2f} MB/s")
            print(f"Baseline Std: {self.baseline_std:.2f} MB/s")
            print(f"Z-Score: {z_score:.2f}")

            # Deteksi anomali berdasarkan threshold atau z-score
            is_anomaly = (write_rate > SystemThresholds.DISK_WRITE_RATE_THRESHOLD or 
                        abs(z_score) > SystemThresholds.ZSCORE_THRESHOLD)
            
            # Hitung anomaly score yang lebih representatif
            # Semakin tinggi write_rate dibanding threshold, semakin tinggi score
            threshold_score = write_rate / SystemThresholds.DISK_WRITE_RATE_THRESHOLD if SystemThresholds.DISK_WRITE_RATE_THRESHOLD > 0 else 0
            zscore_score = abs(z_score) / SystemThresholds.ZSCORE_THRESHOLD if SystemThresholds.ZSCORE_THRESHOLD > 0 else 0
            
            # Ambil nilai maksimum dari kedua score
            normalized_score = max(threshold_score, zscore_score)
            
            # Debug print
            print(f"DEBUG - Scores:")
            print(f"Threshold Score: {threshold_score:.2f}")
            print(f"Z-Score Score: {zscore_score:.2f}")
            print(f"Final Score: {normalized_score:.2f}")

            analysis_result = {
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'details': {
                    'write_rate': write_rate,
                    'baseline_mean': self.baseline_mean,
                    'baseline_std': self.baseline_std,
                    'z_score': z_score,
                    'threshold_score': threshold_score,
                    'zscore_score': zscore_score
                }
            }

            return DetectionResult(
                is_anomaly=is_anomaly,
                score=normalized_score,
=======
            # I/O rates dalam MB/s
            write_rate = current_metrics['system'].disk_write_rate
            read_rate = current_metrics['system'].disk_read_rate
            
            # Cek I/O rate
            io_anomaly = False
            io_details = {}
            
            # Cek write rate dengan threshold
            if write_rate > SystemThresholds.DISK_WRITE_RATE_THRESHOLD:
                SystemThresholds.high_io_counter += 1
                if SystemThresholds.high_io_counter >= SystemThresholds.SUSTAINED_IO_DURATION:
                    io_anomaly = True
                    io_details['high_write_rate'] = {
                        'current': write_rate,
                        'threshold': SystemThresholds.DISK_WRITE_RATE_THRESHOLD,
                        'duration': SystemThresholds.high_io_counter
                    }
            else:
                SystemThresholds.high_io_counter = 0
            
            # Analisis model
            feature_vector = self._create_feature_vector(current_metrics)
            analysis_result = self.analyzer.analyze(feature_vector)
            
            # Set is_anomaly berdasarkan IO dan anomaly score
            is_anomaly = io_anomaly or analysis_result['anomaly_score'] < -0.7  # Perbaikan di sini
            
            # Update details
            analysis_result['io_analysis'] = {
                'write_rate': write_rate,
                'read_rate': read_rate,
                'io_anomaly': io_anomaly,
                'io_details': io_details
            }
            
            # Buat objek DetectionResult
            return DetectionResult(
                is_anomaly=is_anomaly,
                score=analysis_result['anomaly_score'],  # Pastikan konsisten dengan key
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
                metrics=current_metrics['system'],
                file_activities=current_metrics.get('files', []),
                suspicious_processes=current_metrics.get('processes', []),
                timestamp=datetime.now(),
                details=analysis_result
            )
        
        except Exception as e:
            self.logger.error(f"Error during detection: {str(e)}")
            self.logger.error(f"Analysis result keys: {analysis_result.keys()}")  # Debug
            raise
    # def detect(self) -> DetectionResult:
    #     """Melakukan deteksi anomali dengan pengecekan I/O rate per detik"""
    #     if not self.analyzer.is_trained:
    #         raise ValueError("Detector belum dilatih!")
        
    #     try:
    #         current_metrics = self._collect_all_metrics()
            
<<<<<<< HEAD
    #         # I/O rates dalam MB/s
    #         write_rate = current_metrics['system'].disk_write_rate
    #         read_rate = current_metrics['system'].disk_read_rate
            
    #         # Debug print
    #         print(f"\nDEBUG - I/O Rates:")
    #         print(f"Write Rate: {write_rate:.2f} MB/s (Threshold: {SystemThresholds.DISK_WRITE_RATE_THRESHOLD} MB/s)")
    #         print(f"High I/O Counter: {SystemThresholds._high_io_counter}")
            
    #         # Cek I/O rate
    #         io_anomaly = False
    #         io_details = {}
            
    #         # Cek write rate dengan threshold
    #         if write_rate > SystemThresholds.DISK_WRITE_RATE_THRESHOLD:
    #             print(f"DEBUG - Write rate above threshold!")
    #             SystemThresholds._high_io_counter += 1
    #             print(f"DEBUG - Counter increased to: {SystemThresholds._high_io_counter}")
                
    #             if SystemThresholds._high_io_counter >= SystemThresholds.SUSTAINED_IO_DURATION:
    #                 print("DEBUG - Sustained high I/O detected!")
    #                 io_anomaly = True
    #                 io_details['high_write_rate'] = {
    #                     'current': write_rate,
    #                     'threshold': SystemThresholds.DISK_WRITE_RATE_THRESHOLD,
    #                     'duration': SystemThresholds._high_io_counter
    #                 }
    #         else:
    #             print("DEBUG - Write rate normal, resetting counter")
    #             SystemThresholds._high_io_counter = 0
            
    #         # Feature vector dan analisis
    #         feature_vector = self._create_feature_vector(current_metrics)
    #         analysis_result = self.analyzer.analyze(feature_vector)
            
    #         # Debug print
    #         print(f"DEBUG - Analysis:")
    #         print(f"IO Anomaly: {io_anomaly}")
    #         print(f"Analysis Score: {analysis_result['anomaly_score']}")
            
    #         # Set is_anomaly berdasarkan IO atau score
    #         is_anomaly = io_anomaly or analysis_result['anomaly_score'] < SystemThresholds.ANOMALY_SCORE_THRESHOLD
            
    #         # Debug print
    #         print(f"DEBUG - Final Decision:")
    #         print(f"Is Anomaly: {is_anomaly}")

    #         # Update details
    #         analysis_result['io_analysis'] = {
    #             'write_rate': write_rate,
    #             'read_rate': read_rate,
    #             'io_anomaly': io_anomaly,
    #             'io_details': io_details
    #         }
            
    #         result = DetectionResult(
    #             is_anomaly=is_anomaly,
    #             score=analysis_result['anomaly_score'],
    #             metrics=current_metrics['system'],
    #             file_activities=current_metrics.get('files', []),
    #             suspicious_processes=current_metrics.get('processes', []),
    #             timestamp=datetime.now(),
    #             details=analysis_result
    #         )
            
    #         return result
            
    #     except Exception as e:
    #         self.logger.error(f"Error during detection: {str(e)}")
    #         raise
        
    # def detect(self) -> DetectionResult:
    #     """Melakukan deteksi anomali dengan pengecekan I/O rate per detik"""
    #     if not self.analyzer.is_trained:
    #         raise ValueError("Detector belum dilatih!")
        
    #     try:
    #         current_metrics = self._collect_all_metrics()
            
=======
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
    #         # I/O rates sudah dalam MB/s
    #         write_rate = current_metrics['system'].disk_write_rate
    #         read_rate = current_metrics['system'].disk_read_rate
            
    #         # Cek I/O rate
    #         io_anomaly = False
    #         io_details = {}
            
    #         # Cek write rate
    #         if write_rate > SystemThresholds.DISK_WRITE_RATE_THRESHOLD:
    #             SystemThresholds.high_io_counter += 1
    #             if SystemThresholds.high_io_counter >= SystemThresholds.SUSTAINED_IO_DURATION:
    #                 io_anomaly = True
    #                 io_details['high_write_rate'] = {
    #                     'current': write_rate,
    #                     'threshold': SystemThresholds.DISK_WRITE_RATE_THRESHOLD,
    #                     'duration': SystemThresholds.high_io_counter
    #                 }
    #         else:
    #             SystemThresholds.high_io_counter = 0

    #         # Analisis model
    #         feature_vector = self._create_feature_vector(current_metrics)
    #         analysis_result = self.analyzer.analyze(feature_vector)
            
    #         # Gabungkan hasil
    #         is_anomaly = analysis_result['is_anomaly'] or io_anomaly
            
    #         # Update details dengan informasi I/O
    #         analysis_result['io_analysis'] = {
    #             'write_rate': write_rate,
    #             'read_rate': read_rate,
    #             'io_anomaly': io_anomaly,
    #             'io_details': io_details
    #         }
            
    #         return DetectionResult(
    #             is_anomaly=is_anomaly,
    #             score=analysis_result['anomaly_score'],
    #             metrics=current_metrics['system'],
    #             file_activities=current_metrics.get('files', []),
    #             suspicious_processes=current_metrics.get('processes', []),
    #             timestamp=datetime.now(),
    #             details=analysis_result
    #         )
            
    #     except Exception as e:
    #         self.logger.error(f"Error during detection: {str(e)}")
    #         raise
    # def detect(self) -> DetectionResult:
        
        # self.logger.debug(f"Analyzer trained status: {self.analyzer.is_trained}")
        # self.logger.debug(f"Detector trained status: {self.is_trained}")
    
        # """Melakukan deteksi anomali dengan cooldown period"""
        # if not self.analyzer.is_trained:
        #     raise ValueError("Detector belum dilatih!")
            
        # try:
        #     current_metrics = self._collect_all_metrics()
            
        #     feature_vector = self._create_feature_vector(current_metrics)
        #     analysis_result = self.analyzer.analyze(feature_vector)
            
        #     # Apply context-aware anomaly detection
        #     is_anomaly = analysis_result['is_anomaly']
        #     if is_anomaly:
        #         current_time = datetime.now()
                
        #         # Check cooldown period
        #         if hasattr(self, 'last_alert_time') and self.last_alert_time:
        #             time_since_last_alert = (current_time - self.last_alert_time).total_seconds()
        #             if time_since_last_alert < self.alert_cooldown:
        #                 is_anomaly = False  # Suppress alert during cooldown
                
        #         # Adjust score based on context
        #         adjusted_score = self._calculate_anomaly_score(analysis_result)
                
        #         # Update last alert time if still anomalous
        #         if is_anomaly:
        #             self.last_alert_time = current_time
        #             analysis_result['anomaly_score'] = adjusted_score
            
        #     return DetectionResult(
        #         is_anomaly=is_anomaly,
        #         score=analysis_result['anomaly_score'],
        #         metrics=current_metrics['system'],
        #         file_activities=current_metrics.get('files', []),
        #         suspicious_processes=current_metrics.get('processes', []),
        #         timestamp=datetime.now(),
        #         details={
        #             **analysis_result,
        #             'context_information': {
        #                 'browser_activity': any(
        #                     SystemThresholds.is_browser_process(p.name) 
        #                     for p in current_metrics.get('processes', [])
        #                 ),
        #                 'system_maintenance': any(
        #                     p.name.lower() in ['wuauclt.exe', 'trustedinstaller.exe'] 
        #                     for p in current_metrics.get('processes', [])
        #                 ),
        #                 'time_of_day': datetime.now().hour
        #             }
        #         }
        #     )
            
        # except Exception as e:
        #     self.logger.error(f"Error during detection: {str(e)}")
        #     raise

    def train(self, duration_seconds: int = 3600) -> None:
        """Training dengan data baseline normal dan menyimpan metrics"""
        training_data = []
        self.baseline_scores = []  # Reset baseline scores
        
        print(f"\nMengumpulkan baseline normal selama {duration_seconds} detik...")
        start_time = datetime.now()
        
        try:
            # Buat direktori untuk metrics jika belum ada
            metrics_dir = os.path.join(self.data_dir, "metrics")
            os.makedirs(metrics_dir, exist_ok=True)
            
            metrics_file = os.path.join(metrics_dir, f"training_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            all_metrics = []  # List untuk menyimpan semua metrics
            
            while (datetime.now() - start_time).total_seconds() < duration_seconds:
                current_metrics = self._collect_all_metrics()
                
                # Simpan data aktivitas normal untuk baseline
                write_rate = current_metrics['system'].disk_write_rate
                read_rate = current_metrics['system'].disk_read_rate
                
                # Konversi metrics ke format yang bisa di-serialize ke JSON
                metrics_to_save = {
                    'timestamp': datetime.now().isoformat(),
                    'system': {
                        'cpu_percent': current_metrics['system'].cpu_percent,
                        'memory_percent': current_metrics['system'].memory_percent,
                        'disk_write_rate': write_rate,
                        'disk_read_rate': read_rate
                    },
                    'files': [{'path': f.path, 'operation': f.operation, 
                            'timestamp': f.timestamp.isoformat()} 
                            for f in current_metrics.get('files', [])],
                    'processes': [{'name': p.name, 'pid': p.pid, 
                                'cpu_percent': p.cpu_percent} 
                                for p in current_metrics.get('processes', [])]
                }
                
                all_metrics.append(metrics_to_save)
                
                # Hanya ambil data normal untuk training
                if (write_rate < SystemThresholds.DISK_WRITE_RATE_THRESHOLD and 
                    read_rate < SystemThresholds.DISK_READ_RATE_THRESHOLD):
                    feature_vector = self._create_feature_vector(current_metrics)
                    training_data.append(feature_vector[0])
                    self.baseline_scores.append({
                        'write_rate': write_rate,
                        'read_rate': read_rate
                    })
                
                print(".", end="", flush=True)
                time.sleep(1)
            
            # Simpan semua metrics ke file JSON
            with open(metrics_file, 'w') as f:
                json.dump(all_metrics, f, indent=4)
                
            print(f"\nMetrics training disimpan di: {metrics_file}")
            
            # Proses training seperti biasa
            training_array = np.array(training_data)
            write_rates = [score['write_rate'] for score in self.baseline_scores]
            self.baseline_mean = np.mean(write_rates) if write_rates else 0
            self.baseline_std = np.std(write_rates) if write_rates else 1
            
            print(f"\nBaseline Statistics:")
            print(f"Mean Write Rate: {self.baseline_mean:.2f} MB/s")
            print(f"Std Dev Write Rate: {self.baseline_std:.2f} MB/s")
            print(f"Total metrics collected: {len(all_metrics)}")
            
            # Train model
            self.analyzer.train(training_array)
            self.is_trained = True
            
        except Exception as e:
            print(f"\nError during training: {e}")
            self.logger.error(f"Training error: {str(e)}")
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