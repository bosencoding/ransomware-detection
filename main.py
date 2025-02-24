#!/usr/bin/env python3
"""
Ransomware Detector Main Script
Author: Hany Andriyanto
Version: 1.0.0
"""

import os
import sys
import time
import signal
import logging
import argparse
import json
from datetime import datetime
from typing import List, Dict, Any
import stat

# Import modul sistem
import psutil
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Import dari core models
from src.core.models.data_models import (
    SystemMetrics,
    FileActivity,
    ProcessInfo,
    DetectionResult,
    NetworkMetrics
)

# Import komponen detector
from src.collectors.system_collector import SystemMetricsCollector
from src.collectors.network_collector import NetworkCollector
from src.collectors.file_collector import FileActivityCollector
from src.collectors.process_collector import ProcessCollector
from src.analyzers.isolation_forest import IsolationForestAnalyzer
from src.storage.file_storage import FileStorage
from src.detectors.ransomware_detector import RansomwareDetector
from src.utils.model_validator import ModelValidator
from src.utils.cleanup import DataCleaner
from src.config.thresholds import SystemThresholds

class RansomwareDetectorApp:
    """Kelas utama aplikasi Ransomware Detector"""
    
    def __init__(self):
        self.base_dir = os.path.abspath(os.path.dirname(__file__))
        self.data_dir = os.path.join(self.base_dir, "data")
        self.detector = None
        self.storage = None
        self.is_running = False
        
        # Pastikan direktori data ada
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)
    
    def handle_interrupt(self, signum, frame):
        """Handle interrupt signals (Ctrl+C)"""
        print("\nMenerima sinyal interrupt...")
        self.is_running = False
        print("Menutup aplikasi dengan aman...")
    
    def cleanup_data_folders(self):
        """Membersihkan folder data sebelum memulai"""
        print("\nMemeriksa permission folder...")
        
        # Cek permission di base directory
        base_path = self.base_dir
        data_path = self.data_dir
        
        print(f"Base directory: {base_path}")
        print(f"Data directory: {data_path}")
        
        # Cek apakah directory bisa diakses
        if not os.access(base_path, os.W_OK):
            print(f"WARNING: Tidak memiliki akses write ke {base_path}")
        
        folders_to_clean = ['logs', 'metrics', 'models', 'training']
        
        # Tampilkan full path untuk setiap folder
        for folder in folders_to_clean:
            folder_path = os.path.join(data_path, folder)
            print(f"\nFolder target: {folder_path}")
            if os.path.exists(folder_path):
                print(f"Status: Ada")
                print(f"Write access: {os.access(folder_path, os.W_OK)}")
                try:
                    files = os.listdir(folder_path)
                    print(f"Jumlah file: {len(files)}")
                except Exception as e:
                    print(f"Error mengakses folder: {e}")
            else:
                print("Status: Belum ada")
        
        try:
            print("\nMemulai proses pembersihan...")
            results = DataCleaner.cleanup_folders(self.data_dir, folders_to_clean)
            print("\nProses pembersihan selesai")
            
            # Verifikasi hasil
            for folder in folders_to_clean:
                folder_path = os.path.join(self.data_dir, folder)
                if os.path.exists(folder_path):
                    files = os.listdir(folder_path)
                    print(f"Folder {folder}: {len(files)} file tersisa")
                else:
                    print(f"Folder {folder} tidak ada")
                    
        except Exception as e:
            print(f"Error saat membersihkan folder: {e}")
    
    def setup_logging(self) -> None:
        """Setup sistem logging"""
        log_dir = os.path.join(self.data_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f'detector_{datetime.now().strftime("%Y%m%d")}.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        logging.info("Logging system initialized")
        print(f"Log file: {log_file}")
        
    def train_from_metrics(self, metrics_path: str) -> None:
        """Training model dari data metrik JSON"""
        try:
            print(f"\nMemuat data metrik dari: {metrics_path}")
            
            # Kumpulkan semua file metrik
            metric_files = []
            for root, _, files in os.walk(metrics_path):
                for file in files:
                    if file.endswith('.json'):  # Ubah ke .json
                        metric_files.append(os.path.join(root, file))
            
            if not metric_files:
                print("Tidak ada file metrik JSON ditemukan!")
                return
                
            print(f"Ditemukan {len(metric_files)} file metrik")
            
            # Kumpulkan semua data
            all_metrics = []
            for file in metric_files:
                try:
                    with open(file, 'r') as f:
                        metrics = json.load(f)  # Load JSON
                    if isinstance(metrics, dict):  # Single metric
                        all_metrics.append(metrics)
                    elif isinstance(metrics, list):  # List of metrics
                        all_metrics.extend(metrics)
                    print(f"Berhasil memuat: {file}")
                except Exception as e:
                    print(f"Gagal memuat {file}: {e}")
                    continue
            
            if not all_metrics:
                print("Tidak ada data metrik valid!")
                return
                
            print(f"\nTotal data metrik: {len(all_metrics)}")
            
            # Convert ke feature vectors
            training_data = []
            for metric in all_metrics:
                try:
                    feature_vector = self.detector._create_feature_vector(metric)
                    training_data.append(feature_vector[0])
                except Exception as e:
                    print(f"Gagal memproses metrik: {e}")
                    continue
            
            if not training_data:
                print("Tidak ada data training yang valid!")
                return

            # Convert ke numpy array
            training_array = np.array(training_data)
            print(f"Shape data training: {training_array.shape}")
            
            # Train model
            print("\nMemulai training...")
            self.detector.analyzer.train(training_array)
            
            # Save model
            model_path = os.path.join(self.data_dir, "models", "model_latest.joblib")
            self.detector.analyzer.save(model_path)
            
            print(f"\nTraining selesai! Model disimpan di: {model_path}")
            
            # Simpan rangkuman
            summary = {
                'timestamp': datetime.now().isoformat(),
                'metrics_files': len(metric_files),
                'total_samples': len(all_metrics),
                'valid_samples': len(training_data),
                'features_shape': training_array.shape,
                'model_path': model_path
            }
            
            summary_path = os.path.join(self.data_dir, "training", "training_summary.json")
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=4)
            print(f"Rangkuman training disimpan di: {summary_path}")
            print("\nProses training selesai. Menutup aplikasi...")
            sys.exit(0)  # Keluar dengan status sukses
            
        except Exception as e:
            print(f"Error during training from metrics: {e}")
            raise
    
    def test_model(self, duration_seconds: int = 60) -> None:
        """
        Menjalankan model dalam mode testing
        """
        try:
            print("\nMemulai mode testing...")
            
            # Load model terbaru
            model_path = os.path.join(self.data_dir, "models", "model_latest.joblib")
            if not os.path.exists(model_path):
                print(f"Model tidak ditemukan di: {model_path}")
                return
                
            print(f"Menggunakan model dari: {model_path}")
            
            # Setup detector
            self.setup_logging()
            self.init_components()
            
            # Load model ke analyzer
            try:
                self.detector.analyzer.load(model_path)
                # Verifikasi status
                if not self.detector.analyzer.is_trained:
                    print("Model dimuat tapi status tidak valid")
                    return
                    
                print("Model berhasil dimuat dan siap digunakan")
                
            except Exception as e:
                print(f"Gagal memuat model: {e}")
                return
            
            # Debug info
            print("\nStatus Model:")
            print(f"Analyzer trained: {self.detector.analyzer.is_trained}")
            print(f"N Features: {self.detector.analyzer.n_features}")
            
            # Mulai testing
            start_time = datetime.now()
            detections = []
            
            print(f"\nMenjalankan test selama {duration_seconds} detik...")
            print("Press Ctrl+C to stop")
            
            while (datetime.now() - start_time).total_seconds() < duration_seconds:
                try:
                    result = self.detector.detect()
                    
                    # Simpan hasil deteksi
                    detection_info = {
                        'timestamp': datetime.now().isoformat(),
                        'is_anomaly': result.is_anomaly,
                        'score': result.score,
                        'cpu_percent': result.metrics.cpu_percent,
                        'memory_percent': result.metrics.memory_percent,
                        'disk_read': result.metrics.disk_read_rate,
                        'disk_write': result.metrics.disk_write_rate
                    }
                    detections.append(detection_info)
                    
                    # Print status
                    self.print_status(result)
                    
                    time.sleep(1)  # Check setiap detik
                    
                except KeyboardInterrupt:
                    print("\nTesting dihentikan oleh user")
                    break
                except Exception as e:
                    print(f"Error during testing: {e}")
                    continue
            
            # Kalkulasi statistik dan akurasi
            total_samples = len(detections)
            anomalies = sum(1 for d in detections if d['is_anomaly'])
            normal = total_samples - anomalies
            
            # Hitung rata-rata score untuk threshold
            scores = [d['score'] for d in detections]
            avg_score = np.mean(scores)
            std_score = np.std(scores)
            threshold = avg_score - (2 * std_score)
            
            # Hitung deteksi yang benar
            correct_detections = sum(
                1 for d in detections
                if (d['score'] < threshold) == d['is_anomaly']
            )
            
            accuracy = (correct_detections / total_samples) * 100
            
            # Buat dictionary untuk accuracy analysis
            accuracy_analysis = {
                'total_samples': total_samples,
                'correct_detections': correct_detections,
                'accuracy_percentage': accuracy,
                'threshold_score': threshold,
                'distribution': {
                    'normal_cases': normal,
                    'normal_percentage': (normal/total_samples)*100,
                    'anomaly_cases': anomalies,
                    'anomaly_percentage': (anomalies/total_samples)*100
                }
            }


            # Update test_results dengan accuracy analysis
            test_results = {
                'start_time': start_time.isoformat(),
                'duration': duration_seconds,
                'total_checks': len(detections),
                'anomalies_detected': sum(1 for d in detections if d['is_anomaly']),
                'detections': detections,
                'accuracy_analysis': accuracy_analysis,
                'score_statistics': {
                    'mean': float(avg_score),
                    'std': float(std_score),
                    'min': float(min(scores)),
                    'max': float(max(scores))
                }
            }
            
            results_path = os.path.join(self.data_dir, "testing", 
                                    f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            os.makedirs(os.path.dirname(results_path), exist_ok=True)
            
            # Print rangkuman
            print("\nRingkasan Testing:")
            print(f"Total checks: {test_results['total_checks']}")
            print(f"Anomali terdeteksi: {test_results['anomalies_detected']}")
            print(f"\nAnalisis Akurasi:")
            print(f"Total sampel: {accuracy_analysis['total_samples']}")
            print(f"Deteksi benar: {accuracy_analysis['correct_detections']}")
            print(f"Akurasi: {accuracy_analysis['accuracy_percentage']:.2f}%")
            print(f"Threshold score: {accuracy_analysis['threshold_score']:.3f}")
            print(f"\nDistribusi Hasil:")
            print(f"Kasus normal: {accuracy_analysis['distribution']['normal_cases']} "
                f"({accuracy_analysis['distribution']['normal_percentage']:.2f}%)")
            print(f"Kasus anomali: {accuracy_analysis['distribution']['anomaly_cases']} "
                f"({accuracy_analysis['distribution']['anomaly_percentage']:.2f}%)")
            print(f"\nHasil lengkap disimpan di: {results_path}")
            
            
            
            # Simpan hasil
            with open(results_path, 'w') as f:
                json.dump(test_results, f, indent=4)
                
            print(f"\nHasil lengkap disimpan di: {results_path}")
            
        except Exception as e:
            print(f"Error dalam testing: {e}")
            raise
        
    def init_components(self) -> None:
        """Inisialisasi komponen-komponen detector"""
        try:
            # Inisialisasi storage
            self.storage = FileStorage(base_path=self.data_dir)
            logging.info(f"Storage initialized at {self.data_dir}")
            
            # Inisialisasi collectors
            monitor_path = os.path.expanduser("~")  # Monitor home directory
            system_collector = SystemMetricsCollector()
            file_collector = FileActivityCollector(monitor_path)
            process_collector = ProcessCollector()
            # network_collector = NetworkCollector() 
            
            # collectors = [system_collector, file_collector, process_collector,network_collector]
            collectors = [system_collector, file_collector, process_collector]
            logging.info("Collectors initialized")
            
            # Inisialisasi analyzer
            analyzer = IsolationForestAnalyzer(contamination=0.1)
            logging.info("Analyzer initialized")
            
            # Buat detector
            self.detector = RansomwareDetector(collectors, analyzer, self.storage, data_dir=self.data_dir)
            logging.info("Detector initialized")
            
            
        except Exception as e:
            logging.error(f"Failed to initialize components: {str(e)}")
            raise
    
    # def print_status(self, result: DetectionResult) -> None:
    #     """Menampilkan status deteksi dengan detail"""
    #     os.system('cls' if os.name == 'nt' else 'clear')
    #     print("\nRansomware Detector Status")
    #     print("=" * 50)
    #     print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    #     # System Metrics
    #     print("\n📊 Metrik Sistem:")
    #     print(f"CPU Usage: {result.metrics.cpu_percent:.1f}%")
    #     print(f"Memory Usage: {result.metrics.memory_percent:.1f}%")
        
    #     # Disk I/O
    #     print("\n💾 Storage I/O:")
    #     print(f"Read Rate: {result.metrics.disk_read_rate / 1024:.2f} KB/s")
    #     print(f"Write Rate: {result.metrics.disk_write_rate / 1024:.2f} KB/s")
    #     print(f"Total Read: {result.metrics.disk_read_bytes / 1024:.2f} KB")
    #     print(f"Total Write: {result.metrics.disk_write_bytes / 1024:.2f} KB")
    #     print(f"Read Operations: {result.metrics.disk_read_count} ops")
    #     print(f"Write Operations: {result.metrics.disk_write_count} ops")
        
    #     # Network Activity (hanya informasi)
    #     # if hasattr(result, 'network_metrics') and result.network_metrics is not None:
    #     #     print("\n🌐 Network Activity (monitoring only):")
    #     #     print(f"Upload Rate: {result.network_metrics.send_rate_kb:.2f} KB/s")
    #     #     print(f"Download Rate: {result.network_metrics.recv_rate_kb:.2f} KB/s")
        
    #     # Score dan Status
    #     print(f"\n📈 Score Anomali: {result.score:.3f}")
        
    #     # Info file metrics yang disimpan
    #     metrics_files = len(os.listdir(os.path.join(self.data_dir, "metrics")))
    #     print(f"\nMetrics Tersimpan: {metrics_files} file")
        
    #     if result.is_anomaly:
    #         print("\n⚠️  PERINGATAN: Aktivitas Mencurigakan Terdeteksi!")
            
    #         # Tampilkan detail faktor anomali
    #         if result.details and 'anomaly_factors' in result.details:
    #             print("\nDetail Faktor Anomali:")
    #             for factor in result.details['anomaly_factors']:
    #                 print(f"- {factor}")
                
    #             print("\nRekomendasi:")
    #             print("1. Monitor proses yang menggunakan CPU/Memory tinggi")
    #             print("2. Periksa aktivitas disk yang tidak normal")
    #             print("3. Cek perubahan file yang mencurigakan")
    #     else:
    #         print("✅ Status: Normal")
        
    #     print("\nPress Ctrl+C to stop")
    
    def print_status(self, result: DetectionResult) -> None:
        """Menampilkan status deteksi dengan detail I/O"""
<<<<<<< HEAD
        # os.system('cls' if os.name == 'nt' else 'clear')
=======
        os.system('cls' if os.name == 'nt' else 'clear')
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
        print("\nRansomware Detector Status")
        print("=" * 50)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\nMetrik Sistem:")
        print(f"CPU Usage: {result.metrics.cpu_percent:.1f}%")
        print(f"Memory Usage: {result.metrics.memory_percent:.1f}%")
        
        # Tampilkan I/O rates
         # Tampilkan I/O rates dengan atribut yang benar
        print(f"Disk Write Rate: {result.metrics.disk_write_rate:.2f} MB/s")
        print(f"Disk Read Rate: {result.metrics.disk_read_rate:.2f} MB/s")
        
        if result.is_anomaly:
            print("\n⚠️  PERINGATAN: Aktivitas Mencurigakan Terdeteksi!")
            print(f"Score Anomali: {result.score:.2f}")
            
<<<<<<< HEAD
            # # Tampilkan detail I/O jika anomali
            # if result.details['io_analysis']['io_anomaly']:
            #     io_details = result.details['io_analysis']['io_details']
            #     if 'high_write_rate' in io_details:
            #         print("\nDisk I/O Mencurigakan:")
            #         print(f"Write Rate: {io_details['high_write_rate']['current']:.2f} MB/s")
            #         print(f"Threshold: {io_details['high_write_rate']['threshold']:.2f} MB/s")
            #         print(f"Durasi: {io_details['high_write_rate']['duration']} detik")
=======
            # Tampilkan detail I/O jika anomali
            if result.details['io_analysis']['io_anomaly']:
                io_details = result.details['io_analysis']['io_details']
                if 'high_write_rate' in io_details:
                    print("\nDisk I/O Mencurigakan:")
                    print(f"Write Rate: {io_details['high_write_rate']['current']:.2f} MB/s")
                    print(f"Threshold: {io_details['high_write_rate']['threshold']:.2f} MB/s")
                    print(f"Durasi: {io_details['high_write_rate']['duration']} detik")
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112
        else:
            print("\n✅ Status: Normal")
        
        print("\nPress Ctrl+C to stop")
    
    def run(self, args: argparse.Namespace) -> None:
        """Menjalankan detector"""
        try:
            print("\nInitializing Ransomware Detector...")
            self.setup_logging()
            self.init_components()
            
            print("\nStarting training mode...")
            self.detector.train(duration_seconds=args.training_duration)
            
            print("\nStarting detection mode...")
            self.is_running = True
            
            while self.is_running:
                try:
                    result = self.detector.detect()
                    self.print_status(result)
                    time.sleep(args.interval)
                    
                except Exception as e:
                    logging.error(f"Error during detection: {str(e)}")
                    continue
            
            print("\nShutting down gracefully...")
            logging.info("Application stopped by user")
            
        except Exception as e:
            logging.error(f"Critical error: {str(e)}")
            raise

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Ransomware Zero-Day Attack Detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
     # Grup untuk mode operasi
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--collect-only",
        action="store_true",
        help="Hanya mengumpulkan metrik tanpa training"
    )
    mode_group.add_argument(
        "--train-from-metrics",
        action="store_true",
        help="Training dari data metrik yang sudah ada"
    )
    mode_group.add_argument(
        "--test-model",
        action="store_true",
        help="Jalankan model dalam mode testing"
    )
    # Argumen untuk path
    parser.add_argument(
        "--metrics-path",
        type=str,
        help="Path ke folder metrik untuk training"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        help="Path ke model untuk validasi atau output training"
    )
    
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Hanya validasi model tanpa menjalankan detector"
    )
    
    parser.add_argument(
        "-t", "--training-duration",
        type=int,
        default=300,
        help="Durasi training dalam detik"
    )
    
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=5,
        help="Interval deteksi dalam detik"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Aktifkan mode debug"
    )
    
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Jalankan tanpa membersihkan folder"
    )
    
    parser.add_argument(
        "--test-duration",
        type=int,
        default=60,
        help="Durasi testing dalam detik"
    )
    

    return parser.parse_args()

def print_banner():
    """Menampilkan banner aplikasi"""
    banner = """
    ╔══════════════════════════════════════════════╗
    ║             RANSOMWARE DETECTOR              ║
    ║        Zero-Day Attack Detection System      ║
    ╚══════════════════════════════════════════════╝
    Author: Hany Andriyanto
    Version: 1.0.0
    """
    print(banner)

def confirm_cleanup() -> bool:
    """Konfirmasi dari user untuk membersihkan folder"""
    while True:
        response = input("\nApakah Anda ingin membersihkan folder data? (y/n): ").lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        print("Mohon masukkan 'y' atau 'n'")


def main():
    """Fungsi utama aplikasi"""
    print_banner()
    
    args = parse_arguments()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Buat instance aplikasi
    app = RansomwareDetectorApp()
    
    if args.validate_only:
        model_path = args.model_path or os.path.join("data", "models", "model_latest.joblib")
        validator = ModelValidator(model_path)
        is_valid, message, _ = validator.load_and_validate_model()
        print(f"\nHasil validasi model:")
        print(f"Status: {'Valid' if is_valid else 'Tidak Valid'}")
        print(f"Pesan: {message}")
        return
    if args.collect_only:
            # Hanya collect metrik
            print("\nMemulai pengumpulan metrik...")
            app.setup_logging()
            app.init_components()
            app.detector.collect_metrics(args.training_duration)
            
    if args.train_from_metrics:
        # Training dari metrik yang ada
        metrics_path = args.metrics_path or os.path.join(app.data_dir, "metrics")
        if not os.path.exists(metrics_path):
            print(f"\nFolder metrik tidak ditemukan di: {metrics_path}")
            return
        app.setup_logging()
        app.init_components()
        app.train_from_metrics(metrics_path)
        
    # else:
    #     # Mode normal: run detector
    #     app.run(args)
    
    # Cek apakah perlu cleanup
    
    if args.test_model:
        app.test_model(args.test_duration)
        return
        
    if not args.no_cleanup and confirm_cleanup():
        print("\nMemulai pembersihan folder...")
        app.cleanup_data_folders()
    else:
        print("\nMelanjutkan tanpa membersihkan folder...")
    
    try:
        app.run(args)
    except KeyboardInterrupt:
        print("\nProgram dihentikan oleh user")
    except Exception as e:
        print(f"\nError: {str(e)}")
        logging.exception("Unexpected error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()
