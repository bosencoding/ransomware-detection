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
    
    # def _collect_network_processes(self) -> List[ProcessInfo]:
    #     """Collect processes dengan aktivitas network"""
    #     network_processes = []
    #     for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
    #         try:
    #             proc_name = proc.name()
    #             # Get network connections untuk proses ini
    #             connections = proc.connections()
    #             if connections:  # Jika ada koneksi aktif
    #                 network_io = proc.io_counters()
    #                 process_info = ProcessInfo(
    #                     pid=proc.pid,
    #                     name=proc_name,
    #                     cpu_percent=proc.cpu_percent(),
    #                     memory_percent=proc.memory_percent(),
    #                     upload_rate=network_io.write_bytes / 1024,  # Convert to KB/s
    #                     download_rate=network_io.read_bytes / 1024,
    #                     is_whitelisted=SystemWhitelist.is_whitelisted_process(proc_name)
    #                 )
    #                 network_processes.append(process_info)
    #         except (psutil.NoSuchProcess, psutil.AccessDenied):
    #             continue
    #     return network_processes

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
            self.detector = RansomwareDetector(collectors, analyzer, self.storage)
            logging.info("Detector initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize components: {str(e)}")
            raise
    
    def print_status(self, result: DetectionResult) -> None:
        """Menampilkan status deteksi dengan detail"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\nRansomware Detector Status")
        print("=" * 50)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # System Metrics
        print("\n📊 Metrik Sistem:")
        print(f"CPU Usage: {result.metrics.cpu_percent:.1f}%")
        print(f"Memory Usage: {result.metrics.memory_percent:.1f}%")
        
        # Disk I/O
        print("\n💾 Storage I/O:")
        print(f"Read Rate: {result.metrics.disk_read_rate / 1024:.2f} KB/s")
        print(f"Write Rate: {result.metrics.disk_write_rate / 1024:.2f} KB/s")
        print(f"Total Read: {result.metrics.disk_read_bytes / 1024:.2f} KB")
        print(f"Total Write: {result.metrics.disk_write_bytes / 1024:.2f} KB")
        print(f"Read Operations: {result.metrics.disk_read_count} ops")
        print(f"Write Operations: {result.metrics.disk_write_count} ops")
        
        # Network Activity (hanya informasi)
        # if hasattr(result, 'network_metrics') and result.network_metrics is not None:
        #     print("\n🌐 Network Activity (monitoring only):")
        #     print(f"Upload Rate: {result.network_metrics.send_rate_kb:.2f} KB/s")
        #     print(f"Download Rate: {result.network_metrics.recv_rate_kb:.2f} KB/s")
        
        # Score dan Status
        print(f"\n📈 Score Anomali: {result.score:.3f}")
        if result.is_anomaly:
            print("\n⚠️  PERINGATAN: Aktivitas Mencurigakan Terdeteksi!")
            
            # Tampilkan detail faktor anomali
            if result.details and 'anomaly_factors' in result.details:
                print("\nDetail Faktor Anomali:")
                for factor in result.details['anomaly_factors']:
                    print(f"- {factor}")
                
                print("\nRekomendasi:")
                print("1. Monitor proses yang menggunakan CPU/Memory tinggi")
                print("2. Periksa aktivitas disk yang tidak normal")
                print("3. Cek perubahan file yang mencurigakan")
        else:
            print("✅ Status: Normal")
        
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
    
    # Cek apakah perlu cleanup
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
