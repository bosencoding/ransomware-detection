# src/storage/file_storage.py
import os
import json
import joblib
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from src.core.interfaces.storage import IStorage

class FileStorage(IStorage):
    def __init__(self, base_path: str = "data"):
        """
        Inisialisasi dengan path yang absolut
        """
        # Gunakan absolute path
        self.base_path = os.path.abspath(base_path)
        self.metrics_path = os.path.join(self.base_path, "metrics")
        self.models_path = os.path.join(self.base_path, "models")
        self.logs_path = os.path.join(self.base_path, "logs")
        self.training_path = os.path.join(self.base_path, "training")
        
        # Buat semua direktori yang diperlukan
        self._create_directories()
        
        # Setup logging khusus untuk storage
        self._setup_storage_logging()
        
    def _create_directories(self):
        """Membuat struktur direktori dengan logging"""
        directories = [
            self.base_path,
            self.metrics_path,
            self.models_path,
            self.logs_path,
            self.training_path
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"Membuat direktori: {directory}")
    
    def _setup_storage_logging(self):
        """Setup logging khusus untuk storage"""
        log_file = os.path.join(self.logs_path, f'storage_{datetime.now().strftime("%Y%m%d")}.log')
        
        # Konfigurasi file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        
        # Dapatkan logger untuk storage
        self.logger = logging.getLogger('storage')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        
        self.logger.info(f"Storage initialized at {self.base_path}")
        print(f"Log file dibuat di: {log_file}")
    
    def save_metrics(self, metrics: Dict[str, Any]) -> None:
        """Menyimpan metrics dengan logging detail"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"metrics_{timestamp}.json"
        file_path = os.path.join(self.metrics_path, filename)
        
        try:
            metrics_copy = self._prepare_metrics_for_save(metrics)
            with open(file_path, 'w') as f:
                json.dump(metrics_copy, f, indent=4)
            
            self.logger.info(f"Metrics saved to {file_path}")
            print(f"Metrics disimpan di: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save metrics: {str(e)}")
            raise

    def _prepare_metrics_for_save(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mempersiapkan metrics untuk disimpan ke JSON.
        """
        if isinstance(metrics, dict):
            return {k: self._prepare_metrics_for_save(v) for k, v in metrics.items()}
        elif isinstance(metrics, (list, tuple)):
            return [self._prepare_metrics_for_save(item) for item in metrics]
        elif isinstance(metrics, datetime):
            return metrics.isoformat()
        elif hasattr(metrics, '__dict__'):
            return self._prepare_metrics_for_save(metrics.__dict__)
        else:
            return metrics
    
    def save_model(self, model: Any, path: str) -> None:
        """Menyimpan model dengan logging"""
        try:
            full_path = os.path.join(self.models_path, path)
            joblib.dump(model, full_path)
            
            model_info = {
                'saved_at': datetime.now().isoformat(),
                'path': full_path,
                'type': str(type(model).__name__)
            }
            
            info_path = os.path.join(self.models_path, 'model_info.json')
            with open(info_path, 'w') as f:
                json.dump(model_info, f, indent=4)
            
            self.logger.info(f"Model saved to {full_path}")
            print(f"Model disimpan di: {full_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {str(e)}")
            raise

    def load_model(self, path: str) -> Optional[Any]:
        """
        Memuat model dari file
        
        Args:
            path: Path ke file model
            
        Returns:
            Model yang dimuat atau None jika gagal
        """
        try:
            full_path = os.path.join(self.models_path, path)
            if os.path.exists(full_path):
                model = joblib.load(full_path)
                self.logger.info(f"Model loaded from {full_path}")
                return model
            else:
                self.logger.warning(f"Model file not found: {full_path}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            return None
    
    def get_metrics(self, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Mendapatkan metrics dalam rentang waktu tertentu
        
        Args:
            start_time: Optional waktu mulai untuk filtering metrics
            
        Returns:
            List dari metrics yang ditemukan
        """
        try:
            metrics_files = sorted(os.listdir(self.metrics_path))
            metrics_list = []
            
            for filename in metrics_files:
                if not filename.endswith('.json'):
                    continue
                    
                file_path = os.path.join(self.metrics_path, filename)
                with open(file_path, 'r') as f:
                    metrics = json.load(f)
                    
                    if start_time:
                        metrics_time = datetime.fromisoformat(metrics['timestamp'])
                        if metrics_time >= start_time:
                            metrics_list.append(metrics)
                    else:
                        metrics_list.append(metrics)
            
            return metrics_list
            
        except Exception as e:
            self.logger.error(f"Failed to get metrics: {str(e)}")
            return []

    def save_training_data(self, data: Any, metadata: Dict[str, Any]) -> None:
        """
        Menyimpan data training dengan metadata
        
        Args:
            data: Data training yang akan disimpan
            metadata: Metadata terkait data training
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        data_file = os.path.join(self.training_path, f"training_data_{timestamp}.joblib")
        metadata_file = os.path.join(self.training_path, f"metadata_{timestamp}.json")
        
        try:
            # Simpan data training
            joblib.dump(data, data_file)
            
            # Simpan metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=4)
            
            self.logger.info(f"Training data saved to {data_file}")
            self.logger.info(f"Training metadata saved to {metadata_file}")
            
            print(f"Data training disimpan di: {data_file}")
            print(f"Metadata training disimpan di: {metadata_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save training data: {str(e)}")
            raise
