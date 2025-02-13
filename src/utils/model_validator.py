# src/utils/model_validator.py
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from datetime import datetime
import logging

class ModelValidator:
    """
    Kelas untuk memvalidasi model joblib dan memastikan kesesuaian dengan format metrik.
    """
    def __init__(self, model_path: str):
        """
        Inisialisasi validator dengan path ke model joblib.
        
        Args:
            model_path: Path ke file model joblib yang akan divalidasi
        """
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path
        
    def load_and_validate_model(self) -> Tuple[bool, str, Any]:
        """Memuat dan memvalidasi model"""
        try:
            print(f"\nMemuat model dari: {self.model_path}")
            
            # Load model data
            model_data = joblib.load(self.model_path)
            
            if not isinstance(model_data, dict):
                return False, "Invalid model format: expected dictionary", None
            
            # Get isolation forest object
            if 'isolation_forest' not in model_data:
                return False, "Model data doesn't contain isolation_forest", None
                
            model = model_data['isolation_forest']
            
            # Print debug info
            print(f"\nModel Info:")
            print(f"- Type: {type(model)}")
            print(f"- Is trained: {model_data.get('is_trained', False)}")
            print(f"- Features: {model_data.get('n_features')}")
            
            # Validate required methods
            required_methods = ['predict', 'score_samples']
            for method in required_methods:
                if not hasattr(model, method):
                    return False, f"Model doesn't have required method: {method}", None
            
            # Test prediction
            try:
                n_features = model_data.get('n_features', 6)
                dummy_data = np.random.rand(1, n_features)
                
                # Test predict
                prediction = model.predict(dummy_data)
                print(f"- Test predict: Success (output shape: {prediction.shape})")
                
                # Test score_samples
                scores = model.score_samples(dummy_data)
                print(f"- Test score_samples: Success (output shape: {scores.shape})")
                
            except Exception as e:
                return False, f"Model failed prediction test: {str(e)}", None
            
            return True, "Model valid and ready to use", model
            
        except Exception as e:
            return False, f"Failed to load model: {str(e)}", None
    
    def validate_feature_compatibility(self, metrics: Dict[str, Any]) -> Tuple[bool, str, np.ndarray]:
        """
        Memvalidasi kesesuaian metrik dengan format yang diharapkan model.
        
        Args:
            metrics: Dictionary berisi metrik sistem
            
        Returns:
            Tuple berisi (is_valid, message, feature_vector)
        """
        try:
            # Definisi fitur yang diharapkan dan tipenya
            expected_features = {
                'cpu_percent': float,
                'memory_percent': float,
                'disk_read_bytes': (int, float),
                'disk_write_bytes': (int, float),
                'process_count': int
            }
            
            # Validasi keberadaan dan tipe data metrik
            for feature, expected_type in expected_features.items():
                if feature not in metrics:
                    return False, f"Metrik tidak ditemukan: {feature}", None
                    
                value = metrics[feature]
                if not isinstance(value, expected_type):
                    return False, f"Tipe data tidak sesuai untuk {feature}: diharapkan {expected_type}, didapat {type(value)}", None
            
            # Buat feature vector
            feature_vector = np.array([
                float(metrics['cpu_percent']),
                float(metrics['memory_percent']),
                float(metrics['disk_read_bytes']),
                float(metrics['disk_write_bytes']),
                float(metrics['process_count'])
            ]).reshape(1, -1)
            
            return True, "Feature vector valid", feature_vector
            
        except Exception as e:
            self.logger.error(f"Error validasi feature: {str(e)}")
            return False, f"Gagal memvalidasi feature: {str(e)}", None
    
    def verify_prediction_capability(self, model: Any, feature_vector: np.ndarray) -> Tuple[bool, str]:
        """
        Memverifikasi kemampuan model untuk melakukan prediksi dengan feature vector.
        
        Args:
            model: Model yang sudah dimuat
            feature_vector: Vector fitur yang akan diuji
            
        Returns:
            Tuple berisi (is_valid, message)
        """
        try:
            # Coba melakukan prediksi
            prediction = model.predict(feature_vector)
            score = model.score_samples(feature_vector)
            
            # Validasi hasil prediksi
            if not isinstance(prediction, np.ndarray):
                return False, "Format prediksi tidak sesuai"
                
            if not isinstance(score, np.ndarray):
                return False, "Format score tidak sesuai"
            
            return True, "Model dapat melakukan prediksi dengan benar"
            
        except Exception as e:
            self.logger.error(f"Error verifikasi prediksi: {str(e)}")
            return False, f"Gagal memverifikasi prediksi: {str(e)}"

def validate_model_and_metrics(model_path: str, current_metrics: Dict[str, Any]) -> Tuple[bool, str, Any]:
    """
    Fungsi utilitas untuk memvalidasi model dan metrik sekaligus.
    
    Args:
        model_path: Path ke file model
        current_metrics: Metrik sistem saat ini
        
    Returns:
        Tuple berisi (is_valid, message, model)
    """
    validator = ModelValidator(model_path)
    
    # Validasi model
    model_valid, model_message, model = validator.load_and_validate_model()
    if not model_valid:
        return False, model_message, None
    
    # Validasi feature compatibility
    feature_valid, feature_message, feature_vector = validator.validate_feature_compatibility(current_metrics)
    if not feature_valid:
        return False, feature_message, None
    
    # Verifikasi kemampuan prediksi
    pred_valid, pred_message = validator.verify_prediction_capability(model, feature_vector)
    if not pred_valid:
        return False, pred_message, None
    
    return True, "Model dan metrik valid", model