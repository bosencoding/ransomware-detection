# validate_model.py
import os
import logging
from src.utils.model_validator import ModelValidator
from src.collectors.system_collector import SystemMetricsCollector

def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Path ke model
    base_dir = os.path.abspath(os.path.dirname(__file__))
    model_path = os.path.join(base_dir, "data", "models", "model_latest.joblib")
    
    if not os.path.exists(model_path):
        print(f"Model tidak ditemukan di: {model_path}")
        return
    
    print(f"\nMemvalidasi model di: {model_path}")
    
    # Inisialisasi validator
    validator = ModelValidator(model_path)
    
    # Validasi model
    is_valid, message, model = validator.load_and_validate_model()
    print(f"\nHasil validasi model:")
    print(f"Status: {'Valid' if is_valid else 'Tidak Valid'}")
    print(f"Pesan: {message}")
    
    if is_valid:
        # Collect current metrics untuk validasi
        collector = SystemMetricsCollector()
        current_metrics = collector.collect()
        
        # Validasi kompatibilitas feature
        feature_valid, feature_message, feature_vector = validator.validate_feature_compatibility(current_metrics)
        print(f"\nHasil validasi feature:")
        print(f"Status: {'Valid' if feature_valid else 'Tidak Valid'}")
        print(f"Pesan: {feature_message}")
        
        if feature_valid:
            # Verifikasi kemampuan prediksi
            pred_valid, pred_message = validator.verify_prediction_capability(model, feature_vector)
            print(f"\nHasil verifikasi prediksi:")
            print(f"Status: {'Valid' if pred_valid else 'Tidak Valid'}")
            print(f"Pesan: {pred_message}")

if __name__ == "__main__":
    main()