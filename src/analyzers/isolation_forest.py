# src/analyzers/isolation_forest.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import Dict, Any, Tuple
from datetime import datetime
from src.config.thresholds import SystemThresholds
<<<<<<< HEAD
#, AnomalyThresholds
=======
>>>>>>> ccc2ef3a73486879f19004c5410e29375d2cb112

class IsolationForestAnalyzer:
    def __init__(self, contamination: float = 0.01):
        self.logger = logging.getLogger(__name__)
        
        # Inisialisasi IsolationForest
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            random_state=42,
            bootstrap=True
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        self.n_features = None
        
        # Tracking scores
        self.training_scores = []
        self.score_mean = None
        self.score_std = None

    def train(self, data: np.ndarray) -> None:
        try:
            if len(data.shape) != 2:
                raise ValueError(f"Expected 2D array, got {len(data.shape)}D array")
            
            self.n_features = data.shape[1]
            
            # Normalize data
            self.scaler.fit(data)
            normalized_data = self.scaler.transform(data)
            
            # Train isolation forest
            self.isolation_forest.fit(normalized_data)
            
            # Calculate training scores
            self.training_scores = self.isolation_forest.score_samples(normalized_data)
            self.score_mean = np.mean(self.training_scores)
            self.score_std = np.std(self.training_scores)
            
            self.is_trained = True
            self.logger.info(f"Model trained successfully with {self.n_features} features")
            
        except Exception as e:
            self.logger.error(f"Error during training: {str(e)}")
            raise

    def predict(self, data: np.ndarray) -> np.ndarray:
        """Method predict untuk compatibility"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        normalized_data = self.scaler.transform(data)
        return self.isolation_forest.predict(normalized_data)

    def score_samples(self, data: np.ndarray) -> np.ndarray:
        """Method score_samples untuk compatibility"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
            
        normalized_data = self.scaler.transform(data)
        return self.isolation_forest.score_samples(normalized_data)

    def save(self, path: str) -> None:
        """Save model dengan semua komponennya"""
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'n_features': self.n_features,
                'training_scores': self.training_scores,
                'score_mean': self.score_mean,
                'score_std': self.score_std,
                'metadata': {
                    'saved_at': datetime.now().isoformat(),
                    'has_predict': hasattr(self.isolation_forest, 'predict'),
                    'has_score_samples': hasattr(self.isolation_forest, 'score_samples')
                }
            }
            joblib.dump(model_data, path)
            self.logger.info(f"Model saved successfully to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise

    def load(self, path: str) -> None:
        """Load model dan semua komponennya"""
        try:
            model_data = joblib.load(path)
            
            if not isinstance(model_data, dict):
                raise ValueError("Invalid model format")
            
            # Load semua komponen
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            self.n_features = model_data['n_features']
            self.training_scores = model_data['training_scores']
            self.score_mean = model_data['score_mean']
            self.score_std = model_data['score_std']
            
            # Validasi method yang diperlukan
            if not hasattr(self.isolation_forest, 'predict'):
                raise ValueError("Loaded model doesn't have predict method")
            if not hasattr(self.isolation_forest, 'score_samples'):
                raise ValueError("Loaded model doesn't have score_samples method")
            
            self.logger.info("Model loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
     
    # src/analyzers/isolation_forest.py
    def analyze(self, data: np.ndarray) -> Dict[str, Any]:
        """Analyze data untuk anomali"""
        if not self.is_trained:
            raise ValueError("Model hasn't been trained!")
        
        try:
            # Normalize dan predict
            normalized_data = self.scaler.transform(data)
            
            # Get prediction dan score
            prediction = self.isolation_forest.predict(normalized_data)
            anomaly_score = float(self.isolation_forest.score_samples(normalized_data)[0])
            
            return {
                'is_anomaly': prediction[0] == -1,
                'anomaly_score': anomaly_score,  # Pastikan menggunakan key yang sama
                'details': {
                    'prediction': int(prediction[0]),
                    'threshold': SystemThresholds.ANOMALY_SCORE_THRESHOLD
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {str(e)}")
            raise
        
    # def analyze(self, data: np.ndarray) -> Dict[str, Any]:
    #     """Analyze data untuk anomali detection"""
    #     if not self.is_trained:
    #         raise ValueError("Model not trained yet")
            
    #     try:
    #         # Normalize data
    #         normalized_data = self.scaler.transform(data)
            
    #         # Get prediction dan score
    #         prediction = self.isolation_forest.predict(normalized_data)
    #         score = self.isolation_forest.score_samples(normalized_data)
            
    #         # Calculate z-score jika ada baseline
    #         z_score = None
    #         if self.score_mean is not None and self.score_std is not None:
    #             z_score = (score[0] - self.score_mean) / self.score_std
            
    #         # Determine anomali dengan multiple criteria
    #         is_anomaly = any([
    #             prediction[0] == -1,  # IsolationForest prediction
    #             score[0] < -0.4,      # Score threshold
    #             z_score < -3 if z_score is not None else False  # Statistical threshold
    #         ])
            
    #         result = {
    #             'is_anomaly': is_anomaly,
    #             'anomaly_score': float(score[0]),
    #             'raw_prediction': int(prediction[0]),
    #             'z_score': float(z_score) if z_score is not None else None,
    #             'statistical_bounds': {
    #                 'mean': float(self.score_mean) if self.score_mean is not None else None,
    #                 'std': float(self.score_std) if self.score_std is not None else None
    #             }
    #         }
            
    #         self.logger.debug(f"Analysis result: {result}")
    #         return result
            
    #     except Exception as e:
    #         self.logger.error(f"Error during analysis: {str(e)}")
    #         raise