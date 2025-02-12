import numpy as np
from typing import Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.core.interfaces.analyzer import IAnalyzer

class IsolationForestAnalyzer(IAnalyzer):
    """Analyzer menggunakan Isolation Forest dengan parameter yang disesuaikan"""
    
    def __init__(
        self,
        contamination: float = 0.01,  # Nilai contamination yang lebih toleran
        n_estimators: int = 200,      # Jumlah trees yang lebih banyak
        random_state: int = 42,
        threshold: float = -0.4       # Threshold yang lebih toleran
    ):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            max_samples='auto',
            bootstrap=True           # Menggunakan bootstrap untuk variasi lebih baik
        )
        self.scaler = StandardScaler()
        self.threshold = threshold
        self.is_trained = False
        
        # Tracking untuk distribution scores
        self.training_scores = []
        self.score_mean = None
        self.score_std = None
    
    def train(self, data: np.ndarray) -> None:
        """Train model dengan data normal"""
        if len(data.shape) != 2:
            raise ValueError(f"Expected 2D array, got {len(data.shape)}D array")
        
        # Normalize data
        self.scaler.fit(data)
        normalized_data = self.scaler.transform(data)
        
        # Train model
        self.model.fit(normalized_data)
        
        # Calculate score distribution
        self.training_scores = self.model.score_samples(normalized_data)
        self.score_mean = np.mean(self.training_scores)
        self.score_std = np.std(self.training_scores)
        
        self.is_trained = True
    
    def analyze(self, data: np.ndarray) -> Dict[str, Any]:
        """Analyze data untuk anomali dengan threshold adaptif"""
        if not self.is_trained:
            raise ValueError("Model belum dilatih!")
        
        if len(data.shape) != 2:
            raise ValueError(f"Expected 2D array, got {len(data.shape)}D array")
        
        # Normalize dan predict
        normalized_data = self.scaler.transform(data)
        score = self.model.score_samples(normalized_data)[0]
        
        # Calculate z-score
        z_score = (score - self.score_mean) / self.score_std if self.score_std else 0
        
        # Determine anomaly dengan multiple criteria
        is_anomaly = any([
            score < self.threshold,                    # Basic threshold
            z_score < -3,                             # Statistical deviation
            score < (self.score_mean - 2*self.score_std) if self.score_std else False  # Distribution based
        ])
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': score,
            'z_score': z_score,
            'threshold': self.threshold,
            'statistical_bounds': {
                'mean': self.score_mean,
                'std': self.score_std,
                'lower_bound': self.score_mean - 2*self.score_std if self.score_std else None
            }
        }