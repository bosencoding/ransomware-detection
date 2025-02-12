import numpy as np
from typing import Dict, Any
from src.core.interfaces.analyzer import IAnalyzer

class StatisticalAnalyzer(IAnalyzer):
    """Implementasi analisis statistik sederhana"""
    def __init__(self, threshold: float = 2.0):
        self.threshold = threshold
        self.mean = None
        self.std = None
        self.is_trained = False
    
    def train(self, data: np.ndarray) -> None:
        """Menghitung statistik dasar dari data training"""
        self.mean = np.mean(data, axis=0)
        self.std = np.std(data, axis=0)
        self.is_trained = True
    
    def analyze(self, data: np.ndarray) -> Dict[str, Any]:
        """Menganalisis data menggunakan z-score"""
        if not self.is_trained:
            raise ValueError("Model belum dilatih")
            
        z_scores = np.abs((data - self.mean) / self.std)
        max_z_score = np.max(z_scores)
        
        return {
            'is_anomaly': max_z_score > self.threshold,
            'anomaly_score': max_z_score
        }
