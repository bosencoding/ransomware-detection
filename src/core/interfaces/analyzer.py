from abc import ABC, abstractmethod
import numpy as np
from typing import Dict, Any

class IAnalyzer(ABC):
    """Interface untuk analisis anomali"""
    @abstractmethod
    def train(self, data: np.ndarray) -> None:
        """Melatih model analisis"""
        pass
    
    @abstractmethod
    def analyze(self, data: np.ndarray) -> Dict[str, Any]:
        """Menganalisis data untuk anomali"""
        pass
