from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime

class IStorage(ABC):
    """Interface untuk penyimpanan data"""
    
    @abstractmethod
    def save_metrics(self, metrics: Dict[str, Any]) -> None:
        """Menyimpan metrics"""
        pass
    
    @abstractmethod
    def save_model(self, model: Any, path: str) -> None:
        """Menyimpan model"""
        pass
    
    @abstractmethod
    def load_model(self, path: str) -> Optional[Any]:
        """Memuat model"""
        pass
    
    @abstractmethod
    def get_metrics(self, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Mendapatkan metrics"""
        pass
    
    @abstractmethod
    def save_training_data(self, data: Any, metadata: Dict[str, Any]) -> None:
        """Menyimpan data training"""
        pass



