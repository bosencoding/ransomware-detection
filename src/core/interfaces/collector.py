from abc import ABC, abstractmethod
from typing import Dict, Any

class IMetricsCollector(ABC):
    """Interface untuk pengumpulan metrik"""
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Mengumpulkan metrik"""
        pass
