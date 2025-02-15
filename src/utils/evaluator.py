from typing import Dict, List
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

class ModelEvaluator:
    """Kelas untuk mengevaluasi performa model deteksi"""
    
    @staticmethod
    def calculate_metrics(detections: List[Dict]) -> Dict:
        """
        Menghitung metrik evaluasi dari hasil deteksi
        
        Args:
            detections: List hasil deteksi dengan format
                      [{'is_anomaly': bool, 'score': float, ...}, ...]
        
        Returns:
            Dict berisi metrik evaluasi
        """
        # Ekstrak hasil deteksi
        y_pred = [1 if d['is_anomaly'] else 0 for d in detections]
        scores = [d['score'] for d in detections]
        
        # Hitung statistik dasar
        total_checks = len(detections)
        anomalies_detected = sum(y_pred)
        normal_detected = total_checks - anomalies_detected
        
        # Hitung rata-rata dan std dev dari scores
        mean_score = np.mean(scores)
        std_score = np.std(scores)
        
        # Rangkum hasil
        evaluation = {
            'total_checks': total_checks,
            'anomalies_detected': anomalies_detected,
            'normal_detected': normal_detected,
            'anomaly_rate': anomalies_detected / total_checks if total_checks > 0 else 0,
            'score_statistics': {
                'mean': mean_score,
                'std': std_score,
                'min': min(scores),
                'max': max(scores)
            }
        }
        
        return evaluation

    @staticmethod
    def evaluate_with_ground_truth(detections: List[Dict], ground_truth: List[bool]) -> Dict:
        """
        Menghitung metrik evaluasi dengan ground truth
        
        Args:
            detections: List hasil deteksi
            ground_truth: List label sebenarnya (True untuk anomali)
            
        Returns:
            Dict berisi metrik evaluasi
        """
        # Konversi ke format yang sesuai
        y_pred = [1 if d['is_anomaly'] else 0 for d in detections]
        y_true = [1 if gt else 0 for gt in ground_truth]
        
        # Hitung metrik
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Hitung confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': {
                'true_negative': int(tn),
                'false_positive': int(fp),
                'false_negative': int(fn),
                'true_positive': int(tp)
            }
        }