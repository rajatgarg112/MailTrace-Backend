"""
Reproducible Evaluator for ML Models.
Calculates actual Accuracy, Precision, Recall, and F1 metrics from real predictions.
"""

from typing import List, Dict, Any


def evaluate_predictions(y_true: List[str], y_pred: List[str], positive_label: str = "phishing") -> Dict[str, float]:
    """
    Calculate reproducible classification metrics from actual predictions.
    """
    if not y_true or not y_pred or len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must be non-empty lists of identical length.")

    total = len(y_true)
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    accuracy = correct / total

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == positive_label and yp == positive_label)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != positive_label and yp == positive_label)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == positive_label and yp != positive_label)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt != positive_label and yp != positive_label)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "sample_size": float(total),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "tn": float(tn)
    }
