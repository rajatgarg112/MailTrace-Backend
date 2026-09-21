"""
Reproducible Evaluator for ML Models.
Calculates actual Accuracy, Precision, Recall, and F1 metrics from real predictions.
"""

from typing import List, Dict, Any, Optional


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


def evaluate_multiclass(
    y_true: List[str],
    y_pred: List[str],
    labels: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Calculate comprehensive multiclass classification metrics including per-class
    precision, recall, F1, support, and macro averages.
    """
    if not y_true or not y_pred or len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must be non-empty lists of identical length.")

    total = len(y_true)
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    accuracy = round(correct / total, 4)

    target_labels = sorted(set(labels) if labels else (set(y_true) | set(y_pred)))
    per_class: Dict[str, Dict[str, float]] = {}

    precision_sum = 0.0
    recall_sum = 0.0
    f1_sum = 0.0

    for lbl in target_labels:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == lbl and yp == lbl)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != lbl and yp == lbl)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == lbl and yp != lbl)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt != lbl and yp != lbl)
        support = sum(1 for yt in y_true if yt == lbl)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class[lbl] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "support": float(support),
            "tp": float(tp),
            "fp": float(fp),
            "fn": float(fn),
            "tn": float(tn)
        }

        precision_sum += prec
        recall_sum += rec
        f1_sum += f1

    num_classes = len(target_labels) if target_labels else 1
    macro_precision = round(precision_sum / num_classes, 4)
    macro_recall = round(recall_sum / num_classes, 4)
    macro_f1 = round(f1_sum / num_classes, 4)

    return {
        "sample_size": float(total),
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "per_class": per_class
    }

