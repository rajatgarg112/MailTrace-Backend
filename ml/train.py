"""
Auditable ML Dataset Training & Evaluation Pipeline for MailTrace-AI.
Supports real dataset training (spam_ham_dataset, CEAS_08, or combined),
deterministic 3-way splitting, data leakage audit, safe JSON model persistence,
and reproducible evaluation.
"""

import argparse
import os
import sys
import time
from typing import Dict, Any, List, Tuple, Optional

# Ensure repository root is on Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from ml.datasets.dataset_loader import DatasetLoader, DatasetRecord
from ml.datasets.preprocessor import split_dataset_3way, audit_split_data_leakage
from ml.models.tfidf_classifier import SimpleTFIDFClassifier
from ml.evaluation.evaluator import evaluate_predictions, evaluate_multiclass


DEFAULT_SPAM_HAM_PATH = os.path.abspath(
    os.path.join(BACKEND_ROOT, "..", "data", "spam_ham_dataset.csv", "spam_ham_dataset.csv")
)
DEFAULT_CEAS_PATH = os.path.abspath(
    os.path.join(BACKEND_ROOT, "..", "data", "CEAS_08.csv", "CEAS_08.csv")
)
DEFAULT_OUTPUT_MODEL_PATH = os.path.join(CURRENT_DIR, "models", "trained_tfidf_model.json")


def load_selected_datasets(
    dataset_choice: str = "spam_ham",
    spam_ham_path: str = DEFAULT_SPAM_HAM_PATH,
    ceas_path: str = DEFAULT_CEAS_PATH
) -> Tuple[List[Tuple[str, str]], Dict[str, Any]]:
    """
    Load and normalize records from selected real datasets.
    Returns (raw_samples, dataset_audit_metadata).
    """
    samples: List[Tuple[str, str]] = []
    audit_stats: Dict[str, Any] = {}

    if dataset_choice in ("spam_ham", "combined"):
        if not os.path.exists(spam_ham_path):
            # Fallback path check relative to cwd
            alt_path = os.path.join("data", "spam_ham_dataset.csv", "spam_ham_dataset.csv")
            if os.path.exists(alt_path):
                spam_ham_path = os.path.abspath(alt_path)

        recs_sh, stats_sh = DatasetLoader.load_csv_with_stats(
            file_path=spam_ham_path,
            dataset_type="spam_ham"
        )
        samples.extend([(r.text, r.label) for r in recs_sh])
        audit_stats["spam_ham_dataset"] = stats_sh

    if dataset_choice in ("ceas", "combined"):
        if not os.path.exists(ceas_path):
            alt_path = os.path.join("data", "CEAS_08.csv", "CEAS_08.csv")
            if os.path.exists(alt_path):
                ceas_path = os.path.abspath(alt_path)

        recs_ceas, stats_ceas = DatasetLoader.load_csv_with_stats(
            file_path=ceas_path,
            dataset_type="ceas"
        )
        samples.extend([(r.text, r.label) for r in recs_ceas])
        audit_stats["ceas_08_dataset"] = stats_ceas

    audit_stats["selected_dataset"] = dataset_choice
    audit_stats["total_raw_samples"] = len(samples)
    return samples, audit_stats


def run_training_pipeline(
    dataset_choice: str = "spam_ham",
    ngram_range: Tuple[int, int] = (1, 1),
    seed: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    stratify: bool = True,
    output_model_path: str = DEFAULT_OUTPUT_MODEL_PATH,
    model_version: str = "7.4.0",
    spam_ham_path: str = DEFAULT_SPAM_HAM_PATH,
    ceas_path: str = DEFAULT_CEAS_PATH
) -> Dict[str, Any]:
    """
    Executes the full end-to-end dataset training and evaluation pipeline:
    1. Load & audit real dataset
    2. Deduplicate
    3. Deterministic 3-way split
    4. Data leakage verification
    5. Fit TF-IDF Naive Bayes strictly on training set
    6. Validation set evaluation
    7. Test set evaluation
    8. Safe JSON persistence with metadata
    9. Prediction equivalence verification
    """
    start_time = time.time()

    # 1. Dataset Loading
    raw_samples, dataset_audit = load_selected_datasets(
        dataset_choice=dataset_choice,
        spam_ham_path=spam_ham_path,
        ceas_path=ceas_path
    )

    if not raw_samples:
        raise ValueError(f"No records could be loaded for dataset choice '{dataset_choice}'.")

    # 2. 3-Way Splitting with Deduplication
    split_result = split_dataset_3way(
        samples=raw_samples,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
        deduplicate=True,
        stratify=stratify
    )

    # 3. Data Leakage Audit
    leakage_audit = audit_split_data_leakage(
        train_text=split_result.train_text,
        val_text=split_result.val_text,
        test_text=split_result.test_text
    )
    if leakage_audit["has_leakage"]:
        raise RuntimeError(
            f"DATA LEAKAGE DETECTED: Overlaps found: "
            f"Train-Val={leakage_audit['overlap_train_val_count']}, "
            f"Train-Test={leakage_audit['overlap_train_test_count']}, "
            f"Val-Test={leakage_audit['overlap_val_test_count']}"
        )

    # Calculate class distributions per partition
    def count_classes(labels: List[str]) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for l in labels:
            dist[l] = dist.get(l, 0) + 1
        return dist

    train_class_dist = count_classes(split_result.train_labels)
    val_class_dist = count_classes(split_result.val_labels)
    test_class_dist = count_classes(split_result.test_labels)

    # 4. Model Training (strictly on training set)
    t_train_start = time.time()
    classifier = SimpleTFIDFClassifier(
        ngram_range=ngram_range,
        model_version=model_version
    )
    classifier.train(split_result.train_text, split_result.train_labels)
    train_duration = round(time.time() - t_train_start, 2)

    # 5. Validation Evaluation
    val_preds = [classifier.predict(t).prediction for t in split_result.val_text]
    val_metrics_spam = evaluate_predictions(split_result.val_labels, val_preds, positive_label="spam")
    val_metrics_multi = evaluate_multiclass(split_result.val_labels, val_preds)

    # 6. Test Evaluation
    test_preds = [classifier.predict(t).prediction for t in split_result.test_text]
    test_metrics_spam = evaluate_predictions(split_result.test_labels, test_preds, positive_label="spam")
    test_metrics_multi = evaluate_multiclass(split_result.test_labels, test_preds)

    # 7. Construct Audit Metadata
    metadata: Dict[str, Any] = {
        "dataset_choice": dataset_choice,
        "dataset_audit": dataset_audit,
        "total_raw_samples": len(raw_samples),
        "deduplicated_removed_count": split_result.deduplicated_count,
        "split_counts": {
            "train": len(split_result.train_text),
            "val": len(split_result.val_text),
            "test": len(split_result.test_text)
        },
        "class_distributions": {
            "train": train_class_dist,
            "val": val_class_dist,
            "test": test_class_dist
        },
        "split_configuration": {
            "train_ratio": train_ratio,
            "val_ratio": val_ratio,
            "test_ratio": test_ratio,
            "seed": seed,
            "stratified": stratify
        },
        "data_leakage_audit": leakage_audit,
        "model_architecture": "TF-IDF Multinomial Naive Bayes",
        "ngram_range": list(ngram_range),
        "vocabulary_size": len(classifier.vocab),
        "model_version": model_version,
        "training_duration_seconds": train_duration,
        "validation_metrics": {
            "binary_spam": val_metrics_spam,
            "multiclass": val_metrics_multi
        },
        "test_metrics": {
            "binary_spam": test_metrics_spam,
            "multiclass": test_metrics_multi
        },
        "production_performance": "NOT ESTABLISHED"
    }
    classifier.metadata = metadata

    # 8. Safe Model Persistence
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    classifier.save_model(output_model_path)

    # 9. Verification: Load & Check Equivalence
    loaded_clf = SimpleTFIDFClassifier.load_model(output_model_path)
    if len(split_result.test_text) > 0:
        sample_test = split_result.test_text[0]
        prob_orig = classifier.predict_proba(sample_test)
        prob_loaded = loaded_clf.predict_proba(sample_test)
        for k in prob_orig:
            if abs(prob_orig[k] - prob_loaded[k]) > 1e-5:
                raise AssertionError(f"Loaded model prediction mismatch for class '{k}'!")

    total_duration = round(time.time() - start_time, 2)
    metadata["total_pipeline_duration_seconds"] = total_duration
    metadata["output_model_path"] = output_model_path

    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train TF-IDF Classifier on Real Datasets.")
    parser.add_argument("--dataset", choices=["spam_ham", "ceas", "combined"], default="spam_ham",
                        help="Dataset selection: 'spam_ham', 'ceas', or 'combined'")
    parser.add_argument("--ngram-min", type=int, default=1, help="Minimum n-gram range")
    parser.add_argument("--ngram-max", type=int, default=1, help="Maximum n-gram range")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for splitting")
    parser.add_argument("--stratify", action="store_true", default=True, help="Stratify dataset split")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_MODEL_PATH, help="Output JSON path")
    args = parser.parse_args()

    print(f"=== MailTrace-AI ML Training Pipeline ===")
    print(f"Dataset: {args.dataset}")
    print(f"N-Gram: ({args.ngram_min}, {args.ngram_max})")
    print(f"Random Seed: {args.seed}")

    res = run_training_pipeline(
        dataset_choice=args.dataset,
        ngram_range=(args.ngram_min, args.ngram_max),
        seed=args.seed,
        stratify=args.stratify,
        output_model_path=args.output
    )

    print("\n--- Training Pipeline Summary ---")
    print(f"Raw Samples: {res['total_raw_samples']}")
    print(f"Deduplicated Removed: {res['deduplicated_removed_count']}")
    print(f"Splits: Train={res['split_counts']['train']}, Val={res['split_counts']['val']}, Test={res['split_counts']['test']}")
    print(f"Vocabulary Size: {res['vocabulary_size']}")
    print(f"Leakage Audit: Clean = {res['data_leakage_audit']['leakage_clean']}")
    print("\n--- Validation Metrics ---")
    print(res['validation_metrics']['binary_spam'])
    print("\n--- Test Metrics ---")
    print(res['test_metrics']['binary_spam'])
    print(f"\nModel successfully saved to: {res['output_model_path']}")
    print(f"Production Performance: {res['production_performance']}")
