"""
Email text dataset preprocessing, text normalization, and dataset splitting utilities.
Implements data leakage prevention mechanisms and reproducible split configurations.
"""

import re
import html
import random
from typing import List, Tuple, Dict, Any, Optional
from pydantic import BaseModel, Field


class DatasetSplitResult(BaseModel):
    """Container for reproducible train / validation / test splits."""
    train_text: List[str]
    train_labels: List[str]
    val_text: List[str]
    val_labels: List[str]
    test_text: List[str]
    test_labels: List[str]
    deduplicated_count: int = 0


def clean_html_and_normalize(raw_text: str) -> str:
    """
    Remove HTML tags, decode entities, and normalize whitespace safely.
    Preserves security-critical tokens (punctuation, numbers, currency symbols, urgency indicators).
    """
    if not raw_text or not isinstance(raw_text, str):
        return ""

    # 1. Replace block-level HTML tags with space to preserve word boundary separation
    text = re.sub(r'</?(?:p|div|h[1-6]|br|hr|li|tr|td|table|blockquote|header|footer|section|article)[^>]*>', ' ', raw_text, flags=re.IGNORECASE)

    # 2. Strip remaining inline/other tags without inserting space (e.g. <b>, <i>, <a>, <span>)
    text = re.sub(r'<[^>]+>', '', text)

    # 3. Decode HTML entities (e.g. &amp;, &lt;, &#39;) so text representations remain literal
    text = html.unescape(text)

    # 4. Replace multiple whitespaces/newlines/tabs with a single space
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def deduplicate_samples(samples: List[Tuple[str, str]]) -> Tuple[List[Tuple[str, str]], int]:
    """
    Remove identical duplicate (text, label) samples to prevent data leakage across splits.
    Returns (unique_samples, count_removed).
    """
    seen = set()
    unique = []
    removed = 0

    for text, label in samples:
        key = (clean_html_and_normalize(text), label.strip().lower())
        if key in seen:
            removed += 1
        else:
            seen.add(key)
            unique.append((key[0], key[1]))

    return unique, removed


def prepare_dataset_split(
    samples: List[Tuple[str, str]],
    train_ratio: float = 0.8,
    seed: int = 42
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Splits samples into (train_text, train_labels, test_text, test_labels).
    Maintains 100% backward compatibility with existing ML test suite.
    """
    if not samples:
        return [], [], [], []

    if not 0.0 < train_ratio < 1.0:
        raise ValueError(f"train_ratio must be between 0.0 and 1.0 exclusive, got {train_ratio}")

    # Deduplicate to prevent train/test data leakage
    unique_samples, _ = deduplicate_samples(samples)

    rng = random.Random(seed)
    shuffled = unique_samples.copy()
    rng.shuffle(shuffled)

    split_idx = int(len(shuffled) * train_ratio)
    if split_idx == 0 and len(shuffled) > 0:
        split_idx = 1
    elif split_idx == len(shuffled) and len(shuffled) > 1:
        split_idx = len(shuffled) - 1

    train_samples = shuffled[:split_idx]
    test_samples = shuffled[split_idx:]

    train_text = [item[0] for item in train_samples]
    train_labels = [item[1] for item in train_samples]
    test_text = [item[0] for item in test_samples]
    test_labels = [item[1] for item in test_samples]

    return train_text, train_labels, test_text, test_labels


def split_dataset_3way(
    samples: List[Tuple[str, str]],
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    deduplicate: bool = True,
    stratify: bool = False
) -> DatasetSplitResult:
    """
    Reproducibly splits dataset into Train, Validation, and Test sets.
    Validates ratio constraints, prevents data leakage across splits, and optionally stratifies by label.
    """
    if not samples:
        return DatasetSplitResult(
            train_text=[], train_labels=[],
            val_text=[], val_labels=[],
            test_text=[], test_labels=[],
            deduplicated_count=0
        )

    # Validate split ratios
    total_ratio = train_ratio + val_ratio + test_ratio
    if abs(total_ratio - 1.0) > 1e-4:
        raise ValueError(f"Split ratios must sum to 1.0 (train: {train_ratio}, val: {val_ratio}, test: {test_ratio}, sum: {total_ratio})")

    if train_ratio <= 0 or val_ratio <= 0 or test_ratio <= 0:
        raise ValueError("All split ratios must be strictly positive (> 0.0).")

    # Deduplicate records to prevent leakage
    dedup_count = 0
    if deduplicate:
        clean_samples, dedup_count = deduplicate_samples(samples)
    else:
        clean_samples = [(clean_html_and_normalize(t), l.strip().lower()) for t, l in samples]

    rng = random.Random(seed)

    if stratify:
        # Group clean samples by label
        by_label: Dict[str, List[Tuple[str, str]]] = {}
        for s in clean_samples:
            by_label.setdefault(s[1], []).append(s)

        train_set = []
        val_set = []
        test_set = []

        for lbl in sorted(by_label.keys()):
            group = by_label[lbl].copy()
            rng.shuffle(group)
            n_grp = len(group)
            n_tr = int(n_grp * train_ratio)
            n_v = int(n_grp * val_ratio)
            if n_grp >= 3:
                if n_tr == 0: n_tr = 1
                if n_v == 0: n_v = 1
            train_set.extend(group[:n_tr])
            val_set.extend(group[n_tr:n_tr + n_v])
            test_set.extend(group[n_tr + n_v:])

        rng.shuffle(train_set)
        rng.shuffle(val_set)
        rng.shuffle(test_set)
    else:
        shuffled = clean_samples.copy()
        rng.shuffle(shuffled)

        n_total = len(shuffled)
        n_train = int(n_total * train_ratio)
        n_val = int(n_total * val_ratio)

        # Adjust indices for very small datasets
        if n_total >= 3:
            if n_train == 0: n_train = 1
            if n_val == 0: n_val = 1

        train_set = shuffled[:n_train]
        val_set = shuffled[n_train:n_train + n_val]
        test_set = shuffled[n_train + n_val:]

    return DatasetSplitResult(
        train_text=[s[0] for s in train_set],
        train_labels=[s[1] for s in train_set],
        val_text=[s[0] for s in val_set],
        val_labels=[s[1] for s in val_set],
        test_text=[s[0] for s in test_set],
        test_labels=[s[1] for s in test_set],
        deduplicated_count=dedup_count
    )


def audit_split_data_leakage(
    train_text: List[str],
    val_text: List[str],
    test_text: List[str]
) -> Dict[str, Any]:
    """
    Explicitly checks for data leakage between train, validation, and test partitions.
    Returns audit statistics and flags any overlapping samples.
    """
    set_train = set(train_text)
    set_val = set(val_text)
    set_test = set(test_text)

    overlap_train_val = set_train.intersection(set_val)
    overlap_train_test = set_train.intersection(set_test)
    overlap_val_test = set_val.intersection(set_test)

    has_leakage = bool(overlap_train_val or overlap_train_test or overlap_val_test)

    return {
        "train_count": len(train_text),
        "val_count": len(val_text),
        "test_count": len(test_text),
        "overlap_train_val_count": len(overlap_train_val),
        "overlap_train_test_count": len(overlap_train_test),
        "overlap_val_test_count": len(overlap_val_test),
        "has_leakage": has_leakage,
        "leakage_clean": not has_leakage
    }
