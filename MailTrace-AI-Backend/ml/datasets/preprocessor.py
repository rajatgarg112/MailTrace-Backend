"""
Email text dataset preprocessing and normalization utilities.
"""

import re
import html
from typing import List, Tuple, Dict


def clean_html_and_normalize(raw_text: str) -> str:
    """
    Remove HTML tags, decode entities, and normalize whitespace.
    """
    if not raw_text:
        return ""

    # Decode HTML entities
    text = html.unescape(raw_text)

    # Strip HTML tags
    text = re.sub(r'<[^>]+>', '', text)

    # Replace multiple whitespaces/newlines with a single space
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def prepare_dataset_split(
    samples: List[Tuple[str, str]],
    train_ratio: float = 0.8,
    seed: int = 42
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Splits samples (text, label) into (train_text, train_labels, test_text, test_labels).
    Reproducible split as required by TESTING.md.
    """
    import random
    rng = random.Random(seed)
    shuffled = samples.copy()
    rng.shuffle(shuffled)

    split_idx = int(len(shuffled) * train_ratio)
    train_samples = shuffled[:split_idx]
    test_samples = shuffled[split_idx:]

    train_text = [clean_html_and_normalize(item[0]) for item in train_samples]
    train_labels = [item[1] for item in train_samples]

    test_text = [clean_html_and_normalize(item[0]) for item in test_samples]
    test_labels = [item[1] for item in test_samples]

    return train_text, train_labels, test_text, test_labels
