"""
TF-IDF Text Classifier for Spam & Phishing score estimation.
Supports sklearn if available, or falls back to an internal TF-IDF + Naive Bayes implementation.
"""

import math
import re
from typing import List, Dict, Tuple, Optional


class SimpleTFIDFClassifier:
    """
    Lightweight, dependency-free TF-IDF Naive Bayes Classifier.
    Used for text classification (spam / phishing / benign) when heavy models are unneeded or offline.
    """

    def __init__(self):
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.class_priors: Dict[str, float] = {}
        self.feature_log_probs: Dict[str, Dict[str, float]] = {}
        self.is_trained: bool = False

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'\b[a-z0-9_]{2,}\b', text)
        return tokens

    def train(self, documents: List[str], labels: List[str]) -> None:
        """Train classifier on sample dataset."""
        if not documents or not labels or len(documents) != len(labels):
            raise ValueError("Documents and labels must be non-empty and of equal length.")

        total_docs = len(documents)
        unique_labels = set(labels)
        doc_count_per_label = {lbl: labels.count(lbl) for lbl in unique_labels}
        self.class_priors = {lbl: math.log(cnt / total_docs) for lbl, cnt in doc_count_per_label.items()}

        # Build vocabulary & Document Frequencies
        df: Dict[str, int] = {}
        tokenized_docs = [self._tokenize(doc) for doc in documents]

        for tokens in tokenized_docs:
            seen = set(tokens)
            for t in seen:
                df[t] = df.get(t, 0) + 1

        self.vocab = {t: idx for idx, t in enumerate(sorted(df.keys()))}
        self.idf = {t: math.log((1 + total_docs) / (1 + count)) + 1.0 for t, count in df.items()}

        # Calculate TF-IDF vectors per doc
        label_word_counts: Dict[str, Dict[str, float]] = {lbl: {} for lbl in unique_labels}
        label_total_weights: Dict[str, float] = {lbl: 0.0 for lbl in unique_labels}

        for tokens, lbl in zip(tokenized_docs, labels):
            tf: Dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1

            for t, count in tf.items():
                tfidf_val = count * self.idf.get(t, 1.0)
                label_word_counts[lbl][t] = label_word_counts[lbl].get(t, 0.0) + tfidf_val
                label_total_weights[lbl] += tfidf_val

        # Smooth log likelihoods
        vocab_size = len(self.vocab)
        self.feature_log_probs = {lbl: {} for lbl in unique_labels}

        for lbl in unique_labels:
            denom = label_total_weights[lbl] + vocab_size
            for term in self.vocab:
                count = label_word_counts[lbl].get(term, 0.0)
                self.feature_log_probs[lbl][term] = math.log((count + 1.0) / denom)

        self.is_trained = True

    def predict_proba(self, text: str) -> Dict[str, float]:
        """Predict class probability distribution for input text."""
        if not self.is_trained:
            # Return baseline prior probabilities if untrained
            return {"spam": 0.1, "phishing": 0.1, "benign": 0.8}

        tokens = self._tokenize(text)
        log_probs: Dict[str, float] = {}

        for lbl, prior in self.class_priors.items():
            score = prior
            for t in tokens:
                if t in self.vocab:
                    score += self.feature_log_probs[lbl][t]
            log_probs[lbl] = score

        # Softmax conversion
        max_log = max(log_probs.values())
        exp_scores = {lbl: math.exp(val - max_log) for lbl, val in log_probs.items()}
        sum_exp = sum(exp_scores.values())

        return {lbl: val / sum_exp for lbl, val in exp_scores.items()}
