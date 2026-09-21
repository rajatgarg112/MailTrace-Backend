"""
TF-IDF Text Classifier for Spam & Phishing score estimation.
Supports optional n-gram tokenization (unigrams, bigrams) and safe JSON model persistence.
"""

import json
import math
import re
from typing import List, Dict, Tuple, Optional, Any
from ml.schemas import MLPredictionResult


def validate_ngram_range(ngram_range: Any) -> Tuple[int, int]:
    """
    Validate ngram_range parameter.
    Must be a tuple or list of 2 integers (min_n, max_n) where 1 <= min_n <= max_n.
    """
    if not isinstance(ngram_range, (tuple, list)) or len(ngram_range) != 2:
        raise ValueError(f"Invalid ngram_range: {ngram_range}. Must be a tuple or list of 2 integers (min_n, max_n).")
    min_n, max_n = ngram_range
    if not isinstance(min_n, int) or not isinstance(max_n, int):
        raise ValueError(f"Invalid ngram_range bounds: ({type(min_n).__name__}, {type(max_n).__name__}). Bounds must be integers.")

    if min_n < 1 or max_n < min_n:
        raise ValueError(f"Invalid ngram_range values: ({min_n}, {max_n}). Bounds must satisfy 1 <= min_n <= max_n.")

    return (min_n, max_n)


class SimpleTFIDFClassifier:
    """
    Lightweight, dependency-free TF-IDF Naive Bayes Classifier.
    Supports configurable n-gram token ranges and safe JSON model serialization.
    """

    def __init__(
        self,
        ngram_range: Tuple[int, int] = (1, 1),
        model_version: str = "1.0",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.ngram_range = validate_ngram_range(ngram_range)
        self.model_version: str = str(model_version)
        self.metadata: Dict[str, Any] = dict(metadata) if metadata else {}
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.class_priors: Dict[str, float] = {}
        self.feature_log_probs: Dict[str, Dict[str, float]] = {}
        self.is_trained: bool = False

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        unigrams = re.findall(r'\b[a-z0-9_]{2,}\b', text)
        if self.ngram_range == (1, 1) or not unigrams:
            return unigrams

        tokens = list(unigrams)
        min_n, max_n = self.ngram_range
        if max_n >= 2:
            for i in range(len(unigrams) - 1):
                bigram = f"{unigrams[i]}_{unigrams[i+1]}"
                tokens.append(bigram)
        return tokens

    def train(self, documents: List[str], labels: List[str]) -> None:
        """Train classifier on dataset documents and labels."""
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

    def predict(self, text: str) -> MLPredictionResult:
        """
        Convenience inference method returning structured MLPredictionResult.
        Calls predict_proba() without retraining or mutating model state.
        """
        probs = self.predict_proba(text)
        best_label = max(probs, key=probs.get)
        confidence = probs[best_label]

        return MLPredictionResult(
            prediction=best_label,
            confidence=confidence,
            model_version=self.model_version,
            probabilities=probs
        )

    def save_model(self, file_path: str) -> None:
        """
        Serialize trained model state safely to a JSON file.
        Raises ValueError if model is untrained.
        """
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model.")

        model_data = {
            "version": self.model_version,
            "ngram_range": list(self.ngram_range),
            "vocab": self.vocab,
            "idf": self.idf,
            "class_priors": self.class_priors,
            "feature_log_probs": self.feature_log_probs,
            "metadata": self.metadata,
            "is_trained": True
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(model_data, f, indent=2)

    @classmethod
    def load_model(cls, file_path: str) -> "SimpleTFIDFClassifier":
        """
        Deserialize model state safely from a JSON file.
        Raises ValueError if JSON file is invalid or malformed.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to read model file '{file_path}': {e}")

        if not isinstance(data, dict):
            raise ValueError("Invalid or malformed model file: root JSON object must be a dictionary.")

        required_keys = ["ngram_range", "vocab", "idf", "class_priors", "feature_log_probs", "is_trained"]
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Invalid or malformed model file: missing required key '{key}'.")

        ngram_range = validate_ngram_range(data["ngram_range"])
        version = str(data.get("version", "1.0"))
        metadata = dict(data.get("metadata", {}))
        classifier = cls(ngram_range=ngram_range, model_version=version, metadata=metadata)

        classifier.vocab = dict(data["vocab"])
        classifier.idf = {k: float(v) for k, v in data["idf"].items()}
        classifier.class_priors = {k: float(v) for k, v in data["class_priors"].items()}
        classifier.feature_log_probs = {
            lbl: {term: float(prob) for term, prob in terms.items()}
            for lbl, terms in data["feature_log_probs"].items()
        }
        classifier.is_trained = bool(data["is_trained"])

        return classifier
