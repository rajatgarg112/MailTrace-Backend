"""
Dataset loader and record validation interface for ML training/evaluation pipelines.
Provides structured DatasetRecord models and DatasetLoader utilities.
"""

import csv
import json
import os
import sys
from typing import List, Dict, Any, Tuple, Optional, Union
from pydantic import BaseModel, Field

# Ensure large CSV text fields (e.g. lengthy email bodies) do not exceed field limits
try:
    csv.field_size_limit(100 * 1024 * 1024)
except Exception:
    pass


ALLOWED_LABELS = {"phishing", "spam", "benign"}


class DatasetRecord(BaseModel):
    """Structured representation of a single dataset record."""
    text: str = Field(..., description="Raw or preprocessed email text content")
    label: str = Field(..., description="Target security classification label ('phishing', 'spam', 'benign')")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional metadata (e.g. source, ID)")

    def validate_record(self) -> bool:
        """Validate label and text non-emptiness."""
        if not self.text or not isinstance(self.text, str):
            return False
        if not self.label or self.label.lower() not in ALLOWED_LABELS:
            return False
        return True


class DatasetLoader:
    """
    Generic loader for dataset records from Python structures, JSON files, and CSV datasets.
    Supports dataset-specific column and label normalization (e.g. spam_ham_dataset, CEAS_08).
    """

    last_load_stats: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_tuples(records: List[Tuple[str, str]]) -> List[DatasetRecord]:
        """Convert list of (text, label) tuples into validated DatasetRecords."""
        loaded = []
        for item in records:
            if isinstance(item, (tuple, list)) and len(item) >= 2:
                rec = DatasetRecord(text=str(item[0]), label=str(item[1]).lower())
                if rec.validate_record():
                    loaded.append(rec)
        return loaded

    @staticmethod
    def from_dicts(records: List[Dict[str, Any]]) -> List[DatasetRecord]:
        """Convert list of dicts into validated DatasetRecords."""
        loaded = []
        for d in records:
            if "text" in d and "label" in d:
                rec = DatasetRecord(
                    text=str(d["text"]),
                    label=str(d["label"]).lower(),
                    metadata=d.get("metadata", {})
                )
                if rec.validate_record():
                    loaded.append(rec)
        return loaded

    @staticmethod
    def from_json_string(json_str: str) -> List[DatasetRecord]:
        """Parse JSON string containing list of records into DatasetRecords."""
        data = json.loads(json_str)
        if isinstance(data, list):
            return DatasetLoader.from_dicts(data)
        raise ValueError("JSON input must be a list of record objects.")

    @classmethod
    def load_csv_with_stats(
        cls,
        file_path: str,
        text_column: Optional[str] = None,
        label_column: Optional[str] = None,
        subject_column: Optional[str] = None,
        body_column: Optional[str] = None,
        label_map: Optional[Dict[Any, str]] = None,
        dataset_type: Optional[str] = None,
        encoding: str = "utf-8",
        errors: str = "replace",
        max_rows: Optional[int] = None
    ) -> Tuple[List[DatasetRecord], Dict[str, Any]]:
        """
        Load records from CSV file with column validation, label normalization,
        safe handling of malformed/missing fields, and load statistics reporting.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"CSV dataset file not found at: '{file_path}'")

        records: List[DatasetRecord] = []
        total_rows = 0
        skipped_rows = 0
        skip_reasons: Dict[str, int] = {
            "empty_text": 0,
            "invalid_label": 0,
            "validation_failed": 0,
            "csv_parse_error": 0
        }
        label_distribution: Dict[str, int] = {}

        with open(file_path, mode="r", encoding=encoding, errors=errors) as f:
            reader = csv.DictReader(f)
            headers = [h.strip() for h in (reader.fieldnames or []) if h]
            header_map = {h.lower(): h for h in headers}

            # Auto-detect dataset_type if not provided
            detected_type = dataset_type
            if not detected_type:
                if "text" in header_map and ("label" in header_map or "label_num" in header_map):
                    detected_type = "spam_ham"
                elif "subject" in header_map and "body" in header_map and "label" in header_map:
                    detected_type = "ceas"
                else:
                    detected_type = "custom"

            # Configure effective column names and label mappings
            effective_text_col = text_column
            effective_subj_col = subject_column
            effective_body_col = body_column
            effective_label_col = label_column
            effective_label_map = label_map

            if detected_type == "spam_ham":
                if not effective_text_col:
                    effective_text_col = header_map.get("text", "text")
                if not effective_label_col:
                    effective_label_col = header_map.get("label", "label")
                if effective_label_map is None:
                    effective_label_map = {
                        "ham": "benign", "spam": "spam",
                        "0": "benign", "1": "spam",
                        0: "benign", 1: "spam"
                    }
            elif detected_type == "ceas":
                if not effective_subj_col:
                    effective_subj_col = header_map.get("subject", "subject")
                if not effective_body_col:
                    effective_body_col = header_map.get("body", "body")
                if not effective_label_col:
                    effective_label_col = header_map.get("label", "label")
                if effective_label_map is None:
                    effective_label_map = {
                        "0": "benign", "1": "spam",
                        "ham": "benign", "spam": "spam",
                        0: "benign", 1: "spam"
                    }
            else:
                if not effective_text_col and "text" in header_map:
                    effective_text_col = header_map["text"]
                if not effective_label_col and "label" in header_map:
                    effective_label_col = header_map["label"]
                if effective_label_map is None:
                    effective_label_map = {}

            # Validate required columns exist in headers
            if not effective_text_col and not (effective_subj_col or effective_body_col):
                raise ValueError(
                    f"Required text column missing for dataset type '{detected_type}'. "
                    f"Available headers: {headers}"
                )
            if not effective_label_col or effective_label_col not in headers:
                raise ValueError(
                    f"Required label column '{effective_label_col}' not found in CSV headers: {headers}"
                )

            for row in reader:
                total_rows += 1
                try:
                    # Construct text content
                    if effective_text_col and effective_text_col in row:
                        raw_text = row.get(effective_text_col) or ""
                    else:
                        subj = (row.get(effective_subj_col) or "").strip() if effective_subj_col else ""
                        body = (row.get(effective_body_col) or "").strip() if effective_body_col else ""
                        if subj and body:
                            raw_text = f"{subj} {body}"
                        else:
                            raw_text = subj or body

                    if not isinstance(raw_text, str) or not raw_text.strip():
                        skipped_rows += 1
                        skip_reasons["empty_text"] += 1
                        continue

                    # Normalize label
                    raw_lbl = str(row.get(effective_label_col, "")).strip().lower()
                    if effective_label_map and raw_lbl in effective_label_map:
                        norm_lbl = effective_label_map[raw_lbl]
                    elif raw_lbl in ALLOWED_LABELS:
                        norm_lbl = raw_lbl
                    else:
                        skipped_rows += 1
                        skip_reasons["invalid_label"] += 1
                        continue

                    rec = DatasetRecord(
                        text=raw_text.strip(),
                        label=norm_lbl,
                        metadata={"source": detected_type, "row_index": total_rows}
                    )
                    if rec.validate_record():
                        records.append(rec)
                        label_distribution[norm_lbl] = label_distribution.get(norm_lbl, 0) + 1
                    else:
                        skipped_rows += 1
                        skip_reasons["validation_failed"] += 1

                except Exception:
                    skipped_rows += 1
                    skip_reasons["csv_parse_error"] += 1

                if max_rows and len(records) >= max_rows:
                    break

        stats = {
            "file_path": file_path,
            "total_rows": total_rows,
            "valid_records": len(records),
            "skipped_rows": skipped_rows,
            "skip_reasons": skip_reasons,
            "label_distribution": label_distribution,
            "dataset_type": detected_type,
            "columns": headers
        }
        cls.last_load_stats = stats
        return records, stats

    @classmethod
    def from_csv(
        cls,
        file_path: str,
        text_column: Optional[str] = None,
        label_column: Optional[str] = None,
        subject_column: Optional[str] = None,
        body_column: Optional[str] = None,
        label_map: Optional[Dict[Any, str]] = None,
        dataset_type: Optional[str] = None,
        encoding: str = "utf-8",
        errors: str = "replace",
        max_rows: Optional[int] = None
    ) -> List[DatasetRecord]:
        """Convenience loader returning only List[DatasetRecord]."""
        records, _ = cls.load_csv_with_stats(
            file_path=file_path,
            text_column=text_column,
            label_column=label_column,
            subject_column=subject_column,
            body_column=body_column,
            label_map=label_map,
            dataset_type=dataset_type,
            encoding=encoding,
            errors=errors,
            max_rows=max_rows
        )
        return records
