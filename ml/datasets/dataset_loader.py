"""
Dataset loader and record validation interface for ML training/evaluation pipelines.
Provides structured DatasetRecord models and DatasetLoader utilities.
"""

import json
from typing import List, Dict, Any, Tuple, Optional
from pydantic import BaseModel, Field


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
    Generic loader for dataset records from Python structures or JSON files.
    """

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
