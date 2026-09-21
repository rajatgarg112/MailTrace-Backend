from typing import Any, Dict, List, Optional
from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.security import SecurityFinding


def create_analyzer_result(
    analyzer_name: str,
    status: AnalyzerStatus,
    features: Optional[Dict[str, Any]] = None,
    findings: Optional[List[SecurityFinding]] = None,
    execution_time_ms: Optional[float] = 0.0,
    error_message: Optional[str] = None,
) -> AnalyzerResultItem:
    """Helper to construct a canonical AnalyzerResultItem."""
    return AnalyzerResultItem(
        analyzer=analyzer_name,
        status=status,
        features=features or {},
        findings=findings or [],
        execution_time_ms=execution_time_ms,
        error_message=error_message,
    )


def create_skipped_result(
    analyzer_name: str,
    reason: str = "Stub implementation - analysis skipped",
) -> AnalyzerResultItem:
    """Constructs a standard SKIPPED analyzer result."""
    return create_analyzer_result(
        analyzer_name=analyzer_name,
        status=AnalyzerStatus.SKIPPED,
        error_message=reason,
    )


def create_unavailable_result(
    analyzer_name: str,
    reason: str = "External analyzer service unavailable",
) -> AnalyzerResultItem:
    """Constructs a standard UNAVAILABLE analyzer result."""
    return create_analyzer_result(
        analyzer_name=analyzer_name,
        status=AnalyzerStatus.UNAVAILABLE,
        error_message=reason,
    )


def create_failed_result(
    analyzer_name: str,
    error_message: str,
) -> AnalyzerResultItem:
    """Constructs a standard FAILED analyzer result."""
    return create_analyzer_result(
        analyzer_name=analyzer_name,
        status=AnalyzerStatus.FAILED,
        error_message=error_message,
    )
