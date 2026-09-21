from abc import ABC, abstractmethod
import time
from typing import Any, Dict

from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.services.analyzers.context import AnalysisContext
from app.services.analyzers.result import create_failed_result


class BaseAnalyzer(ABC):
    """Abstract Base Class for all MailTrace-AI analyzers (M3, M4, M6)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique analyzer identifier (e.g. ml_content, url_reputation, dkim)."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Analyzer version string."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Logical analyzer category (e.g. ml, header, domain, url, threat_intel)."""
        pass

    @abstractmethod
    async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
        """Perform analysis on the provided AnalysisContext."""
        pass

    async def safe_analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
        """Wrapper method executing analyze with error isolation to prevent pipeline failure."""
        start_time = time.perf_counter()
        try:
            result = await self.analyze(context)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if result.execution_time_ms is None or result.execution_time_ms == 0.0:
                result.execution_time_ms = elapsed_ms
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            res = create_failed_result(
                analyzer_name=self.name,
                error_message=f"Analyzer error: {str(exc)}"
            )
            res.execution_time_ms = elapsed_ms
            return res
