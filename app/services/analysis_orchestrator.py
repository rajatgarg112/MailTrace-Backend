import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from app.core.config import settings
from app.schemas.analysis import AnalysisRun, AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.email import EmailNormalized
from app.schemas.security import SecurityFinding
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.context import AnalysisContext
from app.services.analyzers.registry import AnalyzerRegistry, default_registry
from app.services.analyzers.result import create_analyzer_result, create_failed_result


class AnalysisOrchestrator:
    """Orchestrates async, safe execution of registered analyzers on an ingested email."""

    def __init__(self, registry: Optional[AnalyzerRegistry] = None):
        self.registry = registry or default_registry

    async def analyze_email(
        self,
        email_input: Union[EmailNormalized, AnalysisContext],
        analysis_id: Optional[str] = None
    ) -> AnalysisRun:
        """Executes registered analyzers concurrently with timeout and error isolation."""
        start_time = datetime.now(timezone.utc)

        # Build AnalysisContext if EmailNormalized is passed
        if isinstance(email_input, EmailNormalized):
            run_id = analysis_id or f"run-{uuid.uuid4().hex[:12]}"
            context = AnalysisContext(analysis_id=run_id, email=email_input)
        elif isinstance(email_input, AnalysisContext):
            context = email_input
            if analysis_id:
                context = AnalysisContext(
                    analysis_id=analysis_id,
                    email=context.email,
                    metadata=context.metadata,
                    timeout_seconds=context.timeout_seconds
                )
        else:
            raise TypeError("email_input must be an EmailNormalized or AnalysisContext instance")

        analyzers = self.registry.list_analyzers()

        if not analyzers:
            end_time = datetime.now(timezone.utc)
            return AnalysisRun(
                analysis_id=context.analysis_id,
                email_id=context.email.message_id,
                status=AnalyzerStatus.SUCCESS,
                analyzer_results={},
                findings=[],
                tags=[],
                created_at=start_time,
                completed_at=end_time,
                errors=[]
            )

        # Create concurrent tasks with per-analyzer timeout protection
        tasks = [self._execute_single_analyzer(analyzer, context) for analyzer in analyzers]
        results_list = await asyncio.gather(*tasks)

        # Process results in deterministic registry order
        analyzer_results: Dict[str, AnalyzerResultItem] = {}
        all_findings: List[SecurityFinding] = []
        errors: List[str] = []
        overall_status = AnalyzerStatus.SUCCESS

        for result_item in results_list:
            analyzer_results[result_item.analyzer] = result_item
            all_findings.extend(result_item.findings)

            if result_item.status == AnalyzerStatus.FAILED:
                if overall_status == AnalyzerStatus.SUCCESS:
                    overall_status = AnalyzerStatus.FAILED
                if result_item.error_message:
                    errors.append(f"[{result_item.analyzer}] {result_item.error_message}")
            elif result_item.status == AnalyzerStatus.TIMEOUT:
                if result_item.error_message:
                    errors.append(f"[{result_item.analyzer}] {result_item.error_message}")

        end_time = datetime.now(timezone.utc)

        return AnalysisRun(
            analysis_id=context.analysis_id,
            email_id=context.email.message_id,
            status=overall_status,
            analyzer_results=analyzer_results,
            findings=all_findings,
            tags=[],
            created_at=start_time,
            completed_at=end_time,
            errors=errors
        )

    async def _execute_single_analyzer(
        self,
        analyzer: BaseAnalyzer,
        context: AnalysisContext
    ) -> AnalyzerResultItem:
        """Executes a single analyzer wrapped with timeout protection and safe_analyze error isolation."""
        timeout_sec = context.timeout_seconds
        start_perf = time.perf_counter()

        try:
            return await asyncio.wait_for(
                analyzer.safe_analyze(context),
                timeout=timeout_sec
            )
        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
            return create_analyzer_result(
                analyzer_name=analyzer.name,
                status=AnalyzerStatus.TIMEOUT,
                execution_time_ms=elapsed_ms,
                error_message=f"Analyzer timed out after {timeout_sec}s"
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
            return create_failed_result(
                analyzer_name=analyzer.name,
                error_message=f"Orchestration execution error: {str(exc)}"
            )
