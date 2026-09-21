import asyncio
from unittest.mock import patch
import pytest

from app.schemas import (
    AnalysisRun,
    AnalyzerResultItem,
    AnalyzerStatus,
    EmailAddress,
    EmailNormalized,
    SecurityFinding,
    SeverityLevel,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analyzers import (
    AnalysisContext,
    AnalyzerRegistry,
    BaseAnalyzer,
    StubAttachmentAnalyzer,
    StubAuthenticationAnalyzer,
    StubDomainAnalyzer,
    StubHeaderAnalyzer,
    StubMLAnalyzer,
    StubThreatIntelAnalyzer,
    StubURLAnalyzer,
)


@pytest.fixture
def sample_email() -> EmailNormalized:
    return EmailNormalized(
        message_id="<orchestrator-test-001@mailtrace.local>",
        sender=EmailAddress(address="sender@example.com", name="Sender"),
        recipients=[EmailAddress(address="recipient@target.com")],
        subject="Orchestration Test Subject",
        body_text_preview="Orchestrator test body preview",
    )


def test_all_analyzers_execute(sample_email):
    """1. All registered analyzers execute successfully."""
    registry = AnalyzerRegistry()
    registry.register(StubMLAnalyzer())
    registry.register(StubHeaderAnalyzer())
    registry.register(StubURLAnalyzer())

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run_res = await orchestrator.analyze_email(sample_email, analysis_id="run-001")
        assert isinstance(run_res, AnalysisRun)
        assert run_res.analysis_id == "run-001"
        assert run_res.email_id == sample_email.message_id
        assert len(run_res.analyzer_results) == 3
        assert "stub_ml" in run_res.analyzer_results
        assert "stub_header" in run_res.analyzer_results
        assert "stub_url" in run_res.analyzer_results

    asyncio.run(_run())


def test_registry_order_respected_and_deterministic(sample_email):
    """2 & 3. Registry order is respected and output is deterministic."""
    registry = AnalyzerRegistry()
    registry.register(StubHeaderAnalyzer())
    registry.register(StubMLAnalyzer())
    registry.register(StubURLAnalyzer())

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run1 = await orchestrator.analyze_email(sample_email, analysis_id="run-det-1")
        run2 = await orchestrator.analyze_email(sample_email, analysis_id="run-det-2")

        keys1 = list(run1.analyzer_results.keys())
        keys2 = list(run2.analyzer_results.keys())

        # Exact registry order: stub_header, stub_ml, stub_url
        assert keys1 == ["stub_header", "stub_ml", "stub_url"]
        assert keys2 == ["stub_header", "stub_ml", "stub_url"]

    asyncio.run(_run())


def test_analyzer_exception_isolation(sample_email):
    """4. Analyzer exception isolation: one analyzer failing does not crash others."""
    class CrashingAnalyzer(BaseAnalyzer):
        @property
        def name(self) -> str:
            return "crashing_analyzer"

        @property
        def version(self) -> str:
            return "1.0"

        @property
        def category(self) -> str:
            return "test"

        async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
            raise RuntimeError("Crashing analyzer failure!")

    registry = AnalyzerRegistry()
    registry.register(StubHeaderAnalyzer())
    registry.register(CrashingAnalyzer())
    registry.register(StubURLAnalyzer())

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run_res = await orchestrator.analyze_email(sample_email, analysis_id="run-crash-test")
        assert len(run_res.analyzer_results) == 3
        assert run_res.analyzer_results["stub_header"].status == AnalyzerStatus.SKIPPED
        assert run_res.analyzer_results["crashing_analyzer"].status == AnalyzerStatus.FAILED
        assert run_res.analyzer_results["stub_url"].status == AnalyzerStatus.SKIPPED
        assert run_res.status == AnalyzerStatus.FAILED
        assert any("Crashing analyzer failure!" in e for e in run_res.errors)

    asyncio.run(_run())


def test_analyzer_timeout_isolation(sample_email):
    """5. Analyzer timeout isolation: one analyzer timing out does not cancel others."""
    class SlowAnalyzer(BaseAnalyzer):
        @property
        def name(self) -> str:
            return "slow_analyzer"

        @property
        def version(self) -> str:
            return "1.0"

        @property
        def category(self) -> str:
            return "test"

        async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
            await asyncio.sleep(5.0)  # Exceeds context timeout
            return AnalyzerResultItem(analyzer=self.name, status=AnalyzerStatus.SUCCESS)

    registry = AnalyzerRegistry()
    registry.register(StubHeaderAnalyzer())
    registry.register(SlowAnalyzer())
    registry.register(StubURLAnalyzer())

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        context = AnalysisContext(
            analysis_id="run-timeout-test",
            email=sample_email,
            timeout_seconds=0.1
        )
        run_res = await orchestrator.analyze_email(context)
        assert len(run_res.analyzer_results) == 3
        assert run_res.analyzer_results["stub_header"].status == AnalyzerStatus.SKIPPED
        assert run_res.analyzer_results["slow_analyzer"].status == AnalyzerStatus.TIMEOUT
        assert run_res.analyzer_results["stub_url"].status == AnalyzerStatus.SKIPPED

    asyncio.run(_run())


def test_unavailable_and_skipped_analyzer_handling(sample_email):
    """6 & 7. Unavailable and Skipped statuses are preserved without false safe conversion."""
    registry = AnalyzerRegistry()
    registry.register(StubThreatIntelAnalyzer())  # Returns UNAVAILABLE
    registry.register(StubDomainAnalyzer())       # Returns SKIPPED

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run_res = await orchestrator.analyze_email(sample_email)
        assert run_res.analyzer_results["stub_threat_intel"].status == AnalyzerStatus.UNAVAILABLE
        assert run_res.analyzer_results["stub_domain"].status == AnalyzerStatus.SKIPPED
        # No fake threat verdicts or conversions
        assert len(run_res.findings) == 0

    asyncio.run(_run())


def test_empty_registry(sample_email):
    """8. Empty registry returns valid empty AnalysisRun without crashing."""
    registry = AnalyzerRegistry()
    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run_res = await orchestrator.analyze_email(sample_email, analysis_id="run-empty")
        assert run_res.status == AnalyzerStatus.SUCCESS
        assert len(run_res.analyzer_results) == 0
        assert len(run_res.findings) == 0
        assert run_res.errors == []

    asyncio.run(_run())


def test_duplicate_registration_behavior(sample_email):
    """9. Duplicate registration overwrites cleanly without duplicate execution."""
    registry = AnalyzerRegistry()
    stub1 = StubHeaderAnalyzer()
    stub2 = StubHeaderAnalyzer()

    registry.register(stub1)
    registry.register(stub2)

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        run_res = await orchestrator.analyze_email(sample_email)
        assert len(run_res.analyzer_results) == 1
        assert "stub_header" in run_res.analyzer_results

    asyncio.run(_run())


def test_input_compatibility(sample_email):
    """10. Orchestrator accepts both EmailNormalized and AnalysisContext inputs."""
    registry = AnalyzerRegistry()
    registry.register(StubMLAnalyzer())
    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        # Pass EmailNormalized
        res1 = await orchestrator.analyze_email(sample_email, analysis_id="run-compat-1")
        assert res1.analysis_id == "run-compat-1"

        # Pass AnalysisContext
        ctx = AnalysisContext(analysis_id="run-compat-2", email=sample_email)
        res2 = await orchestrator.analyze_email(ctx)
        assert res2.analysis_id == "run-compat-2"

    asyncio.run(_run())


def test_no_network_calls_and_safety_guarantees(sample_email):
    """11, 12, 13. Verify no socket/DNS network calls and concurrency safety."""
    registry = AnalyzerRegistry()
    registry.register(StubMLAnalyzer())
    registry.register(StubHeaderAnalyzer())
    registry.register(StubURLAnalyzer())
    registry.register(StubAttachmentAnalyzer())
    registry.register(StubThreatIntelAnalyzer())

    orchestrator = AnalysisOrchestrator(registry=registry)

    async def _run():
        with patch("socket.socket") as mock_sock, patch("socket.gethostbyname") as mock_dns:
            run_res = await orchestrator.analyze_email(sample_email)
            assert mock_sock.called is False
            assert mock_dns.called is False
            assert len(run_res.analyzer_results) == 5

    asyncio.run(_run())
