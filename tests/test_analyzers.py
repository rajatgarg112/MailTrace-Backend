import asyncio
import pytest

from app.schemas import AnalyzerStatus, EmailAddress, EmailNormalized
from app.services.analyzers import (
    AnalysisContext,
    AnalyzerRegistry,
    BaseAnalyzer,
    StubAttachmentAnalyzer,
    StubAuthenticationAnalyzer,
    StubDomainAnalyzer,
    StubForensicAnalyzer,
    StubHeaderAnalyzer,
    StubInfrastructureAnalyzer,
    StubMLAnalyzer,
    StubRelayAnalyzer,
    StubThreatIntelAnalyzer,
    StubURLAnalyzer,
    create_failed_result,
)


@pytest.fixture
def sample_context() -> AnalysisContext:
    email = EmailNormalized(
        message_id="<test-msg-001@mailtrace.local>",
        sender=EmailAddress(address="sender@example.com", name="Sender"),
        recipients=[EmailAddress(address="recipient@example.com")],
        subject="Test Analysis Context Email",
    )
    return AnalysisContext(analysis_id="analysis-run-001", email=email)


def test_base_analyzer_import_and_context(sample_context):
    """1 & 2. Base analyzer/interface can be imported and context created."""
    assert BaseAnalyzer is not None
    assert sample_context.analysis_id == "analysis-run-001"
    assert sample_context.email.sender.address == "sender@example.com"
    assert sample_context.timeout_seconds > 0.0


def test_stub_analyzers_deterministic_results(sample_context):
    """3 & 4. Stub analyzers return deterministic safe SKIPPED/UNAVAILABLE results."""
    async def _run():
        stubs = [
            StubMLAnalyzer(),
            StubHeaderAnalyzer(),
            StubDomainAnalyzer(),
            StubAuthenticationAnalyzer(),
            StubURLAnalyzer(),
            StubRelayAnalyzer(),
            StubInfrastructureAnalyzer(),
            StubAttachmentAnalyzer(),
            StubForensicAnalyzer(),
        ]

        for stub in stubs:
            res = await stub.analyze(sample_context)
            assert res.analyzer == stub.name
            assert res.status == AnalyzerStatus.SKIPPED
            # Must not return fake malicious findings
            assert len(res.findings) == 0
            assert "stub implementation" in res.error_message.lower()

        # Threat Intel stub returns UNAVAILABLE cleanly
        ti_stub = StubThreatIntelAnalyzer()
        ti_res = await ti_stub.analyze(sample_context)
        assert ti_res.analyzer == ti_stub.name
        assert ti_res.status == AnalyzerStatus.UNAVAILABLE
        assert len(ti_res.findings) == 0

    asyncio.run(_run())


def test_analyzer_registry_operations():
    """5, 6, 7. Registry can register, retrieve, list, and filter analyzers."""
    registry = AnalyzerRegistry()
    ml_stub = StubMLAnalyzer()
    url_stub = StubURLAnalyzer()

    # Register
    registry.register(ml_stub)
    registry.register(url_stub)

    # Retrieve
    assert registry.get("stub_ml") == ml_stub
    assert registry.get("stub_url") == url_stub
    assert registry.get("non_existent") is None

    # List
    all_analyzers = registry.list_analyzers()
    assert len(all_analyzers) == 2
    assert ml_stub in all_analyzers
    assert url_stub in all_analyzers

    # Filter by category
    ml_category = registry.get_by_category("ml")
    assert len(ml_category) == 1
    assert ml_category[0] == ml_stub


def test_analyzer_error_isolation(sample_context):
    """8. Analyzer failure can be represented using canonical FAILED status."""
    class FaultyAnalyzer(BaseAnalyzer):
        @property
        def name(self) -> str:
            return "faulty_analyzer"

        @property
        def version(self) -> str:
            return "1.0.0"

        @property
        def category(self) -> str:
            return "test"

        async def analyze(self, context: AnalysisContext):
            raise ValueError("Simulated unexpected analyzer crash")

    async def _run():
        faulty = FaultyAnalyzer()
        # safe_analyze catches exception and isolates pipeline error
        res = await faulty.safe_analyze(sample_context)
        assert res.analyzer == "faulty_analyzer"
        assert res.status == AnalyzerStatus.FAILED
        assert "Simulated unexpected analyzer crash" in res.error_message

    asyncio.run(_run())


def test_no_external_network_calls(sample_context):
    """9. Verify no external network calls are performed by stubs."""
    async def _run():
        ti_stub = StubThreatIntelAnalyzer()
        res = await ti_stub.analyze(sample_context)
        assert res.status == AnalyzerStatus.UNAVAILABLE
        assert "stubbed" in res.error_message.lower()

    asyncio.run(_run())
