from app.schemas.analysis import AnalyzerResultItem
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.context import AnalysisContext
from app.services.analyzers.result import create_skipped_result, create_unavailable_result


class BaseStubAnalyzer(BaseAnalyzer):
    """Base class for safe deterministic analyzer stubs."""

    def __init__(self, name_str: str, category_str: str, version_str: str = "0.1.0-stub"):
        self._name = name_str
        self._category = category_str
        self._version = version_str

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def category(self) -> str:
        return self._category

    async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
        """Default stub returns SKIPPED status without false threat findings or network calls."""
        return create_skipped_result(
            analyzer_name=self.name,
            reason=f"Stub implementation for {self.name} - analysis skipped"
        )


class StubMLAnalyzer(BaseStubAnalyzer):
    """M3 ML Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_ml", category_str="ml")


class StubHeaderAnalyzer(BaseStubAnalyzer):
    """M4 Header Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_header", category_str="header")


class StubDomainAnalyzer(BaseStubAnalyzer):
    """M4 Domain Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_domain", category_str="domain")


class StubAuthenticationAnalyzer(BaseStubAnalyzer):
    """M4 Email Authentication (SPF/DKIM/DMARC) Stub."""
    def __init__(self):
        super().__init__(name_str="stub_authentication", category_str="authentication")


class StubURLAnalyzer(BaseStubAnalyzer):
    """M4 URL Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_url", category_str="url")


class StubRelayAnalyzer(BaseStubAnalyzer):
    """M4 Relay/Received-Hop Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_relay", category_str="relay")


class StubThreatIntelAnalyzer(BaseStubAnalyzer):
    """M4 Threat Intelligence Adapter Stub."""
    def __init__(self):
        super().__init__(name_str="stub_threat_intel", category_str="threat_intel")

    async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
        """Threat Intel stub returns UNAVAILABLE status cleanly."""
        return create_unavailable_result(
            analyzer_name=self.name,
            reason="External threat intelligence service stubbed - provider unavailable"
        )


class StubInfrastructureAnalyzer(BaseStubAnalyzer):
    """M6 Infrastructure/Geo Context Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_infrastructure", category_str="infrastructure")


class StubAttachmentAnalyzer(BaseStubAnalyzer):
    """M4 Attachment Metadata Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_attachment", category_str="attachment")


class StubForensicAnalyzer(BaseStubAnalyzer):
    """M6 Forensic Timeline Analyzer Stub."""
    def __init__(self):
        super().__init__(name_str="stub_forensic", category_str="forensic")
