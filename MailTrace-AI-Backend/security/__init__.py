"""
MailTrace-AI Security Subsystem (Member 4)
Package containing email header analysis, authentication checking,
domain lookalike/typosquatting detection, URL extraction/inspection,
and relay hop analysis.
"""

from security.models import SecurityResult, AuthenticationResult, DomainAnalysisResult, URLAnalysisResult, RelayAnalysisResult, HeaderAnalysisResult

__all__ = [
    "SecurityResult",
    "AuthenticationResult",
    "DomainAnalysisResult",
    "URLAnalysisResult",
    "RelayAnalysisResult",
    "HeaderAnalysisResult",
]
