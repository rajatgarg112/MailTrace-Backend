"""
Security Analyzers Adapter Suite for MailTrace-AI Backend.

Bridges the real detector implementations in the security/ directory into BaseAnalyzer
interfaces for execution by AnalysisOrchestrator and AnalyzerRegistry without duplicating
detection algorithms or hijacking final delivery/risk policy decisions.
"""

import os
from typing import Any, Dict, List, Optional

from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.context import AnalysisContext
from app.services.analyzers.result import create_analyzer_result, create_failed_result

# Existing Real Security Implementations
from security.header_analysis import HeaderParser, HeaderAnomalyDetector
from security.authentication import SPFEvaluator, DKIMEvaluator, DMARCEvaluator
from security.authentication.spf_evaluator import AuthStatus
from security.domain_analysis import LookalikeDomainDetector, TyposquattingDetector, TLDInspector
from security.url_analysis import URLExtractor, RedirectChainAnalyzer, URLDomainReputationAnalyzer
from security.relay_analysis import HopCounter, RelayVerifier
from security.attachment_analysis import StaticAttachmentInspector
from security.infrastructure import IPResolver, ASNLookup, GeoMapper
from security.forensic import ForensicEvidenceEngine, ForensicCaseBuilder, AuditLogger


class HeaderAuthenticationAnalyzer(BaseAnalyzer):
    """M4 Email Header & Authentication (SPF/DKIM/DMARC) Analyzer Adapter."""

    def __init__(self, name_str: str = "header_auth", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "authentication"
        self.header_parser = HeaderParser()
        self.header_anomaly_detector = HeaderAnomalyDetector()
        self.spf_evaluator = SPFEvaluator()
        self.dkim_evaluator = DKIMEvaluator()
        self.dmarc_evaluator = DMARCEvaluator()

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
        email = context.email
        headers_input = email.headers or {}

        # Ensure basic headers if dict is minimal
        if email.sender and "From" not in headers_input and "from" not in headers_input:
            headers_input["From"] = email.sender.address
        if email.subject and "Subject" not in headers_input and "subject" not in headers_input:
            headers_input["Subject"] = email.subject

        parsed_headers = self.header_parser.parse(headers_input)
        header_anomalies = self.header_anomaly_detector.detect_anomalies(parsed_headers)

        spf_status, spf_reason = self.spf_evaluator.evaluate(parsed_headers)
        dkim_status, dkim_reason = self.dkim_evaluator.evaluate(parsed_headers)
        auth_result = self.dmarc_evaluator.evaluate(parsed_headers, spf_status, dkim_status)

        findings: List[SecurityFinding] = []

        if header_anomalies.anomalies:
            findings.append(
                SecurityFinding(
                    code="HEADER_ANOMALY",
                    severity=SeverityLevel.LOW,
                    description=f"Header anomaly detected: {', '.join(header_anomalies.anomalies)}",
                    details={"anomalies": header_anomalies.anomalies, "findings": header_anomalies.findings}
                )
            )

        if auth_result.spf == AuthStatus.FAIL:
            findings.append(
                SecurityFinding(
                    code="SPF_FAIL",
                    severity=SeverityLevel.MEDIUM,
                    description=spf_reason or "SPF sender verification check failed",
                    details={"spf_status": auth_result.spf.value, "reason": spf_reason}
                )
            )

        if auth_result.dkim == AuthStatus.FAIL:
            findings.append(
                SecurityFinding(
                    code="DKIM_FAIL",
                    severity=SeverityLevel.LOW,
                    description=dkim_reason or "DKIM cryptographic signature verification failed",
                    details={"dkim_status": auth_result.dkim.value, "reason": dkim_reason}
                )
            )

        if auth_result.dmarc == AuthStatus.FAIL:
            findings.append(
                SecurityFinding(
                    code="DMARC_FAIL",
                    severity=SeverityLevel.HIGH,
                    description="DMARC alignment and authentication policy failed",
                    details={"dmarc_status": auth_result.dmarc.value, "alignment": auth_result.alignment_mode}
                )
            )

        features = {
            "spf": auth_result.spf.value,
            "dkim": auth_result.dkim.value,
            "dmarc": auth_result.dmarc.value,
            "alignment_mode": auth_result.alignment_mode,
            "anomalies_count": len(header_anomalies.anomalies),
            "parsed_headers": {k: str(v) for k, v in parsed_headers.items() if not isinstance(v, (list, dict))},
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )


class DomainSecurityAnalyzer(BaseAnalyzer):
    """M4 Domain, Lookalike, Typosquatting & Display Name Spoofing Analyzer Adapter."""

    def __init__(self, name_str: str = "domain", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "domain"
        self.lookalike_detector = LookalikeDomainDetector()
        self.typosquatting_detector = TyposquattingDetector()
        self.tld_inspector = TLDInspector()

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
        email = context.email
        sender_address = email.sender.address if email.sender else ""
        from_display = email.sender.name if email.sender else ""

        from_domain = sender_address.split("@")[-1].strip().lower() if "@" in sender_address else ""

        is_lookalike, target_brand, distance, lookalike_findings = self.lookalike_detector.check_lookalike(from_domain)
        is_typo, typo_findings = self.typosquatting_detector.detect_typosquatting(from_domain)
        susp_tld, tld_findings = self.tld_inspector.check_suspicious_tld(from_domain)
        display_spoof, spoof_findings = self.tld_inspector.check_display_name_spoofing(from_display, from_domain)

        findings: List[SecurityFinding] = []

        if is_lookalike:
            findings.append(
                SecurityFinding(
                    code="LOOKALIKE_DOMAIN",
                    severity=SeverityLevel.HIGH,
                    description=lookalike_findings[0] if lookalike_findings else f"Lookalike domain mimicking {target_brand}",
                    details={"target_brand": target_brand, "distance": distance}
                )
            )

        if is_typo:
            findings.append(
                SecurityFinding(
                    code="TYPOSQUATTED_DOMAIN",
                    severity=SeverityLevel.MEDIUM,
                    description=typo_findings[0] if typo_findings else "Typosquatted domain detected",
                    details={"findings": typo_findings}
                )
            )

        if susp_tld:
            findings.append(
                SecurityFinding(
                    code="SUSPICIOUS_TLD",
                    severity=SeverityLevel.MEDIUM,
                    description=tld_findings[0] if tld_findings else "Suspicious high-risk TLD detected",
                    details={"findings": tld_findings}
                )
            )

        if display_spoof:
            findings.append(
                SecurityFinding(
                    code="DISPLAY_NAME_SPOOF",
                    severity=SeverityLevel.HIGH,
                    description=spoof_findings[0] if spoof_findings else "Display name impersonation spoof detected",
                    details={"findings": spoof_findings, "display_name": from_display, "from_domain": from_domain}
                )
            )

        features = {
            "from_domain": from_domain,
            "is_lookalike": is_lookalike,
            "target_brand": target_brand,
            "is_typosquatted": is_typo,
            "suspicious_tld": susp_tld,
            "display_name_spoofed": display_spoof,
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )


class URLSecurityAnalyzer(BaseAnalyzer):
    """M4 URL Extraction, Redirect Chains & Domain Reputation Analyzer Adapter."""

    def __init__(self, name_str: str = "url", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "url"
        self.url_extractor = URLExtractor()
        self.redirect_chain_analyzer = RedirectChainAnalyzer()
        self.url_reputation_analyzer = URLDomainReputationAnalyzer()

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
        email = context.email
        body_content = email.body_text_preview or ""

        # Extract URLs from body text/html
        extracted_urls, has_anchor_mismatch, anchor_mismatches = self.url_extractor.extract_urls(body_content)

        # Merge pre-extracted URLs if present in NormalizedEmail
        all_urls = list(extracted_urls)
        for u in email.urls:
            if u.url and u.url not in all_urls:
                all_urls.append(u.url)

        redirect_detected, redirect_findings = self.redirect_chain_analyzer.check_redirect_chains(all_urls)
        url_result = self.url_reputation_analyzer.analyze(
            all_urls, has_anchor_mismatch, anchor_mismatches, redirect_detected, redirect_findings
        )

        findings: List[SecurityFinding] = []

        if url_result.suspicious_urls_count > 0:
            findings.append(
                SecurityFinding(
                    code="SUSPICIOUS_URL",
                    severity=SeverityLevel.HIGH,
                    description=f"{url_result.suspicious_urls_count} suspicious URL(s) detected",
                    details={"findings": url_result.findings, "total_urls": len(all_urls)}
                )
            )

        if redirect_detected:
            findings.append(
                SecurityFinding(
                    code="REDIRECT_CHAIN",
                    severity=SeverityLevel.MEDIUM,
                    description="Suspicious URL redirect chain detected",
                    details={"findings": redirect_findings}
                )
            )

        if has_anchor_mismatch:
            findings.append(
                SecurityFinding(
                    code="ANCHOR_TEXT_MISMATCH",
                    severity=SeverityLevel.HIGH,
                    description="Visual link text does not match underlying target URL destination",
                    details={"mismatches": anchor_mismatches}
                )
            )

        features = {
            "total_urls": len(all_urls),
            "suspicious_urls_count": url_result.suspicious_urls_count,
            "redirect_chain_detected": redirect_detected,
            "anchor_text_mismatch_detected": has_anchor_mismatch,
            "extracted_urls": all_urls[:20],
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )


class AttachmentSecurityAnalyzer(BaseAnalyzer):
    """M4 Attachment Static Inspection Analyzer Adapter."""

    def __init__(self, name_str: str = "attachment", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "attachment"
        self.attachment_inspector = StaticAttachmentInspector()

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
        email = context.email
        filenames = [att.filename for att in email.attachments if att.filename]

        attachment_result = self.attachment_inspector.analyze_attachments(filenames)

        findings: List[SecurityFinding] = []

        if attachment_result.dangerous_attachments_count > 0:
            findings.append(
                SecurityFinding(
                    code="MALICIOUS_ATTACHMENT",
                    severity=SeverityLevel.CRITICAL,
                    description=f"{attachment_result.dangerous_attachments_count} high-risk attachment(s) identified",
                    details={"findings": attachment_result.findings}
                )
            )

        if attachment_result.has_double_extension:
            findings.append(
                SecurityFinding(
                    code="EXECUTABLE_ATTACHMENT",
                    severity=SeverityLevel.CRITICAL,
                    description="Double extension spoofing detected in email attachments",
                    details={"findings": attachment_result.findings}
                )
            )

        # Also inspect flags from AttachmentMetadata
        for att in email.attachments:
            if att.is_executable:
                findings.append(
                    SecurityFinding(
                        code="EXECUTABLE_ATTACHMENT",
                        severity=SeverityLevel.CRITICAL,
                        description=f"Executable binary attachment detected: {att.filename}",
                        details={"filename": att.filename, "size_bytes": att.size_bytes}
                    )
                )
            if att.has_macro:
                findings.append(
                    SecurityFinding(
                        code="MACRO_DETECTED",
                        severity=SeverityLevel.HIGH,
                        description=f"Document macro detected in attachment: {att.filename}",
                        details={"filename": att.filename}
                    )
                )

        features = {
            "total_attachments": len(filenames),
            "dangerous_attachments_count": attachment_result.dangerous_attachments_count,
            "has_double_extension": attachment_result.has_double_extension,
            "attachment_names": filenames,
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )


class RelayInfrastructureAnalyzer(BaseAnalyzer):
    """M4/M6 Mail Relay, Originating IP, ASN & Geolocation Context Analyzer Adapter."""

    def __init__(self, name_str: str = "infrastructure", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "infrastructure"
        self.hop_counter = HopCounter()
        self.relay_verifier = RelayVerifier()
        self.ip_resolver = IPResolver()
        self.asn_lookup = ASNLookup()
        self.geo_mapper = GeoMapper()

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
        email = context.email
        headers = email.headers or {}

        # Parse Received headers if available
        received_raw = headers.get("Received") or headers.get("received") or []
        if isinstance(received_raw, str):
            received_list = [received_raw]
        elif isinstance(received_raw, list):
            received_list = received_raw
        else:
            received_list = []

        # Also pull from received_hops if populated
        hops_dict_list: List[Dict[str, Any]] = []
        for h in email.received_hops:
            hops_dict_list.append({
                "from_host": h.from_host,
                "by_host": h.by_host,
                "ip_address": h.ip_address,
                "delay_seconds": h.delay_seconds,
            })

        hop_count, originating_ip, hops = self.hop_counter.parse_hops(received_list)
        relay_result = self.relay_verifier.verify_relays(hop_count, originating_ip, hops)

        # Resolve originating IP through fallback chain
        resolved_ip = self.ip_resolver.resolve_originating_ip(headers, hops_dict_list) or originating_ip
        asn_data = self.asn_lookup.lookup(resolved_ip) if resolved_ip else {}
        geo_data = self.geo_mapper.resolve_geo(resolved_ip) if resolved_ip else {}

        findings: List[SecurityFinding] = []

        if relay_result.suspicious_relay_detected:
            findings.append(
                SecurityFinding(
                    code="SUSPICIOUS_RELAY",
                    severity=SeverityLevel.MEDIUM,
                    description=relay_result.relay_anomaly_reason or "Suspicious mail relay routing path",
                    details={"hop_count": hop_count, "originating_ip": resolved_ip}
                )
            )

        if geo_data.get("is_vpn_or_tor"):
            findings.append(
                SecurityFinding(
                    code="VPN_OR_TOR_ORIGIN",
                    severity=SeverityLevel.LOW,
                    description=f"Originating mail infrastructure ({resolved_ip}) is a known VPN or Tor exit node",
                    details=geo_data
                )
            )

        features = {
            "originating_ip": resolved_ip,
            "hop_count": hop_count,
            "asn": asn_data.get("asn"),
            "isp": asn_data.get("isp"),
            "country": geo_data.get("country"),
            "city": geo_data.get("city"),
            "latitude": geo_data.get("latitude"),
            "longitude": geo_data.get("longitude"),
            "is_vpn_or_tor": geo_data.get("is_vpn_or_tor", False),
            "map_marker": geo_data.get("map_marker", {}),
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )


class ForensicEvidenceAnalyzer(BaseAnalyzer):
    """M6 Cryptographic Evidence Hashing, Timeline Tracking & Forensic Draft Adapter."""

    def __init__(self, name_str: str = "forensic", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "forensic"
        self.forensic_engine = ForensicEvidenceEngine()
        self.case_builder = ForensicCaseBuilder()
        self.audit_logger = AuditLogger()

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
        email = context.email
        raw_headers_str = str(email.headers or {})
        body_str = email.body_text_preview or ""

        # Compute forensic report and hashes safely
        forensic_report = self.forensic_engine.generate_forensic_report(
            raw_headers_str=raw_headers_str,
            body_text_str=body_str,
            originating_ip=None,
            auth_status_str="EVALUATING",
            domain_findings_count=0,
            url_count=len(email.urls),
            risk_score=0,
            action_str="EVALUATING",
        )

        timeline_items = [t.model_dump() for t in forensic_report.timeline] if hasattr(forensic_report, "timeline") else []

        features = {
            "raw_sha256": forensic_report.raw_sha256,
            "timeline": timeline_items,
            "audit_trail": [a.model_dump() for a in forensic_report.audit_trail] if hasattr(forensic_report, "audit_trail") else [],
            "extracted_facts": {
                "message_id": email.message_id,
                "subject": email.subject,
                "sender": email.sender.address if email.sender else "",
                "attachments_count": len(email.attachments),
                "urls_count": len(email.urls),
            }
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=[],
        )
