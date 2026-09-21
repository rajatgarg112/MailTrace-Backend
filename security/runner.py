import uuid
from typing import Dict, Any, Optional, List
from security.models import (
    SecurityResult, AuthStatus, ThreatClassification, DeliveryAction,
    PolicyDecision, DomainAnalysisResult
)
from security.header_analysis import HeaderParser, HeaderAnomalyDetector
from security.authentication import SPFEvaluator, DKIMEvaluator, DMARCEvaluator
from security.domain_analysis import LookalikeDomainDetector, TyposquattingDetector, TLDInspector
from security.url_analysis import URLExtractor, RedirectChainAnalyzer, URLDomainReputationAnalyzer
from security.relay_analysis import HopCounter, RelayVerifier
from security.attachment_analysis import StaticAttachmentInspector
from security.forensic import ForensicEvidenceEngine, ForensicCaseBuilder, AuditLogger
from security.infrastructure import IPResolver, ASNLookup, GeoMapper


class SecurityAnalyzer:
    """
    Unified Top-Notch Security Analysis & Policy Decision Orchestrator for Member 4 & Member 6.
    Runs all static security checks, computes 0-100 Risk Score, maps Threat Classification
    and Delivery Action, resolves approximate infrastructure geolocation & map markers,
    and outputs cryptographic evidence & forensic case records.
    """

    def __init__(self):
        self.header_parser = HeaderParser()
        self.header_anomaly_detector = HeaderAnomalyDetector()
        self.spf_evaluator = SPFEvaluator()
        self.dkim_evaluator = DKIMEvaluator()
        self.dmarc_evaluator = DMARCEvaluator()
        self.lookalike_detector = LookalikeDomainDetector()
        self.typosquatting_detector = TyposquattingDetector()
        self.tld_inspector = TLDInspector()
        self.url_extractor = URLExtractor()
        self.redirect_chain_analyzer = RedirectChainAnalyzer()
        self.url_reputation_analyzer = URLDomainReputationAnalyzer()
        self.hop_counter = HopCounter()
        self.relay_verifier = RelayVerifier()
        self.attachment_inspector = StaticAttachmentInspector()
        self.forensic_engine = ForensicEvidenceEngine()
        # Member 6 Components
        self.ip_resolver = IPResolver()
        self.asn_lookup = ASNLookup()
        self.geo_mapper = GeoMapper()
        self.case_builder = ForensicCaseBuilder()
        self.audit_logger = AuditLogger()


    def analyze(
        self,
        raw_headers_or_dict: Any,
        body_text_or_html: Optional[str] = None,
        attachments_input: Optional[List[str]] = None,
        email_id: Optional[str] = None
    ) -> SecurityResult:
        
        if not email_id:
            email_id = f"eml_{uuid.uuid4().hex[:12]}"

        security_tags: List[str] = []
        risk_score_contrib = 0

        # 1. Header Analysis
        parsed_headers = self.header_parser.parse(raw_headers_or_dict)
        header_result = self.header_anomaly_detector.detect_anomalies(parsed_headers)

        if header_result.anomalies:
            security_tags.append("HEADER_ANOMALY")
            risk_score_contrib += 15

        # 2. Authentication Checks
        spf_status, _ = self.spf_evaluator.evaluate(parsed_headers)
        dkim_status, _ = self.dkim_evaluator.evaluate(parsed_headers)
        auth_result = self.dmarc_evaluator.evaluate(parsed_headers, spf_status, dkim_status)

        if auth_result.spf == AuthStatus.FAIL:
            security_tags.append("SPF_FAIL")
            risk_score_contrib += 20
        if auth_result.dkim == AuthStatus.FAIL:
            security_tags.append("DKIM_FAIL")
            risk_score_contrib += 15
        if auth_result.dmarc == AuthStatus.FAIL:
            security_tags.append("DMARC_FAIL")
            risk_score_contrib += 25

        # 3. Domain Analysis
        from_domain = parsed_headers.get("from_domain")
        from_display = parsed_headers.get("from_display")
        from_addr = parsed_headers.get("from_addr")

        is_lookalike, target_brand, distance, lookalike_findings = self.lookalike_detector.check_lookalike(from_domain)
        is_typo, typo_findings = self.typosquatting_detector.detect_typosquatting(from_domain)
        susp_tld, tld_findings = self.tld_inspector.check_suspicious_tld(from_domain)
        display_spoof, spoof_findings = self.tld_inspector.check_display_name_spoofing(from_display, from_domain)

        all_domain_findings = lookalike_findings + typo_findings + tld_findings + spoof_findings

        if is_lookalike:
            security_tags.append("LOOKALIKE_DOMAIN")
            risk_score_contrib += 30
        if is_typo:
            security_tags.append("TYPOSQUATTED_DOMAIN")
            risk_score_contrib += 20
        if susp_tld:
            security_tags.append("SUSPICIOUS_TLD")
            risk_score_contrib += 15
        if display_spoof:
            security_tags.append("DISPLAY_NAME_SPOOF")
            risk_score_contrib += 25

        domain_result = DomainAnalysisResult(
            domain=from_domain,
            is_lookalike=is_lookalike,
            target_brand_domain=target_brand,
            lookalike_distance=distance,
            is_typosquatted=is_typo,
            suspicious_tld=susp_tld,
            display_name_spoofed=display_spoof,
            claimed_display_name=from_display,
            actual_sender_email=from_addr,
            findings=all_domain_findings,
        )

        # 4. URL Analysis
        urls, has_anchor_mismatch, anchor_mismatches = self.url_extractor.extract_urls(body_text_or_html or "")
        redirect_detected, redirect_findings = self.redirect_chain_analyzer.check_redirect_chains(urls)
        url_result = self.url_reputation_analyzer.analyze(
            urls, has_anchor_mismatch, anchor_mismatches, redirect_detected, redirect_findings
        )

        if url_result.suspicious_urls_count > 0:
            security_tags.append("SUSPICIOUS_URL")
            risk_score_contrib += 25
        if redirect_detected:
            security_tags.append("REDIRECT_CHAIN")
            risk_score_contrib += 15
        if has_anchor_mismatch:
            security_tags.append("ANCHOR_TEXT_MISMATCH")
            risk_score_contrib += 30

        # 5. Relay Hop Analysis
        received_list = parsed_headers.get("received_list", [])
        hop_count, originating_ip, hops = self.hop_counter.parse_hops(received_list)
        relay_result = self.relay_verifier.verify_relays(hop_count, originating_ip, hops)

        if relay_result.suspicious_relay_detected:
            security_tags.append("SUSPICIOUS_RELAY")
            risk_score_contrib += 15

        # 6. Attachment Inspection
        attachment_result = self.attachment_inspector.analyze_attachments(attachments_input or [])
        if attachment_result.dangerous_attachments_count > 0:
            security_tags.append("DANGEROUS_ATTACHMENT")
            risk_score_contrib += 35
        if attachment_result.has_double_extension:
            security_tags.append("DOUBLE_EXTENSION_SPOOF")
            risk_score_contrib += 40

        # Cap risk score contribution at 100
        final_risk_score = min(100, risk_score_contrib)

        # 7. Threat Classification & Delivery Policy Mapping
        if final_risk_score >= 76:
            classification = ThreatClassification.MALICIOUS
            action = DeliveryAction.QUARANTINE
            reason = f"High threat risk score ({final_risk_score}/100) triggered automatic QUARANTINE policy."
        elif final_risk_score >= 56:
            classification = ThreatClassification.SUSPICIOUS
            action = DeliveryAction.WARN
            reason = f"Elevated threat risk score ({final_risk_score}/100) triggered inbox WARNING policy."
        elif final_risk_score >= 21:
            classification = ThreatClassification.SPAM
            action = DeliveryAction.SPAM
            reason = f"Low-level spam/promotional signals detected ({final_risk_score}/100). Routed to SPAM."
        elif not from_domain and not raw_headers_or_dict:
            classification = ThreatClassification.UNKNOWN
            action = DeliveryAction.HOLD
            reason = "Insufficient email payload data for conclusive analysis. Held for review."
        else:
            classification = ThreatClassification.SAFE
            action = DeliveryAction.INBOX
            reason = f"Low risk score ({final_risk_score}/100). Email verified SAFE for INBOX delivery."

        policy_decision = PolicyDecision(
            risk_score=final_risk_score,
            threat_classification=classification,
            delivery_action=action,
            action_reason=reason
        )

        # 8. Cryptographic Evidence & Forensics Engine (Member 4 & 6)
        raw_headers_str = str(raw_headers_or_dict)
        body_str = body_text_or_html or ""
        auth_status_str = f"SPF={auth_result.spf.value}, DKIM={auth_result.dkim.value}, DMARC={auth_result.dmarc.value}"
        
        # Resolve real originating IP & Geo-Infrastructure
        hops_dict_list = [hop.model_dump() if hasattr(hop, "model_dump") else dict(hop) for hop in hops]
        resolved_ip = self.ip_resolver.resolve_originating_ip(parsed_headers, hops_dict_list) or originating_ip
        asn_data = self.asn_lookup.lookup(resolved_ip) if resolved_ip else {}
        geo_data = self.geo_mapper.resolve_geo(resolved_ip) if resolved_ip else {}

        if geo_data.get("is_vpn_or_tor"):
            if "VPN_OR_TOR_ORIGIN" not in security_tags:
                security_tags.append("VPN_OR_TOR_ORIGIN")

        forensic_result = self.forensic_engine.generate_forensic_report(
            raw_headers_str=raw_headers_str,
            body_text_str=body_str,
            originating_ip=resolved_ip,
            auth_status_str=auth_status_str,
            domain_findings_count=len(all_domain_findings),
            url_count=len(urls),
            risk_score=final_risk_score,
            action_str=action.value
        )

        # Enrich network context with real coordinates & map marker
        if resolved_ip:
            forensic_result.network_context.asn = asn_data.get("asn", "UNKNOWN")
            forensic_result.network_context.isp = asn_data.get("isp", "Unknown ISP")
            forensic_result.network_context.country = geo_data.get("country", "Unknown")
            forensic_result.network_context.city = geo_data.get("city", "Unknown")
            forensic_result.network_context.approximate_region = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
            forensic_result.network_context.latitude = geo_data.get("latitude", 0.0)
            forensic_result.network_context.longitude = geo_data.get("longitude", 0.0)
            forensic_result.network_context.is_vpn_or_tor = geo_data.get("is_vpn_or_tor", False)
            forensic_result.network_context.map_marker = geo_data.get("map_marker", {})

        # Build Forensic Case & Sanitized Security Report
        forensic_case = self.case_builder.build_case(
            email_id=email_id,
            sender=from_addr or "unknown_sender",
            subject=parsed_headers.get("subject", "No Subject"),
            risk_score=final_risk_score,
            confidence=0.92 if final_risk_score > 50 else 0.85,
            security_tags=security_tags,
            evidence_summary={"raw_sha256": forensic_result.raw_sha256},
            geo_infrastructure=forensic_result.network_context.model_dump(),
            timeline=[t.model_dump() for t in forensic_result.timeline],
        )

        sanitized_report = self.case_builder.build_sanitized_report(
            email_id=email_id,
            sender=from_addr or "unknown_sender",
            subject=parsed_headers.get("subject", "No Subject"),
            raw_body=body_str,
            threat_tags=security_tags,
            risk_score=final_risk_score,
        )

        return SecurityResult(
            email_id=email_id,
            headers=header_result,
            authentication=auth_result,
            domain_analysis=domain_result,
            url_analysis=url_result,
            relay_analysis=relay_result,
            attachments=attachment_result,
            forensics=forensic_result,
            policy_decision=policy_decision,
            security_tags=security_tags,
            risk_score_contribution=final_risk_score,
            infrastructure=forensic_result.network_context.model_dump(),
            evidence=forensic_result.model_dump(),
            timeline=[t.model_dump() for t in forensic_result.timeline],
            forensic_case=forensic_case,
            sanitized_report=sanitized_report,
        )

