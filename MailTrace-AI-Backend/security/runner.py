import uuid
from typing import Dict, Any, Optional, List
from security.models import SecurityResult, AuthStatus
from security.header_analysis import HeaderParser, HeaderAnomalyDetector
from security.authentication import SPFEvaluator, DKIMEvaluator, DMARCEvaluator
from security.domain_analysis import LookalikeDomainDetector, TyposquattingDetector, TLDInspector
from security.url_analysis import URLExtractor, RedirectChainAnalyzer, URLDomainReputationAnalyzer
from security.relay_analysis import HopCounter, RelayVerifier


class SecurityAnalyzer:
    """
    Unified Security Analysis Orchestrator for Member 4.
    Runs all static security checks and outputs canonical SecurityResult payload.
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

    def analyze(self, raw_headers_or_dict: Any, body_text_or_html: Optional[str] = None, email_id: Optional[str] = None) -> SecurityResult:
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

        domain_result = {
            "domain": from_domain,
            "is_lookalike": is_lookalike,
            "target_brand_domain": target_brand,
            "lookalike_distance": distance,
            "is_typosquatted": is_typo,
            "suspicious_tld": susp_tld,
            "display_name_spoofed": display_spoof,
            "claimed_display_name": from_display,
            "actual_sender_email": from_addr,
            "findings": all_domain_findings,
        }

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

        # Cap risk score contribution at 100
        final_risk_contrib = min(100, risk_score_contrib)

        return SecurityResult(
            email_id=email_id,
            headers=header_result,
            authentication=auth_result,
            domain_analysis=domain_result,
            url_analysis=url_result,
            relay_analysis=relay_result,
            security_tags=security_tags,
            risk_score_contribution=final_risk_contrib,
        )
