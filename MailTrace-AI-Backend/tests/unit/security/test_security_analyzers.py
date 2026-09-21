import pytest
from security.models import AuthStatus, SecurityResult
from security.header_analysis import HeaderParser, HeaderAnomalyDetector
from security.authentication import SPFEvaluator, DKIMEvaluator, DMARCEvaluator
from security.domain_analysis import LookalikeDomainDetector, TyposquattingDetector, TLDInspector
from security.url_analysis import URLExtractor, RedirectChainAnalyzer, URLDomainReputationAnalyzer
from security.relay_analysis import HopCounter, RelayVerifier
from security.runner import SecurityAnalyzer


def test_header_parser_and_anomaly_detector():
    raw_headers = {
        "From": "Security Team <security@paypa1-support.xyz>",
        "Subject": "URGENT: Verify Your Account Immediately",
        "Date": "Mon, 21 Sep 2026 09:30:00 +0000",
        "Message-ID": "<12345@legit-domain.com>",
        "Return-Path": "<bounce@unrelated-domain.com>",
        "Authentication-Results": "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
        "Received": [
            "from mail.suspicious.com ([185.220.101.5]) by mx.example.com; Mon, 21 Sep 2026 09:30:00 +0000",
            "from internal.relay.local ([10.0.0.1]) by mail.suspicious.com; Mon, 21 Sep 2026 09:29:58 +0000"
        ]
    }

    parser = HeaderParser()
    parsed = parser.parse(raw_headers)

    assert parsed["from_domain"] == "paypa1-support.xyz"
    assert parsed["from_display"] == "Security Team"
    assert parsed["return_path_domain"] == "unrelated-domain.com"
    assert len(parsed["received_list"]) == 2

    detector = HeaderAnomalyDetector()
    anomaly_res = detector.detect_anomalies(parsed)

    assert anomaly_res.return_path_mismatch is True
    assert anomaly_res.message_id_domain_mismatch is True
    assert len(anomaly_res.anomalies) >= 2


def test_authentication_evaluators():
    headers_fail = {
        "auth_results_raw": "mx.google.com; spf=fail; dkim=fail; dmarc=fail",
        "from_domain": "paypal-spoof.com",
        "return_path_domain": "attacker-bounce.com"
    }

    spf_eval = SPFEvaluator()
    dkim_eval = DKIMEvaluator()
    dmarc_eval = DMARCEvaluator()

    spf_status, _ = spf_eval.evaluate(headers_fail)
    dkim_status, _ = dkim_eval.evaluate(headers_fail)
    dmarc_res = dmarc_eval.evaluate(headers_fail, spf_status, dkim_status)

    assert spf_status == AuthStatus.FAIL
    assert dkim_status == AuthStatus.FAIL
    assert dmarc_res.dmarc == AuthStatus.FAIL
    assert dmarc_res.dmarc_aligned is False


def test_lookalike_and_domain_analysis():
    lookalike = LookalikeDomainDetector()
    is_lookalike, target, dist, findings = lookalike.check_lookalike("paypa1.com")
    assert is_lookalike is True
    assert target == "paypal.com"
    assert dist == 1

    typo = TyposquattingDetector()
    is_typo, _ = typo.detect_typosquatting("pay-pal-login.com")
    assert is_typo is True

    tld_insp = TLDInspector()
    susp_tld, _ = tld_insp.check_suspicious_tld("verify-account.xyz")
    assert susp_tld is True

    display_spoof, _ = tld_insp.check_display_name_spoofing("PayPal Security", "hacker-domain.com")
    assert display_spoof is True


def test_url_analysis():
    body_text = """
    Please click here to update your credentials: <a href="http://185.220.101.5/auth">http://paypal.com/login</a>
    Or visit our short link: https://bit.ly/3x89qAZ
    """

    extractor = URLExtractor()
    urls, has_mismatch, mismatches = extractor.extract_urls(body_text)

    assert len(urls) >= 2
    assert has_mismatch is True
    assert mismatches[0]["display_domain"] == "paypal.com"

    redirect_eval = RedirectChainAnalyzer()
    has_redirect, _ = redirect_eval.check_redirect_chains(urls)
    assert has_redirect is True

    url_rep = URLDomainReputationAnalyzer()
    res = url_rep.analyze(urls, has_mismatch, mismatches, has_redirect, [])

    assert res.total_urls >= 2
    assert res.suspicious_urls_count >= 1
    assert res.anchor_text_mismatch_detected is True


def test_relay_analysis():
    received_headers = [
        "from mail.suspicious.com ([185.220.101.5]) by mx.example.com",
        "from internal.node ([10.0.0.2]) by mail.suspicious.com"
    ]

    counter = HopCounter()
    hop_count, originating_ip, hops = counter.parse_hops(received_headers)

    assert hop_count == 2
    assert originating_ip == "185.220.101.5"

    verifier = RelayVerifier()
    res = verifier.verify_relays(hop_count, originating_ip, hops)

    assert res.hop_count == 2
    assert res.originating_ip == "185.220.101.5"


def test_unified_security_analyzer():
    raw_headers = {
        "From": "PayPal Security <billing@paypa1-verify.xyz>",
        "Subject": "URGENT: Account Suspension Notice",
        "Date": "Mon, 21 Sep 2026 09:30:00 +0000",
        "Message-ID": "<999@random-host.com>",
        "Return-Path": "<bounce@attacker.ru>",
        "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        "Received": ["from bad.relay.com ([185.220.101.5]) by mx.example.com"]
    }

    html_body = '<p>Verify your details immediately at <a href="http://185.220.101.5/login">http://paypal.com/verify</a> or https://bit.ly/3x89qAZ</p>'

    analyzer = SecurityAnalyzer()
    result: SecurityResult = analyzer.analyze(raw_headers, html_body)

    assert result.email_id.startswith("eml_")
    assert "DMARC_FAIL" in result.security_tags
    assert "SPF_FAIL" in result.security_tags
    assert "LOOKALIKE_DOMAIN" in result.security_tags
    assert "DISPLAY_NAME_SPOOF" in result.security_tags
    assert "SUSPICIOUS_URL" in result.security_tags
    assert "ANCHOR_TEXT_MISMATCH" in result.security_tags
    assert result.risk_score_contribution >= 70
