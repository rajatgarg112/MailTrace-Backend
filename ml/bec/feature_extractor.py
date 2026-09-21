"""
BEC / Impersonation Feature Extractor.
Extracts Category 10 features: executive_impersonation_score, brand_impersonation_score,
payment_request_score, invoice_request_score, bank_account_change_score, gift_card_request_score,
urgency_score, conversation_hijacking_score, authority_impersonation_score.
"""

import re
from typing import Dict, Any, Optional
from ml.config import EXECUTIVE_TITLES, COMMON_TARGET_BRANDS
from ml.models.rule_engine import match_keyword_density, detect_social_engineering_tactics


def extract_bec_features(
    display_name: str = "",
    from_address: str = "",
    subject: str = "",
    body: str = "",
    reply_to: str = ""
) -> Dict[str, float]:
    """
    Extract BEC and Impersonation feature scores.
    """
    full_text = f"{subject}\n{body}".strip()
    full_text_lower = full_text.lower()
    display_name_lower = display_name.lower()
    from_address_lower = from_address.lower()

    # 1. Executive Impersonation Score
    exec_title_matched = any(title in display_name_lower or title in full_text_lower[:200] for title in EXECUTIVE_TITLES)
    # Check if display name claims executive role but from address domain is generic/freemail
    is_freemail = any(domain in from_address_lower for domain in ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"])
    
    exec_imp_score = 0.0
    if exec_title_matched:
        exec_imp_score = 0.85 if is_freemail else 0.40

    # 2. Brand Impersonation Score
    brand_matched = any(brand in full_text_lower or brand in display_name_lower for brand in COMMON_TARGET_BRANDS)
    brand_imp_score = 0.0
    if brand_matched:
        # If brand mentioned but sender domain doesn't match brand
        matched_brand = next((b for b in COMMON_TARGET_BRANDS if b in full_text_lower or b in display_name_lower), "")
        if matched_brand and matched_brand not in from_address_lower:
            brand_imp_score = 0.80
        else:
            brand_imp_score = 0.20

    # 3. Specific Solicitation Types
    payment_request_score = match_keyword_density(full_text_lower, ["wire transfer", "payment", "remittance", "send money", "ach transfer"])
    invoice_request_score = match_keyword_density(full_text_lower, ["invoice", "overdue bill", "outstanding invoice", "attached invoice"])
    bank_account_change_score = match_keyword_density(full_text_lower, ["change bank details", "new direct deposit", "update account number", "routing number"])
    gift_card_request_score = match_keyword_density(full_text_lower, ["gift card", "apple card", "steam card", "google play card", "buy cards"])

    # 4. Social engineering & Authority scores
    urgency_score, _, authority_score = detect_social_engineering_tactics(full_text_lower)

    # 5. Conversation Hijacking Score (Re: / Fwd: with mismatched metadata or sudden financial request)
    is_reply_fwd = subject.lower().startswith("re:") or subject.lower().startswith("fwd:")
    convo_hijack_score = 0.0
    if is_reply_fwd and (payment_request_score > 0.3 or bank_account_change_score > 0.3):
        convo_hijack_score = 0.75
    elif is_reply_fwd and reply_to and reply_to.lower() != from_address_lower:
        convo_hijack_score = 0.85

    return {
        "executive_impersonation_score": round(exec_imp_score, 4),
        "brand_impersonation_score": round(brand_imp_score, 4),
        "payment_request_score": round(payment_request_score, 4),
        "invoice_request_score": round(invoice_request_score, 4),
        "bank_account_change_score": round(bank_account_change_score, 4),
        "gift_card_request_score": round(gift_card_request_score, 4),
        "urgency_score": round(urgency_score, 4),
        "conversation_hijacking_score": round(convo_hijack_score, 4),
        "authority_impersonation_score": round(authority_score, 4)
    }
