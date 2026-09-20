"""
Rule & Pattern Engine for heuristic NLP, BEC, and Behavioral feature extraction.
"""

import re
import math
from typing import List, Dict, Tuple


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon Entropy of string to quantify randomness/obfuscation."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum([p * math.log2(p) for p in prob]), 4)


def match_keyword_density(text: str, keywords: List[str]) -> float:
    """Calculate match ratio of keywords normalized between 0.0 and 1.0."""
    if not text or not keywords:
        return 0.0
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw.lower() in text_lower)
    # Scale score with diminishing returns (capped at 1.0)
    score = 1.0 - math.exp(-0.4 * matches)
    return round(score, 4)


def detect_call_to_action(text: str) -> float:
    """Score intensity of call to action phrases."""
    cta_patterns = [
        r"click (here|this link|below)",
        r"open (the attached|attachment|file)",
        r"verify (your|account|details|info)",
        r"login (now|immediately|to continue)",
        r"update (your|credentials|profile|billing)",
        r"download (invoice|file|document)"
    ]
    text_lower = text.lower()
    matches = sum(1 for pat in cta_patterns if re.search(pat, text_lower))
    return round(min(1.0, matches * 0.35), 4)


def detect_social_engineering_tactics(text: str) -> Tuple[float, float, float]:
    """
    Returns (urgency_score, fear_score, authority_score).
    """
    text_lower = text.lower()
    
    urgency_patterns = [
        "urgent", "immediately", "action required", "24 hours", "asap",
        "time sensitive", "suspended within", "expiration", "deadline"
    ]
    fear_patterns = [
        "suspended", "unauthorized access", "legal action", "penalty",
        "account locked", "security breach", "terminated", "compromised"
    ]
    authority_patterns = [
        "executive order", "ceo directive", "management approval", "hr policy",
        "compliance audit", "finance department", "official request"
    ]

    urgency = match_keyword_density(text_lower, urgency_patterns)
    fear = match_keyword_density(text_lower, fear_patterns)
    authority = match_keyword_density(text_lower, authority_patterns)

    return urgency, fear, authority
