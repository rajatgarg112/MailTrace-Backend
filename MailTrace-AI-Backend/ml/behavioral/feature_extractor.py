"""
Behavioral Feature Extractor.
Extracts Category 7 features: sending_frequency, volume_anomaly, time_anomaly,
location_anomaly, sender_behavior_change, conversation_anomaly, recipient_count,
bulk_score, historical_similarity, conversation_exists.
"""

from typing import Dict, Any, Optional, List


def extract_behavioral_features(
    sender_address: str = "",
    recipient_count: int = 1,
    sender_history: Optional[Dict[str, Any]] = None,
    current_time_hour: Optional[int] = None,
    originating_country: Optional[str] = None
) -> Dict[str, Any]:
    """
    Extract behavioral baseline comparison features.
    """
    history = sender_history or {}

    # Historical metrics
    seen_before = history.get("seen_before", False)
    avg_daily_volume = history.get("avg_daily_volume", 1.0)
    recent_volume = history.get("recent_volume", 1.0)
    usual_hours = history.get("usual_hours", list(range(6, 22)))  # Standard business hours
    usual_countries = history.get("usual_countries", [])
    past_recipient_avg = history.get("past_recipient_avg", 1.0)
    conversation_exists = history.get("conversation_exists", False)

    # 1. Sending Frequency & Volume Anomaly
    volume_anomaly = 0.0
    if seen_before and avg_daily_volume > 0:
        ratio = recent_volume / avg_daily_volume
        if ratio > 3.0:
            volume_anomaly = min(1.0, (ratio - 3.0) / 10.0)

    # 2. Time Anomaly
    time_anomaly = 0.0
    if seen_before and current_time_hour is not None and usual_hours:
        if current_time_hour not in usual_hours:
            time_anomaly = 0.75

    # 3. Location Anomaly
    location_anomaly = 0.0
    if seen_before and originating_country and usual_countries:
        if originating_country not in usual_countries:
            location_anomaly = 0.85

    # 4. Bulk Score (High recipient count or mass mailing signals)
    bulk_score = 0.0
    if recipient_count > 50:
        bulk_score = 0.95
    elif recipient_count > 10:
        bulk_score = 0.60
    elif recipient_count > 3:
        bulk_score = 0.25

    # 5. Conversation & Behavior Change Anomaly
    sender_behavior_change = max(volume_anomaly, time_anomaly, location_anomaly)
    
    convo_anomaly = 0.0
    if not conversation_exists and seen_before and recipient_count > past_recipient_avg * 2:
        convo_anomaly = 0.70

    historical_sim = 1.0 if seen_before else 0.0

    return {
        "sending_frequency": float(recent_volume),
        "volume_anomaly": round(float(volume_anomaly), 4),
        "time_anomaly": round(float(time_anomaly), 4),
        "location_anomaly": round(float(location_anomaly), 4),
        "sender_behavior_change": round(float(sender_behavior_change), 4),
        "conversation_anomaly": round(float(convo_anomaly), 4),
        "recipient_count": int(recipient_count),
        "bulk_score": round(float(bulk_score), 4),
        "historical_similarity": round(float(historical_sim), 4),
        "conversation_exists": bool(conversation_exists)
    }
