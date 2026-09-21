from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class InvestigationTimelineTracker:
    """
    Step-by-step investigation timeline tracker.
    Builds an immutable chronological record from SMTP ingestion
    through multi-engine security & ML checks to final delivery enforcement.
    """

    def __init__(self, email_id: str):
        self.email_id = email_id
        self.events: List[Dict[str, Any]] = []
        self._sequence = 1

    def record_event(
        self,
        stage: str,
        event_description: str,
        status: str = "COMPLETED",
        provenance: str = "VERIFIED_EVIDENCE",
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Appends an immutable chronological event.
        Compatible with both Backend API schema and Frontend UI contract.
        """
        now = datetime.now(timezone.utc)
        iso_timestamp = now.isoformat()
        time_display = now.strftime("%H:%M:%S.%f")[:-3]

        event = {
            "sequence": self._sequence,
            "timestamp": iso_timestamp,
            "time": time_display,
            "stage": stage,
            "status": status,
            "event": event_description,
            "details": event_description,
            "extra": details or {},
            "provenance": provenance,
        }

        self.events.append(event)
        self._sequence += 1
        return event

    def get_timeline(self) -> List[Dict[str, Any]]:
        return list(self.events)
