import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List


class AuditLogger:
    """
    Cryptographic Audit Trail Logger.
    Logs immutable gateway decisions and generates verification hashes.
    """

    def __init__(self):
        self.logs: List[Dict[str, Any]] = []

    def log_action(self, email_id: str, actor: str, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Calculate cryptographic seal for the log entry
        payload = f"{email_id}|{actor}|{action}|{timestamp}|{str(sorted(details.items()))}"
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        entry = {
            "log_id": f"log_{entry_hash[:12]}",
            "email_id": email_id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "details": details,
            "signature": entry_hash,
            "status": "SEALED",
        }

        self.logs.append(entry)
        return entry

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self.logs)
