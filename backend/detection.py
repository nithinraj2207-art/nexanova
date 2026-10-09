"""
CyberDNA - Behavioral Pattern Detection Engine
Analyzes sequential event streams, extracts behavioral fingerprints,
and detects complex multi-stage attack patterns (not just single isolated events).
"""

from typing import List, Dict, Any, Tuple
from backend.stage_classification import classify_event_stage


def detect_behavioral_patterns(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Performs end-to-end behavioral sequence analysis.
    Returns:
        - suspicious_events_count
        - detected_patterns: List of recognized attack sequence patterns
        - fingerprint: List of human-readable sequence stages
        - fingerprint_str: Display string, e.g., "Login -> File Access -> Network Activity -> Privilege Request"
        - stages_encountered: List of attack stages in sequence
        - suspicious_flags: Dict of detected behavioral indicators
    """
    if not events:
        return {
            "suspicious_events_count": 0,
            "detected_patterns": [],
            "fingerprint": [],
            "fingerprint_str": "None",
            "stages_encountered": [],
            "suspicious_flags": {}
        }

    detected_stages = []
    fingerprint_items = []
    suspicious_flags = {
        "repeated_failed_logins": 0,
        "failed_then_success": False,
        "sensitive_file_touched": False,
        "internal_lateral_pivot": False,
        "privilege_escalation_requested": False,
        "unusual_high_severity_count": 0,
        "abnormal_hour_activity": False,
        "multi_destination_activity": False
    }

    # Tracking states
    failed_login_count = 0
    prior_was_failed = False
    destinations = set()
    users = set()

    for idx, ev in enumerate(events):
        ev_type = str(ev.get("event_type", "")).lower()
        resource = str(ev.get("resource", "")).lower()
        status = str(ev.get("status", "")).lower()
        severity = str(ev.get("severity", "")).lower()
        dest = str(ev.get("destination_ip", ""))
        user = str(ev.get("user", ""))

        destinations.add(dest)
        users.add(user)

        # 1. Failed Login tracking
        if "failed" in status or "failed login" in ev_type:
            failed_login_count += 1
            prior_was_failed = True
            ev["is_suspicious"] = True
            ev["risk_contribution"] = 15
            fingerprint_items.append("Failed Login")
        elif prior_was_failed and ("success" in status or "successful login" in ev_type):
            suspicious_flags["failed_then_success"] = True
            ev["is_suspicious"] = True
            ev["risk_contribution"] = 25
            fingerprint_items.append("Successful Login")
            prior_was_failed = False
        else:
            if "login" in ev_type or "auth" in ev_type:
                fingerprint_items.append("Login")

        # 2. Sensitive File / Data Access
        if ("confidential" in resource or "sensitive file" in ev_type or "data exfiltration" in ev_type) and severity in ["medium", "high", "critical"]:
            suspicious_flags["sensitive_file_touched"] = True
            ev["is_suspicious"] = True
            ev["risk_contribution"] = max(ev.get("risk_contribution", 0), 20)
            fingerprint_items.append("Sensitive File Access")

        # 3. Network Activity / Lateral Movement
        if ("network connection" in ev_type or "rdp" in ev_type or "lateral" in ev_type or "internal server" in resource) and severity in ["medium", "high", "critical"]:
            suspicious_flags["internal_lateral_pivot"] = True
            if len(destinations) > 1 or "internal server" in resource or "server-02" in dest.lower():
                ev["is_suspicious"] = True
                ev["risk_contribution"] = max(ev.get("risk_contribution", 0), 20)
            fingerprint_items.append("Network Activity")

        # 4. Privilege Escalation
        if "privilege" in ev_type or "admin" in resource or "root" in resource or "sudo" in ev_type:
            suspicious_flags["privilege_escalation_requested"] = True
            ev["is_suspicious"] = True
            ev["risk_contribution"] = max(ev.get("risk_contribution", 0), 30)
            fingerprint_items.append("Privilege Request")

        # 5. Severity flags
        if severity in ["high", "critical"]:
            suspicious_flags["unusual_high_severity_count"] += 1
            if not ev.get("is_suspicious"):
                ev["is_suspicious"] = True
                ev["risk_contribution"] = 15

        # Classify attack stage
        stage = classify_event_stage(ev)
        if stage:
            detected_stages.append(stage)
            ev["attack_stage"] = stage
        else:
            ev["attack_stage"] = "Routine Activity"

    suspicious_flags["repeated_failed_logins"] = failed_login_count
    if len(destinations) > 1:
        suspicious_flags["multi_destination_activity"] = True

    # Collapse duplicate consecutive fingerprint tokens
    collapsed_fingerprint = []
    for item in fingerprint_items:
        if not collapsed_fingerprint or collapsed_fingerprint[-1] != item:
            collapsed_fingerprint.append(item)

    fingerprint_str = " -> ".join(collapsed_fingerprint) if collapsed_fingerprint else "Normal System Activity"

    # Known complex pattern matches
    detected_patterns = []
    if suspicious_flags["repeated_failed_logins"] >= 2 and suspicious_flags["failed_then_success"]:
        detected_patterns.append("Brute Force followed by Credential Compromise")

    if suspicious_flags["sensitive_file_touched"] and suspicious_flags["internal_lateral_pivot"]:
        detected_patterns.append("Post-Exploitation Lateral Exploration")

    if suspicious_flags["internal_lateral_pivot"] and suspicious_flags["privilege_escalation_requested"]:
        detected_patterns.append("Cross-Host Privilege Escalation Attempt")

    if len(collapsed_fingerprint) >= 3 and any("Privilege" in f for f in collapsed_fingerprint):
        detected_patterns.append("Multi-Stage Advanced Intrusion Sequence")

    suspicious_count = sum(1 for e in events if e.get("is_suspicious"))

    return {
        "suspicious_events_count": suspicious_count,
        "detected_patterns": detected_patterns,
        "fingerprint": collapsed_fingerprint,
        "fingerprint_str": fingerprint_str,
        "stages_encountered": detected_stages,
        "suspicious_flags": suspicious_flags
    }
