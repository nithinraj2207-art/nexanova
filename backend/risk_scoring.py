"""
CyberDNA - Multi-Factor Risk Scoring Engine
Calculates overall composite risk scores (0-100), risk levels (LOW, MEDIUM, HIGH, CRITICAL),
and granular entity risk ratings for Users and Devices.
"""

from typing import List, Dict, Any, Tuple


def calculate_risk_level(score: int) -> str:
    """Maps numerical score (0-100) to standard cybersecurity severity bands."""
    if score >= 81:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    return "LOW"


def calculate_overall_risk(
    events: List[Dict[str, Any]],
    detection_results: Dict[str, Any],
    current_stage: str
) -> Tuple[int, str]:
    """
    Computes weighted 0-100 risk score based on:
    - Event severities
    - Ratio of suspicious events
    - Sequence progression flags
    - Failed login counts
    - Privilege requests and sensitive assets touched
    """
    if not events:
        return 0, "LOW"

    suspicious_count = detection_results.get("suspicious_events_count", 0)
    flags = detection_results.get("suspicious_flags", {})
    patterns = detection_results.get("detected_patterns", [])

    # If completely normal baseline
    if suspicious_count == 0 and current_stage == "Normal Activity":
        return 18, "LOW"

    # Multi-factor accumulation
    score = 20  # Base starting point for suspicious detection

    # Factor 1: Suspicious event proportion
    suspicious_ratio = suspicious_count / max(1, len(events))
    score += int(suspicious_ratio * 15)

    # Factor 2: Severity weights
    high_crit_events = sum(
        1 for e in events if str(e.get("severity", "")).capitalize() in ["High", "Critical"]
    )
    score += min(16, high_crit_events * 4)

    # Factor 3: Specific behavioral indicators
    if flags.get("repeated_failed_logins", 0) >= 1:
        score += 8
    if flags.get("failed_then_success"):
        score += 8
    if flags.get("sensitive_file_touched"):
        score += 7
    if flags.get("internal_lateral_pivot"):
        score += 7
    if flags.get("privilege_escalation_requested"):
        score += 10

    # Factor 4: Detected multi-step attack pattern bonus
    if len(patterns) > 0:
        score += min(10, len(patterns) * 3)

    # Factor 5: Attack stage depth
    stage_bonus = {
        "Initial Access": 4,
        "Credential Access": 6,
        "Discovery": 8,
        "Lateral Movement": 11,
        "Privilege Escalation": 14,
        "Data Access": 16
    }
    score += stage_bonus.get(current_stage, 5)

    # Clamp to [0, 100]
    final_score = max(5, min(100, score))
    risk_level = calculate_risk_level(final_score)

    return final_score, risk_level


def calculate_entity_risks(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Aggregates risk scores grouped by User and by Device (Source/Destination IP).
    Returns lists of dicts ready for dashboard presentation.
    """
    user_stats: Dict[str, Dict[str, Any]] = {}
    device_stats: Dict[str, Dict[str, Any]] = {}

    for ev in events:
        user = ev.get("user", "Unknown")
        src_ip = ev.get("source_ip", "0.0.0.0")
        dst_ip = ev.get("destination_ip", "0.0.0.0")
        sev = str(ev.get("severity", "")).capitalize()
        is_susp = ev.get("is_suspicious", False)

        weight = 5
        if sev == "Critical":
            weight = 25
        elif sev == "High":
            weight = 18
        elif sev == "Medium":
            weight = 10

        if is_susp:
            weight += 15

        # Update User
        if user not in user_stats:
            user_stats[user] = {"total": 0, "suspicious": 0, "raw_score": 10}
        user_stats[user]["total"] += 1
        if is_susp:
            user_stats[user]["suspicious"] += 1
        user_stats[user]["raw_score"] += weight

        # Update Source Device
        for dev in [src_ip, dst_ip]:
            if not dev or dev == "Unknown":
                continue
            if dev not in device_stats:
                device_stats[dev] = {"total": 0, "suspicious": 0, "raw_score": 10}
            device_stats[dev]["total"] += 1
            if is_susp:
                device_stats[dev]["suspicious"] += 1
            device_stats[dev]["raw_score"] += weight // 2

    # Normalize users into structured records
    users_list = []
    for user, data in user_stats.items():
        score = min(98, max(12, data["raw_score"]))
        # If no suspicious activity for this user, keep under 30
        if data["suspicious"] == 0:
            score = min(28, score)
        level = calculate_risk_level(score)
        users_list.append({
            "name": user,
            "risk_score": score,
            "risk_level": level,
            "events_count": data["total"],
            "suspicious_count": data["suspicious"]
        })

    # Sort users by risk score descending
    users_list.sort(key=lambda x: x["risk_score"], reverse=True)

    # Normalize devices
    devices_list = []
    for dev, data in device_stats.items():
        score = min(98, max(10, data["raw_score"]))
        if data["suspicious"] == 0:
            score = min(25, score)
        level = calculate_risk_level(score)
        devices_list.append({
            "device": dev,
            "risk_score": score,
            "risk_level": level,
            "events_count": data["total"],
            "suspicious_count": data["suspicious"]
        })

    # Sort devices by risk score descending
    devices_list.sort(key=lambda x: x["risk_score"], reverse=True)

    return users_list, devices_list
