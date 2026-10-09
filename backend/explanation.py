"""
CyberDNA - Explainable AI (XAI) & Defensive Guidance Engine
Generates transparent, evidence-backed justifications ("WHY THIS ALERT?")
derived strictly from actual analyzed event sequences, along with safe recommended actions.
"""

from typing import List, Dict, Any


def generate_explanation(
    events: List[Dict[str, Any]],
    detection_results: Dict[str, Any],
    current_stage: str,
    risk_level: str
) -> List[str]:
    """
    Generates human-understandable, deterministic explanations based strictly
    on events and behavioral indicators identified in the log stream.
    """
    explanations: List[str] = []
    flags = detection_results.get("suspicious_flags", {})
    patterns = detection_results.get("detected_patterns", [])

    if risk_level == "LOW" and not flags.get("privilege_escalation_requested"):
        return [
            "Routine baseline activity: all logged events conform to standard enterprise behavior.",
            "No anomalous authentication bursts or failed login cascades detected.",
            "Resources accessed are standard operational assets without privilege escalation requests."
        ]

    # Concrete evidence extraction
    failed_count = flags.get("repeated_failed_logins", 0)
    if failed_count > 0:
        explanations.append(f"Detected {failed_count} authentication failure(s) in the log stream.")

    if flags.get("failed_then_success"):
        explanations.append("Observed successful authentication immediately following failed login attempts.")

    # Identify sensitive resources touched
    sensitive_files = [
        e.get("resource") for e in events
        if "confidential" in str(e.get("resource", "")).lower()
        or "sensitive" in str(e.get("event_type", "")).lower()
        or "database" in str(e.get("resource", "")).lower()
    ]
    if sensitive_files:
        unique_files = list(set(sensitive_files))[:2]
        explanations.append(f"Sensitive resource access detected: {', '.join(unique_files)}.")

    # Network activity / lateral hops
    if flags.get("internal_lateral_pivot"):
        lateral_dests = [
            e.get("destination_ip") for e in events
            if "server" in str(e.get("destination_ip", "")).lower()
            or "network connection" in str(e.get("event_type", "")).lower()
        ]
        if lateral_dests:
            explanations.append(f"Internal lateral connection established towards target host '{lateral_dests[-1]}'.")
        else:
            explanations.append("Internal network connection indicates potential lateral movement exploration.")

    # Privilege escalation
    if flags.get("privilege_escalation_requested"):
        priv_events = [
            e.get("resource") for e in events
            if "privilege" in str(e.get("event_type", "")).lower()
            or "admin" in str(e.get("resource", "")).lower()
        ]
        if priv_events:
            explanations.append(f"Elevated privilege request observed: '{priv_events[-1]}'.")
        else:
            explanations.append("Privilege escalation request detected within the active session.")

    # Multi-step progression
    if patterns:
        for p in patterns:
            explanations.append(f"Behavioral sequence signature matched: '{p}'.")

    # High severity event proportion
    crit_count = sum(1 for e in events if str(e.get("severity", "")).capitalize() == "Critical")
    if crit_count > 0:
        explanations.append(f"Encountered {crit_count} Critical severity security event(s) in this sequence.")

    # Fallback if list is too brief
    if not explanations:
        explanations.append("Anomalous sequence frequency and severity exceed normal baseline thresholds.")

    return explanations


def generate_recommended_actions(
    current_stage: str,
    risk_level: str,
    detection_results: Dict[str, Any]
) -> List[str]:
    """
    Generates tailored, safe, non-destructive defensive security recommendations.
    Adheres to safety principle: recommendations only, no automated attacks or deletions.
    """
    actions: List[str] = []
    flags = detection_results.get("suspicious_flags", {})

    if risk_level == "LOW":
        return [
            "Continue standard SOC log collection and routine monitoring.",
            "Verify scheduled maintenance windows match logged operations.",
            "Ensure endpoint telemetry agents remain active and healthy."
        ]

    # Core defensive recommendations based on actual stages
    actions.append("Review affected user account and verify identity with account owner.")

    if flags.get("repeated_failed_logins", 0) > 0 or current_stage == "Credential Access":
        actions.append("Inspect recent authentication logs and enforce Multi-Factor Authentication (MFA).")
        actions.append("Prompt user for credential rotation if password spraying is suspected.")

    if flags.get("sensitive_file_touched") or current_stage == "Data Access":
        actions.append("Audit access logs for sensitive files and confidential database resources.")
        actions.append("Verify whether the accessed records match the user's operational role.")

    if flags.get("internal_lateral_pivot") or current_stage == "Lateral Movement":
        actions.append("Review internal firewall and network session logs for suspicious host-to-host pivots.")
        actions.append("Assess network micro-segmentation policies between source and target hosts.")

    if flags.get("privilege_escalation_requested") or current_stage == "Privilege Escalation":
        actions.append("Audit account permissions, administrator group memberships, and role assignments.")
        actions.append("Validate whether the privilege elevation request was authorized by change control.")

    if risk_level in ["HIGH", "CRITICAL"]:
        actions.append("Consider isolating the affected endpoint from the internal subnet if compromise is confirmed.")
        actions.append("Escalate incident telemetry to Tier-2 Security Operations Center (SOC) administrator.")

    return actions
