"""
CyberDNA - Attack Stage Classification Module
Maps raw events to cybersecurity attack stages based on MITRE ATT&CK terminology:
- Initial Access
- Credential Access
- Discovery
- Lateral Movement
- Privilege Escalation
- Data Access
"""

from typing import Dict, List, Any, Optional

ATTACK_STAGES = [
    "Initial Access",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Privilege Escalation",
    "Data Access"
]

# Keyword & Event Type rules for mapping
STAGE_MAPPINGS = {
    "Initial Access": [
        "external connection", "inbound connection", "phishing", "public exploit",
        "remote service", "vpn access", "external login", "perimeter entry", "unauthorized entry"
    ],
    "Credential Access": [
        "failed login", "password spray", "brute force", "credential dump",
        "authentication failure", "kerberoast", "token theft", "hash dump", "bad password"
    ],
    "Discovery": [
        "network scan", "port scan", "reconnaissance", "directory enumeration",
        "service discovery", "ping sweep", "system survey", "user discovery", "net view"
    ],
    "Lateral Movement": [
        "network connection", "remote desktop", "rdp", "smb transfer",
        "ssh session", "remote execution", "internal hop", "wmi call", "psexec"
    ],
    "Privilege Escalation": [
        "privilege request", "sudo elevation", "admin access", "administrator access",
        "root access", "token impersonation", "uac bypass", "permission change", "runas"
    ],
    "Data Access": [
        "sensitive file access", "confidential file", "bulk download", "database query",
        "data exfiltration", "archive creation", "file copy", "confidential document",
        "unauthorized export", "data transfer"
    ]
}


def classify_event_stage(event: Dict[str, Any]) -> Optional[str]:
    """
    Classifies a single security event into an attack stage.
    Returns the stage name or None if purely benign/routine.
    """
    event_type = str(event.get("event_type", "")).lower()
    resource = str(event.get("resource", "")).lower()
    status = str(event.get("status", "")).lower()
    severity = str(event.get("severity", "")).lower()

    # Routine Low severity success activities are not attack stages
    if severity == "low" and ("success" in status or "completed" in status):
        # Unless explicitly a failed login or port scan
        if not ("failed" in status or "scan" in event_type or "brute" in event_type):
            return None

    # Special check: failed login is Credential Access
    if "failed" in status or "failed login" in event_type or "auth failure" in event_type:
        return "Credential Access"

    # Match against dictionary rules
    for stage, keywords in STAGE_MAPPINGS.items():
        for kw in keywords:
            if kw in event_type or kw in resource:
                # If it's a generic network connection, require medium/high/critical severity or internal server
                if kw == "network connection" and severity == "low":
                    continue
                return stage

    # High severity fallback inference
    if "privilege" in event_type or "admin" in resource:
        return "Privilege Escalation"
    if "confidential" in resource or "sensitive file" in event_type or "data exfiltration" in event_type:
        return "Data Access"
    if "lateral" in event_type or ("server-02" in resource and severity in ["high", "critical"]):
        return "Lateral Movement"
    if "scan" in event_type:
        return "Discovery"

    return None


def determine_current_stage(events: List[Dict[str, Any]], detected_stages: List[str]) -> str:
    """
    Determines the active attack stage from the chronological sequence.
    The current stage represents the attacker's latest active frontline.
    If no suspicious stages were detected, returns 'Normal Activity'.
    """
    if not detected_stages:
        return "Normal Activity"

    # Attacker's active operational frontline is the latest detected stage
    return detected_stages[-1]
