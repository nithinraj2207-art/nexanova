"""
CyberDNA - SQLite Database Manager
Handles database initialization, analysis runs, security events, alerts, and entity risks.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database")
DB_PATH = os.path.join(DB_DIR, "cyberdna.db")


def get_db_connection():
    """Create and return a database connection with dict-like row factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table: analyses (stores high-level results of each log analysis run)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        source_name TEXT NOT NULL,
        total_events INTEGER NOT NULL,
        suspicious_events INTEGER NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        current_stage TEXT NOT NULL,
        predicted_next_stage TEXT NOT NULL,
        confidence REAL NOT NULL,
        fingerprint TEXT,
        top_alternatives TEXT,
        explanation TEXT,
        recommendations TEXT,
        user_risks TEXT,
        device_risks TEXT,
        active_stages TEXT,
        explanation_by_ip TEXT,
        remediation_playbook TEXT
    )
    """)

    # Forward migration for existing database instances
    try:
        cursor.execute("ALTER TABLE analyses ADD COLUMN active_stages TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE analyses ADD COLUMN explanation_by_ip TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE analyses ADD COLUMN remediation_playbook TEXT")
    except Exception:
        pass

    # Table: security_events (individual events associated with an analysis)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        user TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        resource TEXT NOT NULL,
        status TEXT NOT NULL,
        is_suspicious INTEGER DEFAULT 0,
        risk_contribution INTEGER DEFAULT 0,
        FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
    )
    """)

    # Table: alerts (generated security alerts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        alert_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        user TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        current_stage TEXT NOT NULL,
        predicted_next_stage TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
    )
    """)

    # Table: reports_metadata (generated reports index)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        analysis_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        file_path TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
    )
    """)

    conn.commit()
    conn.close()


def save_analysis(analysis_data: Dict[str, Any], events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> str:
    """Saves a complete analysis session, its events, and alerts."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    analysis_id = analysis_data["analysis_id"]

    cursor.execute("""
    INSERT INTO analyses (
        analysis_id, timestamp, source_name, total_events, suspicious_events,
        risk_score, risk_level, current_stage, predicted_next_stage,
        confidence, fingerprint, top_alternatives, explanation,
        recommendations, user_risks, device_risks, active_stages, explanation_by_ip, remediation_playbook
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_id,
        analysis_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        analysis_data.get("source_name", "Unknown Source"),
        analysis_data.get("total_events", len(events)),
        analysis_data.get("suspicious_events", 0),
        analysis_data.get("risk_score", 0),
        analysis_data.get("risk_level", "LOW"),
        analysis_data.get("current_stage", "Normal Activity"),
        analysis_data.get("predicted_next_stage", "None"),
        analysis_data.get("confidence", 0.0),
        json.dumps(analysis_data.get("fingerprint", [])),
        json.dumps(analysis_data.get("top_alternatives", [])),
        json.dumps(analysis_data.get("explanation", [])),
        json.dumps(analysis_data.get("recommendations", [])),
        json.dumps(analysis_data.get("user_risks", [])),
        json.dumps(analysis_data.get("device_risks", [])),
        json.dumps(analysis_data.get("active_stages", [])),
        json.dumps(analysis_data.get("explanation_by_ip", {})),
        json.dumps(analysis_data.get("remediation_playbook", {}))
    ))

    # Save events
    for ev in events:
        cursor.execute("""
        INSERT INTO security_events (
            analysis_id, timestamp, user, source_ip, destination_ip,
            event_type, severity, resource, status, is_suspicious, risk_contribution
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            ev.get("timestamp", ""),
            ev.get("user", "Unknown"),
            ev.get("source_ip", "0.0.0.0"),
            ev.get("destination_ip", "0.0.0.0"),
            ev.get("event_type", "Unknown"),
            ev.get("severity", "Low"),
            ev.get("resource", "General"),
            ev.get("status", "Unknown"),
            1 if ev.get("is_suspicious") else 0,
            ev.get("risk_contribution", 0)
        ))

    # Save alerts
    for al in alerts:
        cursor.execute("""
        INSERT INTO alerts (
            analysis_id, alert_id, timestamp, user, source_ip, destination_ip,
            severity, title, description, current_stage, predicted_next_stage, risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            al.get("alert_id", f"ALT-{datetime.now().strftime('%f')}"),
            al.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            al.get("user", "Unknown"),
            al.get("source_ip", "Unknown"),
            al.get("destination_ip", "Unknown"),
            al.get("severity", "Medium"),
            al.get("title", "Security Alert"),
            al.get("description", ""),
            al.get("current_stage", "Unknown"),
            al.get("predicted_next_stage", "Unknown"),
            al.get("risk_score", 50)
        ))

    conn.commit()
    conn.close()
    return analysis_id


def get_latest_analysis() -> Optional[Dict[str, Any]]:
    """Retrieves the most recent analysis run."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    analysis = dict(row)
    # Parse JSON fields
    for field in ["fingerprint", "top_alternatives", "explanation", "recommendations", "user_risks", "device_risks", "active_stages", "explanation_by_ip", "remediation_playbook"]:
        if analysis.get(field):
            try:
                analysis[field] = json.loads(analysis[field])
            except Exception:
                analysis[field] = [] if field not in ["explanation_by_ip", "remediation_playbook"] else {}
        elif field == "active_stages":
            analysis["active_stages"] = []
        elif field == "explanation_by_ip":
            analysis["explanation_by_ip"] = {}
        elif field == "remediation_playbook":
            analysis["remediation_playbook"] = {}

    # Get associated events
    cursor.execute("SELECT * FROM security_events WHERE analysis_id = ? ORDER BY id ASC", (analysis["analysis_id"],))
    events = [dict(r) for r in cursor.fetchall()]
    analysis["events"] = events

    # Get associated alerts
    cursor.execute("SELECT * FROM alerts WHERE analysis_id = ? ORDER BY id DESC", (analysis["analysis_id"],))
    alerts = [dict(r) for r in cursor.fetchall()]
    analysis["alerts"] = alerts

    conn.close()
    return analysis


def get_analysis_by_id(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an analysis by its unique ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    analysis = dict(row)
    for field in ["fingerprint", "top_alternatives", "explanation", "recommendations", "user_risks", "device_risks", "active_stages", "explanation_by_ip", "remediation_playbook"]:
        if analysis.get(field):
            try:
                analysis[field] = json.loads(analysis[field])
            except Exception:
                analysis[field] = [] if field not in ["explanation_by_ip", "remediation_playbook"] else {}
        elif field == "active_stages":
            analysis["active_stages"] = []
        elif field == "explanation_by_ip":
            analysis["explanation_by_ip"] = {}
        elif field == "remediation_playbook":
            analysis["remediation_playbook"] = {}

    cursor.execute("SELECT * FROM security_events WHERE analysis_id = ? ORDER BY id ASC", (analysis_id,))
    analysis["events"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM alerts WHERE analysis_id = ? ORDER BY id DESC", (analysis_id,))
    analysis["alerts"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return analysis


def get_all_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns a list of historical analysis summaries."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, analysis_id, timestamp, source_name, total_events, suspicious_events,
           risk_score, risk_level, current_stage, predicted_next_stage, confidence
    FROM analyses
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_alerts(severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all alerts, optionally filtered by severity."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    if severity and severity.lower() != "all":
        cursor.execute("SELECT * FROM alerts WHERE LOWER(severity) = LOWER(?) ORDER BY id DESC", (severity,))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC")

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_database():
    """Clears all historical data from tables (for testing or reset in settings)."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM security_events")
    cursor.execute("DELETE FROM analyses")
    cursor.execute("DELETE FROM reports_metadata")
    conn.commit()
    conn.close()
