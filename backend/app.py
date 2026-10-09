"""
CyberDNA - Main Flask Backend Application & REST API
Exposes endpoints for CSV uploads, sample dataset execution, behavioral analysis,
alert queries, user/device risk metrics, history, and report generation.
"""

import os
import sys
import io
import json
import uuid
from datetime import datetime

# Ensure root CyberDNA folder is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from flask import Flask, request, jsonify, send_from_directory, make_response


from backend.database import (
    init_db,
    save_analysis,
    get_latest_analysis,
    get_analysis_by_id,
    get_all_history,
    get_all_alerts,
    clear_database
)
from backend.preprocessing import (
    validate_and_load_csv,
    dataframe_to_event_list,
    PreprocessingError
)
from backend.detection import detect_behavioral_patterns
from backend.stage_classification import determine_current_stage
from backend.prediction import predict_next_attack_stage
from backend.risk_scoring import calculate_overall_risk, calculate_entity_risks
from backend.explanation import generate_explanation, generate_recommended_actions

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
if os.environ.get("VERCEL"):
    DATASET_DIR = "/tmp/dataset"
    REPORTS_DIR = "/tmp/reports"
else:
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Ensure folders exist and DB is initialized
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
init_db()


# -------------------------------------------------------------
# HELPER: Run Core Pipeline
# -------------------------------------------------------------
def run_cyberdna_pipeline(df, source_name="Uploaded Log"):
    """Executes the complete CyberDNA detection & predictive pipeline."""
    events = dataframe_to_event_list(df)

    # 1. Behavioral pattern detection
    detection_res = detect_behavioral_patterns(events)

    # 2. Attack stage determination
    current_stage = determine_current_stage(events, detection_res["stages_encountered"])

    # 3. Next-stage predictive analysis
    predicted_next, confidence, alternatives = predict_next_attack_stage(
        current_stage,
        detection_res["stages_encountered"],
        detection_res["suspicious_flags"]
    )

    # 4. Multi-factor risk scoring
    risk_score, risk_level = calculate_overall_risk(events, detection_res, current_stage)

    # 5. User and Device entity scoring
    user_risks, device_risks = calculate_entity_risks(events)

    # 6. Explainable AI & Defensive actions
    explanations = generate_explanation(events, detection_res, current_stage, risk_level)
    recommendations = generate_recommended_actions(current_stage, risk_level, detection_res)

    # 7. Generate alerts
    alerts = []
    analysis_id = f"CDNA-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    if risk_level in ["HIGH", "CRITICAL"] or detection_res["suspicious_events_count"] > 0:
        primary_user = user_risks[0]["name"] if user_risks else "Unknown"
        primary_device = device_risks[0]["device"] if device_risks else "Unknown"

        alerts.append({
            "alert_id": f"ALT-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": primary_user,
            "source_ip": primary_device,
            "destination_ip": events[-1].get("destination_ip", "Internal"),
            "severity": risk_level,
            "title": f"⚠️ Suspicious Activity Detected: {current_stage}",
            "description": f"Multi-stage behavioral anomaly detected for {primary_user}. Current stage: {current_stage}. Predicted next stage: {predicted_next} ({confidence}% confidence).",
            "current_stage": current_stage,
            "predicted_next_stage": predicted_next,
            "risk_score": risk_score
        })

    analysis_data = {
        "analysis_id": analysis_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_name": source_name,
        "total_events": len(events),
        "suspicious_events": detection_res["suspicious_events_count"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "current_stage": current_stage,
        "predicted_next_stage": predicted_next,
        "confidence": confidence,
        "fingerprint": detection_res["fingerprint"],
        "fingerprint_str": detection_res["fingerprint_str"],
        "top_alternatives": alternatives,
        "explanation": explanations,
        "recommendations": recommendations,
        "user_risks": user_risks,
        "device_risks": device_risks,
        "detected_patterns": detection_res["detected_patterns"],
        "events": events,
        "alerts": alerts
    }

    # Persist in SQLite
    save_analysis(analysis_data, events, alerts)

    return analysis_data


# -------------------------------------------------------------
# STATIC & FRONTEND ROUTES
# -------------------------------------------------------------
@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    if os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")


# -------------------------------------------------------------
# API: LEGACY INGESTION ROUTES (DISABLED - SCAN-ONLY ARCHITECTURE)
# -------------------------------------------------------------
@app.route("/api/sample-datasets", methods=["GET"])
def get_sample_datasets():
    return jsonify({"success": False, "error": "Sample datasets have been removed. Use live target scanning."}), 404


@app.route("/api/upload", methods=["POST"])
def upload_csv():
    return jsonify({
        "success": False,
        "error": "CSV log upload has been disabled. CyberDNA operates exclusively on real-time target vulnerability scans."
    }), 400


@app.route("/api/analyze", methods=["POST"])
def analyze_data():
    return jsonify({
        "success": False,
        "error": "Dummy sample analysis is disabled. Enter a target domain or IP on the dashboard to scan."
    }), 400


from backend.scanner import scan_target

# -------------------------------------------------------------
# API: TARGET VULNERABILITY SCANNER
# -------------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def scan_target_endpoint():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()

    if not target:
        return jsonify({
            "success": False,
            "error": "Target input cannot be empty. Please enter a domain or IP address."
        }), 400

    try:
        # Extract client's network IP (handling reverse proxy if present)
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
        result = scan_target(target, user_ip=client_ip)
        if not result.get("success"):
            return jsonify({
                "success": False,
                "error": result.get("error", "Failed to scan target.")
            }), 400

        scan_data = result["data"]
        # Save scan result to SQLite
        save_analysis(scan_data, scan_data.get("events", []), scan_data.get("alerts", []))
        return jsonify({"success": True, "data": scan_data})
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"An unexpected error occurred while scanning target: {str(e)}"
        }), 500


# -------------------------------------------------------------
# API: DASHBOARD OVERVIEW
# -------------------------------------------------------------
@app.route("/api/dashboard", methods=["GET"])
def get_dashboard_data():
    latest = get_latest_analysis()
    if not latest:
        return jsonify({
            "success": True,
            "has_data": False,
            "data": None
        })

    # Summary KPI computation
    user_risks = latest.get("user_risks", [])
    device_risks = latest.get("device_risks", [])

    high_risk_users = sum(1 for u in user_risks if u.get("risk_score", 0) >= 61)
    high_risk_devices = sum(1 for d in device_risks if d.get("risk_score", 0) >= 61)

    # Attack stage distribution
    events = latest.get("events", [])
    stage_dist = {}
    severity_dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    for ev in events:
        st = ev.get("attack_stage", "Routine")
        stage_dist[st] = stage_dist.get(st, 0) + 1
        sev = str(ev.get("severity", "Low")).capitalize()
        if sev in severity_dist:
            severity_dist[sev] += 1

    source_name = latest.get("source_name", "")
    target_val = latest.get("target") or (source_name.replace("Target: ", "").strip() if source_name.startswith("Target:") else None)

    summary = {
        "analysis_id": latest.get("analysis_id"),
        "timestamp": latest.get("timestamp"),
        "source_name": source_name,
        "target": target_val,
        "total_events": latest.get("total_events", 0),
        "threats_detected": latest.get("suspicious_events", 0),
        "critical_alerts": len([a for a in latest.get("alerts", []) if a.get("severity") in ["CRITICAL", "Critical"]]),
        "high_risk_users": high_risk_users,
        "high_risk_devices": high_risk_devices,
        "average_risk_score": latest.get("risk_score", 0),
        "risk_level": latest.get("risk_level", "LOW"),
        "current_stage": latest.get("current_stage", "Normal Activity"),
        "active_stages": latest.get("active_stages", []),
        "user_ip": latest.get("user_ip", latest.get("origin_ip")),
        "origin_ip": latest.get("origin_ip"),
        "predicted_next_stage": latest.get("predicted_next_stage", "None"),
        "confidence": latest.get("confidence", 0),
        "fingerprint": latest.get("fingerprint", []),
        "fingerprint_str": latest.get("fingerprint_str", ""),
        "top_alternatives": latest.get("top_alternatives", []),
        "explanation": latest.get("explanation", []),
        "explanation_by_ip": latest.get("explanation_by_ip", {}),
        "recommendations": latest.get("recommendations", []),
        "remediation_playbook": latest.get("remediation_playbook", {}),
        "user_risks": user_risks,
        "device_risks": device_risks,
        "stage_distribution": stage_dist,
        "severity_distribution": severity_dist,
        "recent_alerts": latest.get("alerts", []),
        "events": events
    }

    return jsonify({"success": True, "has_data": True, "data": summary})


# -------------------------------------------------------------
# API: ALERTS
# -------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    severity = request.args.get("severity", None)
    alerts = get_all_alerts(severity)
    return jsonify({"success": True, "count": len(alerts), "alerts": alerts})


# -------------------------------------------------------------
# API: USERS & DEVICES
# -------------------------------------------------------------
@app.route("/api/users", methods=["GET"])
def get_users_risk():
    latest = get_latest_analysis()
    if not latest:
        return jsonify({"success": True, "users": []})
    return jsonify({"success": True, "users": latest.get("user_risks", [])})


@app.route("/api/devices", methods=["GET"])
def get_devices_risk():
    latest = get_latest_analysis()
    if not latest:
        return jsonify({"success": True, "devices": []})
    return jsonify({"success": True, "devices": latest.get("device_risks", [])})


# -------------------------------------------------------------
# API: HISTORY
# -------------------------------------------------------------
@app.route("/api/history", methods=["GET"])
def get_history():
    history = get_all_history()
    return jsonify({"success": True, "history": history})


@app.route("/api/history/<analysis_id>", methods=["GET"])
def get_history_detail(analysis_id):
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"success": False, "error": "Analysis run not found"}), 404
    return jsonify({"success": True, "data": analysis})


# -------------------------------------------------------------
# API: REPORTS
# -------------------------------------------------------------
@app.route("/api/reports", methods=["GET"])
def get_reports_list():
    history = get_all_history(20)
    reports = []
    for h in history:
        reports.append({
            "report_id": f"REP-{h['analysis_id']}",
            "analysis_id": h["analysis_id"],
            "title": f"Security Assessment: {h['source_name']}",
            "created_at": h["timestamp"],
            "risk_score": h["risk_score"],
            "risk_level": h["risk_level"]
        })
    return jsonify({"success": True, "reports": reports})


@app.route("/api/reports/download/<analysis_id>", methods=["GET"])
def download_report(analysis_id):
    format_type = request.args.get("format", "markdown").lower()
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        latest = get_latest_analysis()
        if latest and latest.get("analysis_id") == analysis_id:
            analysis = latest
        else:
            return jsonify({"success": False, "error": "Analysis not found"}), 404

    # Generate Markdown Report
    explanations_md = "\n".join([f"- {e}" for e in analysis.get("explanation", [])])
    recommendations_md = "\n".join([f"- [ ] {r}" for r in analysis.get("recommendations", [])])
    fingerprint_text = analysis.get("fingerprint_str", " -> ".join(analysis.get("fingerprint", [])))

    report_content = f"""# CYBERDNA DEFENSIVE SECURITY ASSESSMENT REPORT
**Report Reference:** REP-{analysis.get('analysis_id')}
**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Source Analyzed:** {analysis.get('source_name')}

---

## 1. Executive Summary
- **Overall Risk Score:** {analysis.get('risk_score')}/100
- **Risk Level:** {analysis.get('risk_level')}
- **Total Security Events:** {analysis.get('total_events')}
- **Suspicious Events Identified:** {analysis.get('suspicious_events')}
- **Current Attack Stage:** {analysis.get('current_stage')}
- **Possible Next Stage:** {analysis.get('predicted_next_stage')}
- **Prediction Confidence:** {analysis.get('confidence')}%

---

## 2. Behavioral Attack Fingerprint
**Sequential Pattern:**
> `{fingerprint_text or 'None'}`

---

## 3. Explainable Analysis: "Why This Alert?"
{explanations_md}

---

## 4. Entity Risk Overview
### Primary Users at Risk
| User / Origin IP | Active Stage | Risk Score | Threat Level |
|---|---|---|---|
"""
    for u in analysis.get("user_risks", [])[:5]:
        report_content += f"| {u.get('name')} | {u.get('active_stage', 'Discovery')} | {u.get('risk_score')}/100 | {u.get('threat_level', u.get('risk_level', 'LOW'))} |\n"

    report_content += """
### High Risk Devices
| Device | Risk Score | Risk Level | Total Events | Suspicious |
|---|---|---|---|---|
"""
    for d in analysis.get("device_risks", [])[:5]:
        report_content += f"| {d.get('device')} | {d.get('risk_score')}/100 | {d.get('risk_level')} | {d.get('events_count')} | {d.get('suspicious_count')} |\n"

    report_content += f"""
---

## 5. Recommended Defensive Actions (Non-Destructive)
{recommendations_md}
"""

    playbook = analysis.get("remediation_playbook", {})
    if playbook:
        report_content += f"""
---

## 6. Defensive Remediation & Honeypot Playbook (Automated Hardening)
- **Active Canary Token:** `{playbook.get('decoy_id', 'canary-trap-active')}`
- **Decoy Header:** `X-Debug-Canary-Gateway: {playbook.get('decoy_id', 'canary-trap-active')}`

### Nginx Hardening Configuration:
```nginx
{playbook.get('nginx', {}).get('snippet', '')}
```

### Apache Hardening Configuration:
```apache
{playbook.get('apache', {}).get('snippet', '')}
```

### Active Deception Honeypot Guide:
```text
{playbook.get('honeypot', {}).get('snippet', '')}
```
"""

    report_content += f"""
---
*Notice: CyberDNA is an early-warning predictive system. Predictions indicate statistical likelihood and do not constitute an absolute guarantee.*
"""

    if format_type == "json":
        response = make_response(json.dumps(analysis, indent=2))
        response.headers["Content-Disposition"] = f"attachment; filename=CyberDNA_Report_{analysis_id}.json"
        response.headers["Content-Type"] = "application/json"
        return response

    response = make_response(report_content)
    response.headers["Content-Disposition"] = f"attachment; filename=CyberDNA_Report_{analysis_id}.md"
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"
    return response


# -------------------------------------------------------------
# API: REMEDIATION CONFIG DOWNLOAD
# -------------------------------------------------------------
@app.route("/api/remediation/download/<analysis_id>", methods=["GET"])
def download_remediation(analysis_id):
    server = request.args.get("server", "nginx").lower()
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        latest = get_latest_analysis()
        if latest and latest.get("analysis_id") == analysis_id:
            analysis = latest
        else:
            return jsonify({"success": False, "error": "Analysis run not found"}), 404

    playbook = analysis.get("remediation_playbook", {})
    if not playbook or server not in playbook:
        return jsonify({"success": False, "error": f"No playbook configuration found for server type: {server}"}), 404

    server_data = playbook[server]
    snippet = server_data.get("snippet", "")
    filename = server_data.get("filename", f"remediation_{server}.conf")

    response = make_response(snippet)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


# -------------------------------------------------------------
# API: SETTINGS / RESET
# -------------------------------------------------------------
@app.route("/api/settings/reset", methods=["POST"])
def reset_system():
    try:
        clear_database()
        return jsonify({"success": True, "message": "System history and alerts reset successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print("  CYBERDNA - AI-Powered Predictive Early-Warning System")
    print(f"  Running on port {port}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False)
