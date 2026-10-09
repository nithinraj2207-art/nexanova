# CYBERDNA: AI-Powered Predictive Cyberattack Early-Warning System

> *"Detect the Pattern. Predict the Attack. Stop It Early."*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)](https://palletsprojects.com/p/flask/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Complete%20%26%20Functional-cyan.svg)]()

CyberDNA is a defensive cybersecurity web application that analyzes sequences of security events, extracts behavioral fingerprints, determines the active attack stage, forecasts possible next attack stages, calculates multi-factor risk scores, and provides transparent, explainable alerts through an interactive dark SOC dashboard.

---

## 📌 1. Problem Statement
Traditional Intrusion Detection Systems (IDS) and Security Information and Event Management (SIEM) tools frequently generate alerts on single isolated events or after catastrophic damages (such as data exfiltration or ransomware encryption) have already taken place. Analysts face high alert fatigue and lack early-stage probabilistic forecasts of where an attacker will strike next within the intrusion kill-chain.

## 🎯 2. Project Objective
CyberDNA bridges this gap by functioning as a defensive early-warning system. Rather than evaluating isolated log entries, CyberDNA models the **chronological sequence** of user and device behavior. By mapping observed actions against the **MITRE ATT&CK framework** using sequential Markov state modeling and heuristic correlation, it identifies the active attack stage, predicts likely subsequent tactics with confidence ratings, and prescribes non-destructive defensive actions.

> **Defensive Scope Notice:** CyberDNA is strictly a defensive early-warning platform. It does not exploit systems, harvest credentials, delete files, or attack endpoints. Predictions indicate probabilistic likelihoods based on kill-chain patterns and do not guarantee future actions.

---

## 🏗️ 3. Core Architecture & Workflow

```text
       Security Event Telemetry (CSV / Sample Presets)
                            ↓
                Data Ingestion & Cleaning
       (Header validation, timestamp chronological sorting)
                            ↓
                Sequential Behavioral Analysis
       (State-tracking, failure cascades, cross-host pivots)
                            ↓
             Attack Fingerprint Synthesis
       (e.g., Login → File Access → Network → Privilege Request)
                            ↓
                Current Attack Stage Detection
    (Initial Access | Credential Access | Discovery | Lateral | Privilege | Data)
                            ↓
            Markov-Bayesian Next-Stage Prediction
            (Possible Next Stage + Confidence % + Alternatives)
                            ↓
                Multi-Factor Risk Scoring (0–100)
             (Low [0-30], Medium [31-60], High [61-80], Critical [81-100])
                            ↓
            Explainable AI: "WHY THIS ALERT?"
          (Transparent evidence derived strictly from logs)
                            ↓
         Interactive SOC Dashboard & Security Audit Reports
```

---

## ✨ 4. Key Features

1. **Dual Ingestion Engine**:
   - **One-Click Preloaded Demonstration Data**: Instantly test benign baselines, lateral movement chains, brute force attacks, and full kill-chain intrusions with zero setup.
   - **Enterprise CSV Log Ingestion**: Upload custom security logs with real-time schema validation and friendly error handling.
2. **Behavioral Sequence Fingerprinting**:
   - Analyzes multi-step progression signatures (e.g. `Login → File Access → Network Activity → Privilege Request`).
   - Flags anomalies across authentication, file systems, and internal network hops.
3. **MITRE ATT&CK Stage Mapping**:
   - Classifies active stages: *Initial Access*, *Credential Access*, *Discovery*, *Lateral Movement*, *Privilege Escalation*, and *Data Access*.
4. **Probabilistic Next-Stage Prediction**:
   - Forecasts the *Possible Next Stage* (e.g., Lateral Movement $\rightarrow$ Privilege Escalation at 87% confidence).
   - Renders ranked alternative next stages (e.g., Privilege Escalation: 87%, Data Access: 61%, Credential Access: 34%).
5. **Calibrated Multi-Factor Risk Scoring**:
   - 0–100 rating reflecting event severities, failed login bursts, sensitive asset touch, and attack depth.
   - Accurately identifies **Normal Activity** with low risk (e.g., 18/100, `🟢 NO SIGNIFICANT THREAT DETECTED`).
6. **Explainable AI (XAI)**:
   - "WHY THIS ALERT?" breakdown displaying verifiable justifications drawn directly from the analyzed dataset.
7. **Interactive Attack Path Tracker**:
   - Visual kill-chain pipeline with glowing radar nodes highlighting the active frontline (🔴) and forecasted trajectory (🔮).
8. **Entity Exposure Profiling**:
   - Discrete User and Device risk rankings and interactive comparison charts.
9. **Persistent Audit History**:
   - Embedded SQLite storage saving all historical analysis sessions and alerts for instant reload.
10. **Compliance Report Generation**:
    - Generates downloadable Markdown reports, JSON data dumps, and printer-ready PDF assessments.

---

## 🛠️ 5. Technology Stack

- **Backend**: Python 3.10+, Flask, SQLite3, NumPy, Pandas, Scikit-learn, Joblib
- **Frontend**: Vanilla HTML5, Modern CSS3 (Dark SOC Aesthetic, Glassmorphism), Modern ES6+ JavaScript
- **Data Visualization**: Chart.js (CDN), FontAwesome 6, Google Fonts (Inter & JetBrains Mono)
- **Deployment**: Local lightweight web server, runnable directly in VS Code

---

## 📂 6. Project Structure

```
CyberDNA/
│
├── frontend/
│   ├── index.html           # Main SOC single-page application
│   ├── style.css            # Dark cybersecurity theme, animations & print styling
│   └── script.js            # Controller: API client, Chart.js instances, state manager
│
├── backend/
│   ├── app.py               # Flask server & REST API endpoints
│   ├── preprocessing.py     # CSV validation, missing value handling, sorting
│   ├── detection.py         # Sequential behavioral analysis & fingerprinting
│   ├── stage_classification.py # MITRE ATT&CK stage classifier
│   ├── prediction.py        # Markov transition next-stage probabilistic predictor
│   ├── risk_scoring.py      # 0-100 Multi-factor risk engine & entity ratings
│   ├── explanation.py       # Deterministic XAI evidence generator & recommendations
│   └── database.py          # SQLite schema & persistence manager
│
├── dataset/
│   ├── sample_security_logs.csv  # Standard 5-event multi-host progression (Rahul)
│   ├── lateral_movement_stage.csv # 4-event sequence leading to Lateral Movement
│   ├── normal_logs.csv           # 8 routine events yielding LOW risk (18/100)
│   ├── attack_logs.csv           # Full 9-event advanced intrusion kill-chain
│   └── credential_brute_force.csv # Multiple Kerberos failures and elevation
│
├── database/
│   └── cyberdna.db          # Auto-initialized SQLite database
│
├── model/
│   └── cyberdna_model.pkl   # Serialized Markov kill-chain transition model
│
├── reports/                 # Storage for generated assessment reports
├── requirements.txt         # Python package dependencies
├── README.md                # Comprehensive project documentation
└── .gitignore               # Ignored cache, virtualenv, and temp files
```

---

## 📋 7. CSV Log Format Specification

When uploading custom security logs, the CSV must include the following 8 header columns (case-insensitive):

| Column | Type | Example | Description |
|---|---|---|---|
| `timestamp` | Datetime | `2026-10-08 10:01:00` | Log event timestamp (`YYYY-MM-DD HH:MM:SS`) |
| `user` | String | `Rahul` | User account or identity associated with event |
| `source_ip` | String | `192.168.1.20` or `PC-01` | Origin workstation or IP address |
| `destination_ip` | String | `SERVER-01` | Destination host, server, or resource node |
| `event_type` | String | `Failed Login` | Description of operation performed |
| `severity` | Enum | `Medium` | `Low`, `Medium`, `High`, or `Critical` |
| `resource` | String | `Authentication` | Target asset, file, or service |
| `status` | Enum | `Failed` | `Success`, `Failed`, or `Requested` |

### Sample CSV Log Content:
```csv
timestamp,user,source_ip,destination_ip,event_type,severity,resource,status
2026-10-08 10:01:00,Rahul,192.168.1.20,SERVER-01,Failed Login,Medium,Authentication,Failed
2026-10-08 10:03:00,Rahul,192.168.1.20,SERVER-01,Successful Login,High,Authentication,Success
2026-10-08 10:05:00,Rahul,192.168.1.20,SERVER-01,Sensitive File Access,High,Confidential File,Success
2026-10-08 10:07:00,Rahul,192.168.1.20,SERVER-02,Network Connection,High,Internal Server,Success
2026-10-08 10:09:00,Rahul,192.168.1.20,SERVER-02,Privilege Request,Critical,Administrator Access,Requested
```

---

## 🚀 8. Step-by-Step Installation & Local Execution

Follow these straightforward steps to run CyberDNA on your local machine using VS Code:

### Step 1: Open the Project in VS Code
Open VS Code, click **File $\rightarrow$ Open Folder...**, and select the `CyberDNA` directory.

### Step 2: Open Terminal in VS Code
Press ``Ctrl + ` `` (backtick) or select **Terminal $\rightarrow$ New Terminal**.

### Step 3: (Recommended) Create & Activate Virtual Environment
```bash
# On Windows PowerShell:
python -m venv venv
.\venv\Scripts\Activate.ps1

# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Start the Backend Server
```bash
python backend/app.py
```
*You will see the startup banner:*
```text
============================================================
  CYBERDNA - AI-Powered Predictive Early-Warning System
  Running locally on http://127.0.0.1:5000
============================================================
```

### Step 6: Access the Application
Open your web browser (Chrome, Edge, Firefox) and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 9. Demonstration & Testing Scenarios

1. **Test Standard Attack Progression**:
   - Click the top button **[ USE SAMPLE DATA ]**.
   - Observe the risk score update to **Critical (100/100)** or **High**.
   - Notice the behavioral fingerprint: `Failed Login -> Successful Login -> Sensitive File Access -> Network Activity -> Privilege Request`.
   - Inspect the **Explainable AI** evidence breakdown.
2. **Test Lateral Movement Prediction**:
   - In the **Log Analysis** section, click the preset pill **Lateral Movement Stage (4 Events)**.
   - Click **[ USE SAMPLE DATA ]**.
   - The system reveals:
     - **Current Stage**: `Lateral Movement`
     - **Possible Next Stage**: `Privilege Escalation`
     - **Prediction Confidence**: `87%`
     - **Top Alternatives**: Privilege Escalation (87%), Data Access (71%), Credential Access (34%).
3. **Test Benign Baseline (Normal Activity)**:
   - Click the preset pill **Normal Activity (Benign Baseline)**.
   - Click **[ USE SAMPLE DATA ]**.
   - The banner immediately switches to:
     - `🟢 NO SIGNIFICANT THREAT DETECTED`
     - **Risk Score**: `18 / 100` (LOW)
     - **Current Stage**: `Normal Activity`
     - **Prediction**: `None (Normal Baseline)`
4. **Test Custom CSV Upload & Validation**:
   - Select or drag-and-drop any valid `.csv` log file.
   - Test an invalid CSV file to verify the graceful error message: *"Invalid security log format. Please check the required columns."*
5. **Download Security Reports**:
   - Navigate to the **Reports** section.
   - Click **[ Download Report (MD) ]** or **[ Export JSON ]** to save an audit summary.

---

## 🔮 10. Future Scope & Roadmap

- **Live Syslog Collector**: Safe, non-invasive local agent integration for real-time Windows Event Log & Linux journald streaming.
- **Deep Sequence Transformer (BERT/LSTM)**: Neural sequence modeling on multi-million enterprise telemetry corpora.
- **Automated Defensive Playbooks**: Integration with SOAR APIs for automated analyst ticket generation (e.g., Jira, ServiceNow).
- **Multi-Tenant SOC**: Role-based access control (RBAC) and team collaboration dashboards.

---

## 👥 11. Team Information

- **Project**: CyberDNA AI Predictive Early-Warning Platform
- **Academic Program**: Bachelor of Engineering / Technology (Computer Science & Cybersecurity)
- **Institution**: College Engineering Project / Hackathon Submission
- **Team Members**:
  - *Lead Developer & ML Engineer* — [Student Name]
  - *Cybersecurity Analyst & Telemetry Engineer* — [Student Name]
  - *Frontend & SOC Interface Designer* — [Student Name]
- **Mentor / Guide**: [Faculty Name]

---

*CyberDNA is released under the MIT Open Source License.*
