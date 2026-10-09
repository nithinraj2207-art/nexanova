/**
 * CYBERDNA - Frontend Controller & SOC Dashboard Engine
 * Handles navigation, state management, API requests, Chart.js graphs,
 * attack path visualizers, search/filtering, and report exports.
 */

// Global State
const state = {
  currentAnalysis: null,
  currentTarget: "",
  activeSeverityFilter: "all",
  tableSearchQuery: "",
  tableSeverityFilter: "all",
  tableStatusFilter: "all",
  tableStageFilter: "all",
  tableSortColumn: "id",
  tableSortAsc: true,
  charts: {},
  activeRemediationServer: "nginx",
  remediationPlaybook: null
};

// Defined MITRE ATT&CK Stages in sequential order
const MITRE_STAGES = [
  "Initial Access",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Privilege Escalation",
  "Data Access"
];

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initTargetScannerEvents();
  initFilterEvents();
  initModalEvents();
  initExportEvents();
  initRemediationEvents();
  loadDashboardData();
  loadHistoryList();
});

// ============================================================================
// NAVIGATION
// ============================================================================
function initNavigation() {
  const navButtons = document.querySelectorAll(".nav-item");
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      navigateToSection(targetId);
    });
  });

  // Cross-section navigation links
  const btnPredFromOverview = document.getElementById("btn-goto-predictions-from-overview");
  if (btnPredFromOverview) {
    btnPredFromOverview.addEventListener("click", () => navigateToSection("section-predictions"));
  }

  const btnAlertsFromOverview = document.getElementById("btn-goto-alerts-from-overview");
  if (btnAlertsFromOverview) {
    btnAlertsFromOverview.addEventListener("click", () => navigateToSection("section-alerts"));
  }

  const btnRefreshOverview = document.getElementById("btn-refresh-overview");
  if (btnRefreshOverview) {
    btnRefreshOverview.addEventListener("click", () => {
      loadDashboardData();
      showToast("Dashboard telemetry refreshed");
    });
  }

  const btnRefreshHistory = document.getElementById("btn-refresh-history");
  if (btnRefreshHistory) {
    btnRefreshHistory.addEventListener("click", () => {
      loadHistoryList();
      showToast("Analysis history refreshed");
    });
  }
}

function navigateToSection(sectionId) {
  // Update sidebar active state
  document.querySelectorAll(".nav-item").forEach(item => {
    if (item.getAttribute("data-target") === sectionId) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });

  // Switch content sections
  document.querySelectorAll(".content-section").forEach(sec => {
    if (sec.id === sectionId) {
      sec.classList.add("active");
    } else {
      sec.classList.remove("active");
    }
  });

  // If entering section with charts, resize/update them
  if (["section-overview", "section-patterns", "section-entities"].includes(sectionId)) {
    setTimeout(resizeAllCharts, 150);
  }
}

// ============================================================================
// TARGET VULNERABILITY SCANNER CONTROLS
// ============================================================================
function initTargetScannerEvents() {
  const btnStartScan = document.getElementById("btn-start-scan");
  const targetInput = document.getElementById("target-input");
  const quickTags = document.querySelectorAll(".quick-target-tag");

  if (btnStartScan) {
    btnStartScan.addEventListener("click", () => {
      const val = targetInput ? targetInput.value : "";
      startScan(val);
    });
  }

  if (targetInput) {
    targetInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        startScan(targetInput.value);
      }
    });

    targetInput.addEventListener("input", () => {
      hideTargetValidation();
    });
  }

  quickTags.forEach(tag => {
    tag.addEventListener("click", () => {
      const targetVal = tag.getAttribute("data-target");
      if (targetInput) targetInput.value = targetVal;
      startScan(targetVal);
    });
  });
}

/**
 * Initiates vulnerability and security posture scan for the specified target.
 * Validates input, updates UI loading state, and calls backend /api/scan.
 */
async function startScan(target) {
  const rawTarget = (target || "").trim();

  // 1. Validation: check if empty
  if (!rawTarget) {
    showTargetValidation("Target input cannot be empty. Please enter a domain or IP address (e.g., example.com).");
    return;
  }

  // 2. Validation: check domain or IP address format
  const sanitized = rawTarget.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
  const domainOrIpPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^(\d{1,3}\.){3}\d{1,3}$|^localhost$/i;

  if (!domainOrIpPattern.test(sanitized)) {
    showTargetValidation(`Please enter a valid domain name or IP address (e.g., example.com or 192.168.1.1). Received: '${rawTarget}'`);
    return;
  }

  hideTargetValidation();

  // Store target in application state
  state.currentTarget = sanitized;

  // 3. UI Loading State: "Scanning..."
  showScanningState(true, sanitized);

  try {
    // 4. Send target to backend scanner API
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: sanitized })
    });

    const result = await response.json();

    if (result.success && result.data) {
      // 5. Display actual dynamic results
      updateApplicationState(result.data);
      showScanningState(false);
      showToast(`Scan complete for target: ${sanitized}`);
      loadHistoryList();
    } else {
      showScanningState(false);
      showTargetValidation(result.error || "Failed to scan target. Please check target reachability and network connection.");
    }
  } catch (err) {
    showScanningState(false);
    showTargetValidation("Connection error with backend server. Please ensure the CyberDNA backend is running.");
  }
}

function showTargetValidation(message) {
  const msgBox = document.getElementById("target-validation-msg");
  if (msgBox) {
    msgBox.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>${escapeHtml(message)}</span>`;
    msgBox.classList.remove("hidden");
  }
}

function hideTargetValidation() {
  const msgBox = document.getElementById("target-validation-msg");
  if (msgBox) {
    msgBox.classList.add("hidden");
    msgBox.innerHTML = "";
  }
}

function showScanningState(isScanning, targetName = "") {
  const scanningState = document.getElementById("target-scanning-state");
  const initialState = document.getElementById("scan-initial-state");
  const resultsContainer = document.getElementById("scan-results-container");
  const btnScan = document.getElementById("btn-start-scan");
  const statusTag = document.getElementById("scanner-status-tag");
  const scanningTitle = document.getElementById("scanning-status-title");

  if (isScanning) {
    if (scanningState) scanningState.classList.remove("hidden");
    if (initialState) initialState.classList.add("hidden");
    if (resultsContainer) resultsContainer.classList.add("hidden");
    if (btnScan) {
      btnScan.disabled = true;
      btnScan.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning...`;
    }
    if (statusTag) statusTag.innerText = `Scanning: ${targetName}...`;
    if (scanningTitle) scanningTitle.innerText = `Scanning: ${targetName}...`;
  } else {
    if (scanningState) scanningState.classList.add("hidden");
    if (btnScan) {
      btnScan.disabled = false;
      btnScan.innerHTML = `<i class="fa-solid fa-play"></i> Start Scan`;
    }
    if (statusTag) statusTag.innerText = state.currentTarget ? `Audited: ${state.currentTarget}` : "Ready to Scan";
  }
}

function showEmptyScanState() {
  const initialState = document.getElementById("scan-initial-state");
  const resultsContainer = document.getElementById("scan-results-container");
  const scanningState = document.getElementById("target-scanning-state");
  const headerChip = document.getElementById("header-analysis-id");
  const statusTag = document.getElementById("scanner-status-tag");

  if (initialState) initialState.classList.remove("hidden");
  if (resultsContainer) resultsContainer.classList.add("hidden");
  if (scanningState) scanningState.classList.add("hidden");
  if (headerChip) headerChip.innerText = "TARGET: NONE";
  if (statusTag) statusTag.innerText = "Awaiting Target";
}



async function loadDashboardData() {
  try {
    const res = await fetch("/api/dashboard");
    const json = await res.json();
    if (json.success && json.has_data && json.data) {
      updateApplicationState(json.data);
    } else {
      showEmptyScanState();
    }
  } catch (err) {
    console.error("Failed to load initial dashboard telemetry:", err);
    showEmptyScanState();
  }
}

async function loadHistoryList() {
  try {
    const res = await fetch("/api/history");
    const json = await res.json();
    if (json.success && json.history) {
      renderHistoryTable(json.history);
      const badge = document.getElementById("history-count-badge");
      if (badge) badge.innerText = `${json.history.length} Sessions`;
    }
  } catch (err) {
    console.error("Failed to load history list:", err);
  }
}

// ============================================================================
// STATE & UI RENDER DISPATCHER
// ============================================================================
function updateApplicationState(data) {
  state.currentAnalysis = data;

  // Reveal results container and hide initial / loading states
  const resultsContainer = document.getElementById("scan-results-container");
  const initialState = document.getElementById("scan-initial-state");
  const scanningState = document.getElementById("target-scanning-state");

  if (resultsContainer) resultsContainer.classList.remove("hidden");
  if (initialState) initialState.classList.add("hidden");
  if (scanningState) scanningState.classList.add("hidden");

  // 1. Header session chip & Scanner Target Status
  const headerChip = document.getElementById("header-analysis-id");
  const targetInput = document.getElementById("target-input");
  const statusTag = document.getElementById("scanner-status-tag");

  if (data.target) {
    state.currentTarget = data.target;
    if (headerChip) headerChip.innerText = `TARGET: ${data.target.toUpperCase()}`;
    if (targetInput) targetInput.value = data.target;
    if (statusTag) statusTag.innerText = `Audited: ${data.target}`;
  } else {
    if (headerChip) headerChip.innerText = `ID: ${data.analysis_id || 'READY'}`;
    if (statusTag) statusTag.innerText = `Source: ${data.source_name}`;
  }

  // 2. Render Overview Section & KPIs
  renderOverview(data);

  // 3. Render Post-Analysis Summary Ribbon & Table
  renderAnalysisSummary(data);
  renderSecurityEventsTable(data.events || []);

  // 4. Render Attack Patterns & Fingerprint
  renderAttackPatterns(data);

  // 5. Render Predictions & Kill-chain visualizer
  renderPredictions(data);

  // 6. Render Smart Alerts
  renderAlerts(data.alerts || []);

  // 7. Render Users & Devices
  renderEntities(data);

  // 8. Render Reports Document
  renderReportView(data);

  // 9. Rebuild Charts
  renderAllCharts(data);
}

// ============================================================================
// SECTION RENDERING LOGIC
// ============================================================================

// --- 1. OVERVIEW ---
function renderOverview(data) {
  const banner = document.getElementById("overview-state-banner");
  const bannerTitle = document.getElementById("banner-title");
  const bannerDesc = document.getElementById("banner-desc");
  const bannerRiskPill = document.getElementById("banner-risk-pill");
  const bannerStage = document.getElementById("banner-stage");
  const bannerPredicted = document.getElementById("banner-predicted");
  const bannerIcon = document.getElementById("banner-icon-container");

  const isLow = (data.risk_level === "LOW");

  if (isLow) {
    banner.className = "threat-status-banner low-risk-banner";
    bannerTitle.innerText = data.target ? `🟢 NO SIGNIFICANT THREAT DETECTED: ${data.target}` : "🟢 NO SIGNIFICANT THREAT DETECTED";
    bannerDesc.innerText = data.target ? `Target ${data.target} (Host IP: ${data.resolved_ip || 'Resolved'}, User IP: ${data.user_ip || 'Client'}) perimeter posture is healthy. All audited defensive headers and TLS configurations conform to best practices.` : "Security activity appears normal based on analyzed events. No suspicious sequence detected.";
    bannerRiskPill.className = "badge badge-low";
    bannerRiskPill.innerText = `RISK: ${data.risk_score}/100 (LOW)`;
    if (bannerIcon) bannerIcon.innerHTML = `<i class="fa-solid fa-shield-check"></i>`;
  } else {
    banner.className = "threat-status-banner high-risk-banner";
    bannerTitle.innerText = data.target ? `⚠️ PERIMETER VULNERABILITIES DETECTED: ${data.target}` : `⚠️ SUSPICIOUS ACTIVITY DETECTED: ${data.current_stage}`;
    bannerDesc.innerText = data.target ? `Target ${data.target} (Host IP: ${data.resolved_ip || 'Resolved'}, User IP: ${data.user_ip || 'Client'}) exposed ${data.suspicious_events || 0} perimeter vulnerability finding(s). Risk score: ${data.risk_score}/100 (${data.risk_level}). Current stage: ${data.current_stage}.` : `Multi-stage behavioral anomaly detected. Current stage: ${data.current_stage}. Predicted next stage: ${data.predicted_next_stage}.`;
    bannerRiskPill.className = `badge badge-${data.risk_level.toLowerCase()}`;
    bannerRiskPill.innerText = `RISK: ${data.risk_score}/100 (${data.risk_level})`;
    if (bannerIcon) bannerIcon.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i>`;
  }

  if (data.active_stages && data.active_stages.length > 0) {
    bannerStage.innerText = data.active_stages.map(s => s.stage).join(" & ");
  } else {
    bannerStage.innerText = data.current_stage || "Normal Activity";
  }
  bannerPredicted.innerText = data.predicted_next_stage || "None";

  // KPIs
  document.getElementById("kpi-total-events").innerText = data.total_events || 0;
  document.getElementById("kpi-source-subtext").innerText = data.target ? `User IP: ${data.user_ip || '127.0.0.1'}` : `Source: ${data.source_name || 'Telemetry'}`;
  document.getElementById("kpi-threats-count").innerText = data.suspicious_events || 0;
  const kpiThreatSub = document.getElementById("kpi-threats-subtext");
  if (kpiThreatSub) kpiThreatSub.innerText = data.target ? "Perimeter findings" : "Suspicious sequences";
  document.getElementById("kpi-critical-alerts").innerText = (data.alerts || []).filter(a => ["CRITICAL", "Critical"].includes(a.severity)).length;
  
  const highRiskUsers = (data.user_risks || []).filter(u => u.risk_score >= 61).length;
  document.getElementById("kpi-high-risk-users").innerText = highRiskUsers;
  const allUserIps = (data.user_risks || []).map(u => u.name || u.user_ip).filter(Boolean);
  document.getElementById("kpi-primary-user").innerText = allUserIps.length > 1 ? `User IPs: ${allUserIps.join(', ')}` : (data.target ? `User IP: ${data.user_ip || 'Client'}` : `Principal: ${data.user_risks && data.user_risks[0] ? data.user_risks[0].name : 'None'}`);

  const highRiskDevs = (data.device_risks || []).filter(d => d.risk_score >= 61).length;
  document.getElementById("kpi-high-risk-devices").innerText = highRiskDevs;
  document.getElementById("kpi-primary-device").innerText = data.target ? `Target IP: ${data.resolved_ip || 'Resolved'}` : `Target: ${data.device_risks && data.device_risks[0] ? data.device_risks[0].device : 'None'}`;

  const kpiRiskScore = document.getElementById("kpi-risk-score");
  const kpiRiskBadge = document.getElementById("kpi-risk-badge");
  kpiRiskScore.innerText = data.risk_score || 0;
  kpiRiskBadge.innerText = data.risk_level || "LOW";
  kpiRiskBadge.className = `badge badge-${(data.risk_level || 'low').toLowerCase()}`;

  // Overview Kill-chain tracker preview
  renderKillchainTracker("overview-killchain-tracker", data.current_stage, data.predicted_next_stage, data.active_stages);

  // Overview recent alerts table
  const tbody = document.getElementById("overview-alerts-tbody");
  tbody.innerHTML = "";
  const recentAlerts = (data.alerts || []).slice(0, 5);

  if (recentAlerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted text-center" style="padding: 24px;">No security alerts generated for this session. System operating within normal baseline.</td></tr>`;
  } else {
    recentAlerts.forEach(al => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${al.timestamp}</td>
        <td><strong>${escapeHtml(al.user)}</strong></td>
        <td><code>${escapeHtml(al.source_ip)}</code></td>
        <td><span class="badge badge-${al.severity.toLowerCase()}">${al.severity}</span></td>
        <td>${escapeHtml(al.current_stage)}</td>
        <td>${escapeHtml(al.predicted_next_stage)}</td>
        <td><strong>${al.risk_score}/100</strong></td>
        <td><button class="btn btn-sm btn-outline" onclick="openAlertModal('${al.alert_id}')">Details</button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Update sidebar alert badge
  const sidebarBadge = document.getElementById("sidebar-alert-badge");
  if (sidebarBadge) {
    const alertCount = (data.alerts || []).length;
    sidebarBadge.innerText = alertCount;
    sidebarBadge.style.display = alertCount > 0 ? "inline-flex" : "none";
  }
}

// --- 2. LOG ANALYSIS RESULTS & TABLE ---
function renderAnalysisSummary(data) {
  document.getElementById("res-events-count").innerText = data.total_events || 0;
  document.getElementById("res-suspicious-count").innerText = data.suspicious_events || 0;
  document.getElementById("res-users-count").innerText = (data.user_risks || []).length;
  document.getElementById("res-devices-count").innerText = (data.device_risks || []).length;
  document.getElementById("res-risk-score").innerText = `${data.risk_score || 0} / 100`;

  const levelBadge = document.getElementById("results-risk-level-badge");
  levelBadge.innerText = `LEVEL: ${data.risk_level || 'UNKNOWN'}`;
  levelBadge.className = `badge badge-${(data.risk_level || 'low').toLowerCase()}`;
}

function renderSecurityEventsTable(events) {
  const tbody = document.getElementById("security-events-tbody");
  tbody.innerHTML = "";

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted" style="padding: 24px;">No live security events captured yet. Enter a target domain or IP on the Overview dashboard and click 'Start Scan' to generate telemetry.</td></tr>`;
    return;
  }

  // Filter events according to toolbar state
  let filtered = events.filter(e => {
    // Search filter
    if (state.tableSearchQuery) {
      const q = state.tableSearchQuery.toLowerCase();
      const match = (
        (e.user && e.user.toLowerCase().includes(q)) ||
        (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
        (e.destination_ip && e.destination_ip.toLowerCase().includes(q)) ||
        (e.event_type && e.event_type.toLowerCase().includes(q)) ||
        (e.resource && e.resource.toLowerCase().includes(q))
      );
      if (!match) return false;
    }

    // Severity filter
    if (state.tableSeverityFilter !== "all" && e.severity !== state.tableSeverityFilter) {
      return false;
    }

    // Status filter
    if (state.tableStatusFilter !== "all" && e.status !== state.tableStatusFilter) {
      return false;
    }

    // Attack stage filter
    if (state.tableStageFilter !== "all" && e.attack_stage !== state.tableStageFilter) {
      return false;
    }

    return true;
  });

  // Sort events
  filtered.sort((a, b) => {
    let valA = a[state.tableSortColumn];
    let valB = b[state.tableSortColumn];
    if (typeof valA === "string") valA = valA.toLowerCase();
    if (typeof valB === "string") valB = valB.toLowerCase();
    if (valA < valB) return state.tableSortAsc ? -1 : 1;
    if (valA > valB) return state.tableSortAsc ? 1 : -1;
    return 0;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted" style="padding: 24px;">No events matching current filters. Click 'Clear Filters' to reset.</td></tr>`;
    return;
  }

  filtered.forEach(ev => {
    const tr = document.createElement("tr");
    if (ev.is_suspicious) {
      tr.className = "row-suspicious";
    }

    tr.innerHTML = `
      <td>${ev.id}</td>
      <td style="font-family: var(--font-mono); font-size: 11.5px;">${ev.timestamp}</td>
      <td><strong>${escapeHtml(ev.user)}</strong></td>
      <td><code>${escapeHtml(ev.source_ip)}</code></td>
      <td><code>${escapeHtml(ev.destination_ip)}</code></td>
      <td>${escapeHtml(ev.event_type)}</td>
      <td><span class="badge badge-${ev.severity.toLowerCase()}">${ev.severity}</span></td>
      <td>${escapeHtml(ev.resource)}</td>
      <td><span class="badge badge-outline">${escapeHtml(ev.status)}</span></td>
      <td><span class="step-tag">${escapeHtml(ev.attack_stage || 'Routine')}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// --- 3. ATTACK PATTERNS & FINGERPRINT ---
function renderAttackPatterns(data) {
  const container = document.getElementById("fingerprint-nodes-container");
  container.innerHTML = "";

  const fingerprint = data.fingerprint || [];
  if (fingerprint.length === 0) {
    container.innerHTML = `<span class="text-muted">No anomalous behavioral sequence identified in event stream.</span>`;
  } else {
    fingerprint.forEach((step, idx) => {
      const chip = document.createElement("div");
      chip.className = "fp-chip";
      chip.innerHTML = `<i class="fa-solid fa-code-fork"></i> ${escapeHtml(step)}`;
      container.appendChild(chip);

      if (idx < fingerprint.length - 1) {
        const arrow = document.createElement("i");
        arrow.className = "fa-solid fa-arrow-right-long fp-arrow";
        container.appendChild(arrow);
      }
    });
  }

  // Recognized pattern cards
  const sigGrid = document.getElementById("pattern-signatures-grid");
  sigGrid.innerHTML = "";
  const patterns = data.detected_patterns || [];

  if (patterns.length === 0) {
    sigGrid.innerHTML = `<div class="pattern-sig-card" style="border-left-color: var(--sev-low);"><div class="pattern-sig-title">Baseline Operations</div><div class="pattern-sig-desc">Routine activity patterns match benign enterprise profile.</div></div>`;
  } else {
    patterns.forEach(p => {
      const card = document.createElement("div");
      card.className = "pattern-sig-card";
      card.innerHTML = `
        <div class="pattern-sig-title"><i class="fa-solid fa-triangle-exclamation text-amber"></i> ${escapeHtml(p)}</div>
        <div class="pattern-sig-desc">Sequential signature confirmed by MITRE behavioral correlation matrix.</div>
      `;
      sigGrid.appendChild(card);
    });
  }

  // Behavioral indicators list
  const indList = document.getElementById("behavioral-indicators-list");
  indList.innerHTML = "";

  const indicators = [
    { label: "Authentication Failure Burst", value: data.suspicious_events > 0 ? "Observed" : "None Detected", severity: data.suspicious_events > 0 ? "high" : "low" },
    { label: "Post-Failure Compromise", value: (data.fingerprint || []).includes("Successful Login") && (data.fingerprint || []).includes("Failed Login") ? "Detected" : "Clean", severity: (data.fingerprint || []).includes("Successful Login") ? "critical" : "low" },
    { label: "Internal Host Pivoting", value: (data.current_stage === "Lateral Movement" || (data.fingerprint || []).includes("Network Activity")) ? "Active" : "Normal", severity: "high" },
    { label: "Privilege Elevation Request", value: (data.fingerprint || []).includes("Privilege Request") ? "Identified" : "None", severity: (data.fingerprint || []).includes("Privilege Request") ? "critical" : "low" },
    { label: "Sensitive Asset Access", value: (data.fingerprint || []).includes("Sensitive File Access") ? "Logged" : "Normal", severity: (data.fingerprint || []).includes("Sensitive File Access") ? "high" : "low" }
  ];

  indicators.forEach(ind => {
    const row = document.createElement("div");
    row.className = "indicator-row";
    row.innerHTML = `
      <span class="ind-name">${ind.label}</span>
      <span class="ind-badge badge badge-${ind.severity}">${ind.value}</span>
    `;
    indList.appendChild(row);
  });
}

// --- 4. PREDICTIONS & EXPLAINABLE AI ---
function renderPredictions(data) {
  // Attack path flow
  renderKillchainTracker("attack-path-flow", data.current_stage, data.predicted_next_stage, data.active_stages);

  // Predictions Card
  const currStage = document.getElementById("pred-current-stage");
  const nextStage = document.getElementById("pred-next-stage");
  const confVal = document.getElementById("pred-confidence-val");
  const confBar = document.getElementById("pred-confidence-bar");

  if (data.active_stages && data.active_stages.length > 0) {
    currStage.innerText = data.active_stages.map(s => `${s.stage} (${s.user_ip})`).join(" | ");
  } else {
    currStage.innerText = data.current_stage || "Normal Activity";
  }
  nextStage.innerText = data.predicted_next_stage || "None";
  confVal.innerText = `${data.confidence || 0}%`;
  confBar.style.width = `${data.confidence || 0}%`;

  // Alternatives List
  const altList = document.getElementById("pred-alternatives-list");
  altList.innerHTML = "";
  const alts = data.top_alternatives || [];

  if (alts.length === 0) {
    altList.innerHTML = `<span class="text-muted text-sm">No alternative trajectories required. Baseline stable.</span>`;
  } else {
    alts.forEach(a => {
      const row = document.createElement("div");
      row.className = "alt-row";
      row.innerHTML = `
        <span class="alt-stage-name">${escapeHtml(a.stage)}</span>
        <span class="alt-prob">${a.confidence}%</span>
      `;
      altList.appendChild(row);
    });
  }

  // Explainable AI: Group findings by origin IP so user sees which IP triggered which vulnerability/alert
  const whyList = document.getElementById("why-alert-list");
  whyList.innerHTML = "";

  const explanationsByIp = data.explanation_by_ip || {};
  // If not pre-grouped, group vulnerabilities by source_ip or user_ip
  if (Object.keys(explanationsByIp).length === 0 && (data.vulnerabilities || []).length > 0) {
    data.vulnerabilities.forEach(v => {
      const ip = v.source_ip || v.user_ip || data.user_ip || "Workstation";
      if (!explanationsByIp[ip]) explanationsByIp[ip] = [];
      explanationsByIp[ip].push(`${v.title} — ${v.description}`);
    });
  }

  const ipKeys = Object.keys(explanationsByIp);
  if (ipKeys.length > 0) {
    ipKeys.forEach(ip => {
      const ipGroup = document.createElement("div");
      ipGroup.className = "why-ip-group";

      const matchedStage = (data.active_stages || []).find(s => s.user_ip === ip);
      const stageLabel = matchedStage ? `${matchedStage.stage} (${matchedStage.severity})` : "Active Vector";
      const stageClass = matchedStage ? `badge-${matchedStage.severity.toLowerCase()}` : "badge-cyan";

      const findings = explanationsByIp[ip] || [];
      ipGroup.innerHTML = `
        <div class="why-ip-header">
          <div class="why-ip-info">
            <i class="fa-solid fa-network-wired highlight-cyan"></i>
            <span class="why-ip-title">Origin IP: <strong>${escapeHtml(ip)}</strong></span>
          </div>
          <span class="badge ${stageClass}">${stageLabel}</span>
        </div>
        <ul class="why-ip-findings-list">
          ${findings.map(f => `<li><i class="fa-solid fa-triangle-exclamation text-amber mr-6"></i>${escapeHtml(f)}</li>`).join("")}
        </ul>
      `;
      whyList.appendChild(ipGroup);
    });
  } else {
    const explanations = data.explanation || [];
    explanations.forEach(exp => {
      const li = document.createElement("li");
      li.innerText = exp;
      whyList.appendChild(li);
    });
  }

  // Recommended defensive actions
  const actionsList = document.getElementById("defensive-actions-list");
  actionsList.innerHTML = "";
  const actions = data.recommendations || [];

  actions.forEach(act => {
    const li = document.createElement("li");
    li.innerText = act;
    actionsList.appendChild(li);
  });

  // 1-Click Defensive Hardening & Honeypot Playbook
  state.remediationPlaybook = data.remediation_playbook || null;
  renderRemediationPlaybook(state.remediationPlaybook);
}

function renderRemediationPlaybook(playbook) {
  const codeContent = document.getElementById("remediation-code-content");
  const fileTitle = document.getElementById("remediation-file-title");
  const fileName = document.getElementById("remediation-file-name");
  const fileHint = document.getElementById("remediation-file-hint");
  const canaryToken = document.getElementById("remediation-canary-token");
  const canaryBadge = document.getElementById("remediation-canary-badge");

  if (!playbook || Object.keys(playbook).length === 0) {
    if (codeContent) codeContent.innerText = "# Awaiting scan results to generate tailored defensive playbook...";
    if (fileTitle) fileTitle.innerText = "Server Hardening Configuration:";
    if (fileName) fileName.innerText = "hardening.conf";
    if (fileHint) fileHint.innerText = "Execute a scan to generate ready-to-deploy configurations";
    if (canaryToken) canaryToken.innerText = "canary-trap-standby";
    if (canaryBadge) canaryBadge.innerHTML = `<i class="fa-solid fa-shield"></i> Decoy Engine Standby`;
    return;
  }

  const server = state.activeRemediationServer || "nginx";
  const item = playbook[server] || playbook["nginx"];

  if (item) {
    if (codeContent) codeContent.innerText = item.snippet;
    if (fileTitle) fileTitle.innerText = item.title + ":";
    if (fileName) fileName.innerText = item.filename;
    if (fileHint) fileHint.innerText = item.file_hint;
  }

  const decoyId = playbook.decoy_id || "canary-trap-active";
  if (canaryToken) canaryToken.innerText = decoyId;
  if (canaryBadge) canaryBadge.innerHTML = `<i class="fa-solid fa-spider"></i> Decoy Trap Active (${decoyId})`;
}

// Kill-chain progression renderer helper supporting multiple concurrent active stages
function renderKillchainTracker(containerId, currentStage, predictedNextStage, activeStages = []) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";

  const stageIcons = {
    "Initial Access": "fa-door-open",
    "Credential Access": "fa-key",
    "Discovery": "fa-binoculars",
    "Lateral Movement": "fa-network-wired",
    "Privilege Escalation": "fa-user-shield",
    "Data Access": "fa-database"
  };

  const currentIndex = MITRE_STAGES.indexOf(currentStage);

  MITRE_STAGES.forEach((stage, idx) => {
    const step = document.createElement("div");
    let statusClass = "";
    let tagText = "Pending";

    if (stage === currentStage) {
      statusClass = "current";
      tagText = "🔴 CURRENT";
    } else if (stage === predictedNextStage) {
      statusClass = "predicted";
      tagText = "🔮 PREDICTED";
    } else if (currentIndex !== -1 && idx < currentIndex) {
      statusClass = "passed";
      tagText = "Passed";
    }

    step.className = `stage-step ${statusClass}`;
    step.setAttribute("data-stage", stage);
    step.innerHTML = `
      <div class="step-node" title="${stage}">
        <i class="fa-solid ${stageIcons[stage] || 'fa-shield'}"></i>
      </div>
      <span class="step-label">${stage}</span>
      <span class="step-tag badge">${tagText}</span>
    `;
    container.appendChild(step);
  });

  // Render multiple active attack stages across the MITRE ATT&CK path
  if (activeStages && activeStages.length > 0) {
    const stageMap = {};
    activeStages.forEach(attack => {
      if (!stageMap[attack.stage]) stageMap[attack.stage] = [];
      if (!stageMap[attack.stage].includes(attack.user_ip)) {
        stageMap[attack.stage].push(attack.user_ip);
      }
    });

    Object.entries(stageMap).forEach(([stName, ips]) => {
      const stageNodes = container.querySelectorAll(`[data-stage="${stName}"]`);
      stageNodes.forEach(node => {
        node.classList.add('current-active');
        const badge = node.querySelector('.badge') || node.querySelector('.step-tag');
        if (badge) {
          badge.innerText = `CURRENT (${ips.join(', ')})`;
        }
      });
    });
  }
}

// --- 5. SMART ALERTS ---
function renderAlerts(alerts) {
  const container = document.getElementById("alerts-cards-container");
  container.innerHTML = "";

  const filtered = alerts.filter(a => {
    if (state.activeSeverityFilter === "all") return true;
    return a.severity.toLowerCase() === state.activeSeverityFilter.toLowerCase();
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="card p-24 text-center">
        <i class="fa-solid fa-shield-check icon-green" style="font-size: 36px; margin-bottom: 12px; color: var(--sev-low);"></i>
        <h3>Zero Alerts</h3>
        <p class="text-muted text-sm">No security alerts matching severity '${state.activeSeverityFilter}'.</p>
      </div>
    `;
    return;
  }

  filtered.forEach(al => {
    const card = document.createElement("div");
    card.className = `alert-feed-card ${al.severity.toLowerCase()}`;
    card.innerHTML = `
      <div class="alert-feed-icon">
        <i class="fa-solid fa-triangle-exclamation"></i>
      </div>
      <div class="alert-feed-body">
        <div class="alert-feed-top">
          <span class="alert-feed-title">${escapeHtml(al.title)}</span>
          <span class="alert-feed-time">${al.timestamp}</span>
        </div>
        <p class="alert-feed-desc">${escapeHtml(al.description)}</p>
        <div class="alert-feed-tags">
          <span class="tag-item">User: <strong>${escapeHtml(al.user)}</strong></span>
          <span class="tag-item">Source IP: <strong>${escapeHtml(al.source_ip)}</strong></span>
          <span class="tag-item">Current Stage: <strong>${escapeHtml(al.current_stage)}</strong></span>
          <span class="tag-item">Predicted Next: <strong>${escapeHtml(al.predicted_next_stage)}</strong></span>
          <span class="tag-item">Risk: <strong>${al.risk_score}/100</strong></span>
          <button class="btn btn-sm btn-outline" style="margin-left: auto;" onclick="openAlertModal('${al.alert_id}')">
            View Details
          </button>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

// --- 6. USERS & DEVICES ---
function renderEntities(data) {
  const usersTbody = document.getElementById("users-risk-tbody");
  usersTbody.innerHTML = "";
  const users = data.user_risks || [];

  if (users.length === 0) {
    usersTbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No user identities identified.</td></tr>`;
  } else {
    users.forEach(u => {
      const tr = document.createElement("tr");
      const stageName = u.active_stage || (data.active_stages && data.active_stages[0] ? data.active_stages[0].stage : "Discovery");
      const threatLvl = u.threat_level || u.risk_level || "LOW";
      tr.innerHTML = `
        <td><strong><i class="fa-solid fa-laptop-code highlight-cyan mr-6"></i>${escapeHtml(u.name || u.user_ip)}</strong></td>
        <td><span class="badge badge-stage">${escapeHtml(stageName)}</span></td>
        <td><strong>${u.risk_score} / 100</strong></td>
        <td><span class="badge badge-${threatLvl.toLowerCase()}">${threatLvl}</span></td>
      `;
      usersTbody.appendChild(tr);
    });
  }

  const devTbody = document.getElementById("devices-risk-tbody");
  devTbody.innerHTML = "";
  const devices = data.device_risks || [];

  if (devices.length === 0) {
    devTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No device hosts identified.</td></tr>`;
  } else {
    devices.forEach(d => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHtml(d.device)}</code></td>
        <td><strong>${d.risk_score} / 100</strong></td>
        <td><span class="badge badge-${d.risk_level.toLowerCase()}">${d.risk_level}</span></td>
        <td>${d.events_count}</td>
        <td><span class="text-amber">${d.suspicious_count}</span></td>
      `;
      devTbody.appendChild(tr);
    });
  }
}

// --- 7. REPORTS ---
function renderReportView(data) {
  document.getElementById("rep-analysis-id").innerText = data.analysis_id || "CDNA-UNKNOWN";
  document.getElementById("rep-timestamp").innerText = data.timestamp || new Date().toLocaleString();
  document.getElementById("rep-source-name").innerText = data.source_name || "Telemetry Ingestion";
  document.getElementById("rep-risk-score").innerText = `${data.risk_score || 0} / 100 (${data.risk_level || 'LOW'})`;
  document.getElementById("rep-total-events").innerText = data.total_events || 0;
  document.getElementById("rep-suspicious-count").innerText = data.suspicious_events || 0;
  document.getElementById("rep-current-stage").innerText = data.current_stage || "Normal Activity";
  document.getElementById("rep-predicted-stage").innerText = data.predicted_next_stage || "None";
  document.getElementById("rep-confidence").innerText = `${data.confidence || 0}%`;

  const fpBox = document.getElementById("rep-fingerprint-box");
  fpBox.innerText = data.fingerprint_str || (data.fingerprint || []).join(" -> ") || "Normal System Operations";

  // Evidence list
  const evList = document.getElementById("rep-evidence-list");
  evList.innerHTML = "";
  (data.explanation || []).forEach(e => {
    const li = document.createElement("li");
    li.innerText = e;
    evList.appendChild(li);
  });

  // Entities breakdown lists
  const usersList = document.getElementById("rep-users-list");
  usersList.innerHTML = "";
  (data.user_risks || []).slice(0, 6).forEach(u => {
    const li = document.createElement("li");
    const stageName = u.active_stage || (data.active_stages && data.active_stages[0] ? data.active_stages[0].stage : "Discovery");
    const threatLvl = u.threat_level || u.risk_level || "LOW";
    li.innerHTML = `<span><strong>${escapeHtml(u.name || u.user_ip)}</strong> (${stageName})</span> <strong>${u.risk_score}/100 (${threatLvl})</strong>`;
    usersList.appendChild(li);
  });

  const devsList = document.getElementById("rep-devices-list");
  devsList.innerHTML = "";
  (data.device_risks || []).slice(0, 4).forEach(d => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${escapeHtml(d.device)}</span> <strong>${d.risk_score}/100 (${d.risk_level})</strong>`;
    devsList.appendChild(li);
  });

  // Defensive actions
  const actList = document.getElementById("rep-actions-list");
  actList.innerHTML = "";
  (data.recommendations || []).forEach(r => {
    const li = document.createElement("li");
    li.innerText = r;
    actList.appendChild(li);
  });

  // Defensive Remediation & Playbook in Report
  const repCanaryToken = document.getElementById("rep-canary-token");
  const repSnippet = document.getElementById("rep-remediation-snippet");
  if (data.remediation_playbook && data.remediation_playbook.nginx) {
    if (repCanaryToken) repCanaryToken.innerText = data.remediation_playbook.decoy_id || "canary-trap-active";
    if (repSnippet) repSnippet.innerText = data.remediation_playbook.nginx.snippet;
  } else {
    if (repCanaryToken) repCanaryToken.innerText = "canary-trap-standby";
    if (repSnippet) repSnippet.innerText = "# No playbook generated. Target requires active audit.";
  }
}

// --- 8. ANALYSIS HISTORY TABLE ---
function renderHistoryTable(history) {
  const tbody = document.getElementById("history-tbody");
  tbody.innerHTML = "";

  if (!history || history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted" style="padding: 24px;">No historical sessions saved yet. Run an analysis to store records.</td></tr>`;
    return;
  }

  history.forEach(h => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code class="text-cyan">${h.analysis_id}</code></td>
      <td style="font-size: 11.5px; font-family: var(--font-mono);">${h.timestamp}</td>
      <td><strong>${escapeHtml(h.source_name)}</strong></td>
      <td>${h.total_events}</td>
      <td><strong>${h.risk_score} / 100</strong></td>
      <td><span class="badge badge-${h.risk_level.toLowerCase()}">${h.risk_level}</span></td>
      <td>${escapeHtml(h.current_stage)}</td>
      <td>${escapeHtml(h.predicted_next_stage)}</td>
      <td>${h.confidence}%</td>
      <td><button class="btn btn-sm btn-cyan" onclick="loadHistoricalAnalysis('${h.analysis_id}')">Load Run</button></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadHistoricalAnalysis(analysisId) {
  try {
    showLoading(true);
    const res = await fetch(`/api/history/${analysisId}`);
    const json = await res.json();
    if (json.success && json.data) {
      updateApplicationState(json.data);
      navigateToSection("section-overview");
      showToast(`Loaded historical session: ${analysisId}`);
    } else {
      showError(json.error || "Could not retrieve historical run.");
    }
  } catch (err) {
    showError("Failed to load historical analysis session.");
  } finally {
    showLoading(false);
  }
}

// ============================================================================
// CHARTS & ANALYTICS (CHART.JS)
// ============================================================================
function renderAllCharts(data) {
  renderEventsTimelineChart(data.events || []);
  renderSeverityChart(data.severity_distribution || {});
  renderStageChart(data.stage_distribution || {});
  renderRiskTrendChart(data.events || [], data.risk_score || 0);
  renderEventTypesChart(data.events || []);
  renderEntitiesRiskChart(data.user_risks || [], data.device_risks || []);
}

function destroyChart(key) {
  if (state.charts[key]) {
    state.charts[key].destroy();
    delete state.charts[key];
  }
}

function resizeAllCharts() {
  Object.values(state.charts).forEach(c => {
    if (c && typeof c.resize === "function") c.resize();
  });
}

// 1. Events Timeline Chart (Line)
function renderEventsTimelineChart(events) {
  destroyChart("timeline");
  const ctx = document.getElementById("chart-events-timeline");
  if (!ctx) return;

  const labels = events.map((e, idx) => `E-${idx + 1}`);
  const riskValues = events.map((e, idx) => e.risk_contribution || 5);

  state.charts["timeline"] = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels.length ? labels : ["E-1", "E-2"],
      datasets: [{
        label: "Risk Contribution Index",
        data: riskValues.length ? riskValues : [0, 0],
        borderColor: "#00f0ff",
        backgroundColor: "rgba(0, 240, 255, 0.12)",
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointBackgroundColor: "#00f0ff",
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8" } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8" }, min: 0 }
      }
    }
  });
}

// 2. Threat Severity Chart (Doughnut)
function renderSeverityChart(severityDist) {
  destroyChart("severity");
  const ctx = document.getElementById("chart-severity-dist");
  if (!ctx) return;

  const labels = ["Low", "Medium", "High", "Critical"];
  const counts = [
    severityDist["Low"] || 0,
    severityDist["Medium"] || 0,
    severityDist["High"] || 0,
    severityDist["Critical"] || 0
  ];

  state.charts["severity"] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: counts.reduce((a, b) => a + b, 0) > 0 ? counts : [1, 0, 0, 0],
        backgroundColor: ["#10b981", "#eab308", "#f97316", "#ef4444"],
        borderColor: "#0b101d",
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#94a3b8", font: { size: 11 } } }
      },
      cutout: "65%"
    }
  });
}

// 3. Attack Stage Distribution (Bar)
function renderStageChart(stageDist) {
  destroyChart("stage");
  const ctx = document.getElementById("chart-stage-dist");
  if (!ctx) return;

  const labels = Object.keys(stageDist).length ? Object.keys(stageDist) : ["Routine Activity"];
  const dataVals = Object.keys(stageDist).length ? Object.values(stageDist) : [1];

  state.charts["stage"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Events per Stage",
        data: dataVals,
        backgroundColor: "rgba(59, 130, 246, 0.75)",
        borderColor: "#3b82f6",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#94a3b8", font: { size: 10 } } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8", stepSize: 1 }, min: 0 }
      }
    }
  });
}

// 4. Risk Trend Progression (Area Line)
function renderRiskTrendChart(events, finalScore) {
  destroyChart("riskTrend");
  const ctx = document.getElementById("chart-risk-trend");
  if (!ctx) return;

  const count = Math.max(events.length, 5);
  const labels = Array.from({ length: count }, (_, i) => `T+${i * 2}m`);
  
  // Calculate synthetic progression towards final score
  const trendData = [];
  let currentVal = 10;
  const step = (finalScore - 10) / (count - 1);
  for (let i = 0; i < count; i++) {
    trendData.push(Math.round(currentVal));
    currentVal += step;
  }

  state.charts["riskTrend"] = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        label: "Cumulative Risk Score",
        data: trendData,
        borderColor: finalScore > 60 ? "#ef4444" : "#10b981",
        backgroundColor: finalScore > 60 ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.15)",
        fill: true,
        tension: 0.3,
        borderWidth: 2,
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8" } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8" }, max: 100, min: 0 }
      }
    }
  });
}

// 5. Event Types Chart (Bar in Patterns section)
function renderEventTypesChart(events) {
  destroyChart("eventTypes");
  const ctx = document.getElementById("chart-event-types");
  if (!ctx) return;

  const counts = {};
  events.forEach(e => {
    const t = e.event_type || "Generic";
    counts[t] = (counts[t] || 0) + 1;
  });

  state.charts["eventTypes"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(counts),
      datasets: [{
        label: "Occurrences",
        data: Object.values(counts),
        backgroundColor: "rgba(168, 85, 247, 0.65)",
        borderColor: "#a855f7",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#94a3b8", font: { size: 10 } } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8", stepSize: 1 }, min: 0 }
      }
    }
  });
}

// 6. Entities Risk Comparison Chart (Bar in Entities section)
function renderEntitiesRiskChart(users, devices) {
  destroyChart("entities");
  const ctx = document.getElementById("chart-entities-risk");
  if (!ctx) return;

  const allNames = [
    ...users.map(u => `User: ${u.name}`),
    ...devices.map(d => `Host: ${d.device}`)
  ].slice(0, 8);

  const scores = [
    ...users.map(u => u.risk_score),
    ...devices.map(d => d.risk_score)
  ].slice(0, 8);

  state.charts["entities"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: allNames.length ? allNames : ["Sample Entity"],
      datasets: [{
        label: "Risk Score (0-100)",
        data: scores.length ? scores : [20],
        backgroundColor: scores.map(s => s > 60 ? "rgba(239, 68, 68, 0.7)" : (s > 30 ? "rgba(234, 179, 8, 0.7)" : "rgba(16, 185, 129, 0.7)")),
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#94a3b8", font: { size: 10 } } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#94a3b8" }, max: 100, min: 0 }
      }
    }
  });
}

// ============================================================================
// SEARCH, SORT & FILTERS
// ============================================================================
function initFilterEvents() {
  // Search input
  const searchInput = document.getElementById("event-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      state.tableSearchQuery = e.target.value.trim();
      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
    });
  }

  // Severity select
  const sevSelect = document.getElementById("filter-severity-select");
  if (sevSelect) {
    sevSelect.addEventListener("change", (e) => {
      state.tableSeverityFilter = e.target.value;
      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
    });
  }

  // Status select
  const statusSelect = document.getElementById("filter-status-select");
  if (statusSelect) {
    statusSelect.addEventListener("change", (e) => {
      state.tableStatusFilter = e.target.value;
      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
    });
  }

  // Attack Stage select
  const stageSelect = document.getElementById("filter-stage-select");
  if (stageSelect) {
    stageSelect.addEventListener("change", (e) => {
      state.tableStageFilter = e.target.value;
      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
    });
  }

  // Clear filters button
  const btnClear = document.getElementById("btn-clear-filters");
  if (btnClear) {
    btnClear.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      if (sevSelect) sevSelect.value = "all";
      if (statusSelect) statusSelect.value = "all";
      if (stageSelect) stageSelect.value = "all";

      state.tableSearchQuery = "";
      state.tableSeverityFilter = "all";
      state.tableStatusFilter = "all";
      state.tableStageFilter = "all";

      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
      showToast("Filters cleared");
    });
  }

  // Table header sorting
  const sortableHeaders = document.querySelectorAll(".sortable-table th[data-sort]");
  sortableHeaders.forEach(th => {
    th.addEventListener("click", () => {
      const col = th.getAttribute("data-sort");
      if (state.tableSortColumn === col) {
        state.tableSortAsc = !state.tableSortAsc;
      } else {
        state.tableSortColumn = col;
        state.tableSortAsc = true;
      }
      renderSecurityEventsTable(state.currentAnalysis ? state.currentAnalysis.events : []);
    });
  });

  // Alerts section severity pills
  const alertPills = document.querySelectorAll("#alert-filter-buttons .btn-filter");
  alertPills.forEach(pill => {
    pill.addEventListener("click", () => {
      alertPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      state.activeSeverityFilter = pill.getAttribute("data-severity");
      renderAlerts(state.currentAnalysis ? state.currentAnalysis.alerts : []);
    });
  });
}

// ============================================================================
// MODAL & EXPORT EVENTS
// ============================================================================
function initModalEvents() {
  const modal = document.getElementById("alert-detail-modal");
  const closeBtn = document.getElementById("modal-close-btn");

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
  }

  // Reset database button
  const btnReset = document.getElementById("btn-reset-database");
  if (btnReset) {
    btnReset.addEventListener("click", async () => {
      if (confirm("Are you sure you want to clear all historical analysis runs and alerts from SQLite?")) {
        try {
          const res = await fetch("/api/settings/reset", { method: "POST" });
          const json = await res.json();
          if (json.success) {
            showToast("Database reset successfully.");
            loadDashboardData();
            loadHistoryList();
          }
        } catch (e) {
          showError("Failed to reset database.");
        }
      }
    });
  }
}

function openAlertModal(alertId) {
  const modal = document.getElementById("alert-detail-modal");
  const modalBody = document.getElementById("modal-alert-body");
  const modalTitle = document.getElementById("modal-alert-title");

  const alerts = state.currentAnalysis ? state.currentAnalysis.alerts : [];
  const alert = alerts.find(a => a.alert_id === alertId);

  if (!alert) return;

  modalTitle.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber"></i> Alert: ${escapeHtml(alert.alert_id)}`;
  modalBody.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 14px;">
      <div>
        <h4 style="font-size: 16px; margin-bottom: 4px; color: #fff;">${escapeHtml(alert.title)}</h4>
        <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
        <span style="font-size: 12px; color: var(--text-dim); margin-left: 10px;">${alert.timestamp}</span>
      </div>
      <p style="font-size: 13.5px; color: var(--text-main); line-height: 1.5;">${escapeHtml(alert.description)}</p>
      
      <div style="background-color: var(--bg-subtle); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
        <div style="font-size: 12px; margin-bottom: 6px;"><strong>Target User:</strong> ${escapeHtml(alert.user)}</div>
        <div style="font-size: 12px; margin-bottom: 6px;"><strong>Source Device:</strong> <code>${escapeHtml(alert.source_ip)}</code></div>
        <div style="font-size: 12px; margin-bottom: 6px;"><strong>Current Stage:</strong> <span class="highlight-red">${escapeHtml(alert.current_stage)}</span></div>
        <div style="font-size: 12px; margin-bottom: 6px;"><strong>Predicted Next:</strong> <span class="highlight-purple">${escapeHtml(alert.predicted_next_stage)}</span></div>
        <div style="font-size: 12px;"><strong>Risk Score:</strong> ${alert.risk_score}/100</div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 10px;">
        <button class="btn btn-primary-glow btn-sm" onclick="document.getElementById('alert-detail-modal').classList.add('hidden')">
          Acknowledge Alert
        </button>
      </div>
    </div>
  `;

  modal.classList.remove("hidden");
}

function initExportEvents() {
  const btnPrint = document.getElementById("btn-print-report");
  if (btnPrint) {
    btnPrint.addEventListener("click", () => {
      window.print();
    });
  }

  const btnExportJson = document.getElementById("btn-download-report-json");
  if (btnExportJson) {
    btnExportJson.addEventListener("click", () => {
      if (!state.currentAnalysis) {
        showError("No active analysis to export.");
        return;
      }
      const analysisId = state.currentAnalysis.analysis_id;
      window.open(`/api/reports/download/${analysisId}?format=json`, "_blank");
      showToast("Downloading JSON security report...");
    });
  }

  const btnExportMd = document.getElementById("btn-download-report-md");
  if (btnExportMd) {
    btnExportMd.addEventListener("click", () => {
      if (!state.currentAnalysis) {
        showError("No active analysis to export.");
        return;
      }
      const analysisId = state.currentAnalysis.analysis_id;
      window.open(`/api/reports/download/${analysisId}?format=markdown`, "_blank");
      showToast("Downloading Markdown security audit report...");
    });
  }
}

function initRemediationEvents() {
  const tabsContainer = document.getElementById("remediation-server-tabs");
  if (tabsContainer) {
    const tabBtns = tabsContainer.querySelectorAll(".server-tab-btn");
    tabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        tabBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        state.activeRemediationServer = btn.getAttribute("data-server") || "nginx";
        renderRemediationPlaybook(state.remediationPlaybook);
      });
    });
  }

  const btnCopy = document.getElementById("btn-copy-remediation");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => {
      const codeElem = document.getElementById("remediation-code-content");
      const textToCopy = codeElem ? codeElem.innerText : "";
      if (!textToCopy || textToCopy.startsWith("# Loading") || textToCopy.startsWith("# Awaiting")) {
        showToast("No configuration available to copy.", "error");
        return;
      }

      navigator.clipboard.writeText(textToCopy).then(() => {
        const copyBtnText = document.getElementById("copy-btn-text");
        if (copyBtnText) copyBtnText.innerText = "Copied!";
        btnCopy.classList.add("btn-success");
        showToast("Defensive playbook snippet copied to clipboard!");
        setTimeout(() => {
          if (copyBtnText) copyBtnText.innerText = "Copy to Clipboard";
          btnCopy.classList.remove("btn-success");
        }, 2200);
      }).catch(() => {
        showToast("Failed to copy to clipboard", "error");
      });
    });
  }

  const btnDownload = document.getElementById("btn-download-remediation");
  if (btnDownload) {
    btnDownload.addEventListener("click", () => {
      const server = state.activeRemediationServer || "nginx";
      if (state.currentAnalysis && state.currentAnalysis.analysis_id) {
        window.open(`/api/remediation/download/${state.currentAnalysis.analysis_id}?server=${server}`, "_blank");
        showToast(`Downloading ${server.toUpperCase()} hardening file...`);
      } else if (state.remediationPlaybook && state.remediationPlaybook[server]) {
        const item = state.remediationPlaybook[server];
        const blob = new Blob([item.snippet], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = item.filename || `remediation_${server}.conf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`Downloading ${server.toUpperCase()} hardening file...`);
      } else {
        showToast("No active remediation playbook available to download.", "error");
      }
    });
  }
}

// ============================================================================
// UI FEEDBACK HELPERS (LOADING, ERROR, TOAST)
// ============================================================================
function showLoading(isLoading) {
  const stateBox = document.getElementById("analysis-loading-state");
  if (stateBox) {
    if (isLoading) {
      stateBox.classList.remove("hidden");
    } else {
      stateBox.classList.add("hidden");
    }
  }
}

function showError(msg) {
  const errBox = document.getElementById("analysis-error-box");
  const errMsg = document.getElementById("analysis-error-message");
  if (errBox && errMsg) {
    errMsg.innerText = msg;
    errBox.classList.remove("hidden");
  }
  showToast(msg, "error");
}

function hideError() {
  const errBox = document.getElementById("analysis-error-box");
  if (errBox) errBox.classList.add("hidden");
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  const icon = type === "error" ? "fa-circle-xmark text-red" : "fa-circle-check highlight-cyan";
  toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
