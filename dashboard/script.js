/**
 * NSM Platform — Dashboard JavaScript (Person 5)
 * =================================================
 * Handles:
 *   - Fetching data from Flask REST API
 *   - Updating stat cards, charts, and alerts table
 *   - PCAP upload and analysis triggers
 *   - Auto-refresh every 10 seconds
 *
 * API Base: http://localhost:5000/api
 */

// ── Configuration ──
const API_BASE = window.location.origin + "/api";
const REFRESH_INTERVAL = 10000; // 10 seconds

// ── Chart instances (global so we can update them) ──
let trafficChart = null;
let attackChart = null;
let severityChart = null;

// ══════════════════════════════════════════
// INITIALIZATION — runs when page loads
// ══════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    checkServerStatus();
    fetchAllData();
    setInterval(fetchAllData, REFRESH_INTERVAL);

    // Button event listeners
    document.getElementById("btnAnalyze").addEventListener("click", analyzePcap);
    document.getElementById("btnClear").addEventListener("click", clearData);
    document.getElementById("fileInput").addEventListener("change", uploadPcap);
});

// ══════════════════════════════════════════
// SERVER STATUS CHECK
// ══════════════════════════════════════════
async function checkServerStatus() {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    try {
        const res = await fetch(`${API_BASE}/status`);
        if (res.ok) {
            dot.className = "status-dot active";
            text.textContent = "Active";
        } else {
            dot.className = "status-dot error";
            text.textContent = "Error";
        }
    } catch (e) {
        dot.className = "status-dot error";
        text.textContent = "Offline";
    }
}

// ══════════════════════════════════════════
// FETCH ALL DATA (called on load + interval)
// ══════════════════════════════════════════
async function fetchAllData() {
    try {
        const [summaryRes, alertsRes, statsRes] = await Promise.all([
            fetch(`${API_BASE}/summary`),
            fetch(`${API_BASE}/alerts`),
            fetch(`${API_BASE}/traffic-stats`),
        ]);

        const summary = await summaryRes.json();
        const alerts = await alertsRes.json();
        const stats = await statsRes.json();

        updateStatCards(summary);
        updateAlertsTable(alerts.alerts);
        updateTrafficChart(stats.stats);
        updateAttackChart(summary.attack_counts);
        updateSeverityChart(summary.severity_counts);
    } catch (e) {
        console.error("Failed to fetch data:", e);
    }
}

// ══════════════════════════════════════════
// UPDATE STAT CARDS
// ══════════════════════════════════════════
function updateStatCards(summary) {
    animateValue("totalPackets", summary.total_packets || 0);
    animateValue("activeAlerts", summary.total_alerts || 0);
    animateValue("portScanCount", (summary.attack_counts || {}).port_scan || 0);
    animateValue("bruteForceCount", (summary.attack_counts || {}).brute_force || 0);
    animateValue("synFloodCount", (summary.attack_counts || {}).syn_flood || 0);

    const sev = summary.severity_counts || {};
    const highCrit = (sev.high || 0) + (sev.critical || 0);
    animateValue("highAlerts", highCrit);
}

function animateValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    const current = parseInt(el.textContent) || 0;
    if (current !== newValue) {
        el.textContent = newValue;
        el.classList.add("updated");
        setTimeout(() => el.classList.remove("updated"), 400);
    }
}

// ══════════════════════════════════════════
// UPDATE ALERTS TABLE
// ══════════════════════════════════════════
function updateAlertsTable(alerts) {
    const tbody = document.getElementById("alertsBody");
    const badge = document.getElementById("alertsBadge");
    badge.textContent = alerts ? alerts.length : 0;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No alerts yet. Click "Analyze PCAP" to start.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(alert => {
        const severityClass = `severity-${alert.severity}`;
        const attackLabel = alert.attack_type.replace(/_/g, " ").toUpperCase();
        const confidence = (alert.confidence * 100).toFixed(0);
        const confColor = alert.confidence >= 0.8 ? "var(--accent-green)" :
                          alert.confidence >= 0.5 ? "var(--accent-yellow)" : "var(--accent-red)";
        const time = formatTime(alert.timestamp);

        return `
            <tr>
                <td><span class="severity-badge ${severityClass}">${alert.severity.toUpperCase()}</span></td>
                <td class="attack-type-cell">${attackLabel}</td>
                <td class="ip-cell">${alert.src_ip}</td>
                <td class="ip-cell">${alert.dst_ip}</td>
                <td>${alert.details}</td>
                <td>
                    <div class="confidence-bar-container">
                        <div class="confidence-bar">
                            <div class="confidence-bar-fill" style="width:${confidence}%;background:${confColor}"></div>
                        </div>
                        <span class="confidence-text" style="color:${confColor}">${confidence}%</span>
                    </div>
                </td>
                <td>${time}</td>
            </tr>
        `;
    }).join("");
}

function formatTime(isoString) {
    try {
        const d = new Date(isoString);
        return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
        return isoString;
    }
}

// ══════════════════════════════════════════
// CHARTS — Initialization
// ══════════════════════════════════════════
function initCharts() {
    // Global Chart.js defaults for dark theme
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "rgba(255,255,255,0.06)";
    Chart.defaults.font.family = "'Inter', sans-serif";

    // ── Traffic Distribution (Bar Chart) ──
    const trafficCtx = document.getElementById("trafficChart").getContext("2d");
    trafficChart = new Chart(trafficCtx, {
        type: "bar",
        data: {
            labels: ["TCP", "UDP", "ICMP", "Other"],
            datasets: [{
                label: "Packet Count",
                data: [0, 0, 0, 0],
                backgroundColor: [
                    "rgba(99, 102, 241, 0.7)",
                    "rgba(34, 211, 238, 0.7)",
                    "rgba(251, 191, 36, 0.7)",
                    "rgba(167, 139, 250, 0.7)",
                ],
                borderColor: [
                    "rgba(99, 102, 241, 1)",
                    "rgba(34, 211, 238, 1)",
                    "rgba(251, 191, 36, 1)",
                    "rgba(167, 139, 250, 1)",
                ],
                borderWidth: 1,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(17, 24, 39, 0.95)",
                    titleColor: "#f1f5f9",
                    bodyColor: "#94a3b8",
                    borderColor: "rgba(255,255,255,0.1)",
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(255,255,255,0.04)" },
                    ticks: { precision: 0 },
                },
                x: {
                    grid: { display: false },
                }
            }
        }
    });

    // ── Attack Summary (Doughnut Chart) ──
    const attackCtx = document.getElementById("attackChart").getContext("2d");
    attackChart = new Chart(attackCtx, {
        type: "doughnut",
        data: {
            labels: ["Port Scan", "SYN Flood", "Brute Force", "Suspicious"],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    "rgba(251, 191, 36, 0.8)",
                    "rgba(244, 114, 182, 0.8)",
                    "rgba(249, 115, 22, 0.8)",
                    "rgba(167, 139, 250, 0.8)",
                ],
                borderColor: "rgba(10, 14, 26, 0.8)",
                borderWidth: 3,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "62%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10,
                        font: { size: 12, weight: "500" },
                    }
                },
                tooltip: {
                    backgroundColor: "rgba(17, 24, 39, 0.95)",
                    titleColor: "#f1f5f9",
                    bodyColor: "#94a3b8",
                    borderColor: "rgba(255,255,255,0.1)",
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                }
            }
        }
    });

    // ── Severity Breakdown (Horizontal Bar) ──
    const sevCtx = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(sevCtx, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    "rgba(239, 68, 68, 0.75)",
                    "rgba(249, 115, 22, 0.75)",
                    "rgba(234, 179, 8, 0.75)",
                    "rgba(34, 211, 238, 0.75)",
                ],
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: "y",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(17, 24, 39, 0.95)",
                    padding: 10,
                    cornerRadius: 8,
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: "rgba(255,255,255,0.04)" },
                    ticks: { precision: 0 },
                },
                y: {
                    grid: { display: false },
                }
            }
        }
    });
}

// ══════════════════════════════════════════
// CHARTS — Update with real data
// ══════════════════════════════════════════
function updateTrafficChart(stats) {
    if (!stats || !trafficChart) return;
    trafficChart.data.datasets[0].data = [
        stats.tcp_count || 0,
        stats.udp_count || 0,
        stats.icmp_count || 0,
        stats.other_count || 0,
    ];
    trafficChart.update("none"); // "none" disables animation for smooth updates
}

function updateAttackChart(counts) {
    if (!counts || !attackChart) return;
    attackChart.data.datasets[0].data = [
        counts.port_scan || 0,
        counts.syn_flood || 0,
        counts.brute_force || 0,
        counts.suspicious_traffic || 0,
    ];
    attackChart.update("none");
}

function updateSeverityChart(sevCounts) {
    if (!severityChart) return;
    const c = sevCounts || {};
    severityChart.data.datasets[0].data = [
        c.critical || 0,
        c.high || 0,
        c.medium || 0,
        c.low || 0,
    ];
    severityChart.update("none");

    // Update the legend below the chart
    const legend = document.getElementById("severityLegend");
    const items = [
        { label: "Critical", count: c.critical || 0, color: "#ef4444" },
        { label: "High",     count: c.high || 0,     color: "#f97316" },
        { label: "Medium",   count: c.medium || 0,   color: "#eab308" },
        { label: "Low",      count: c.low || 0,      color: "#22d3ee" },
    ];
    legend.innerHTML = items.map(item => `
        <div class="severity-legend-item">
            <div class="severity-legend-left">
                <span class="severity-legend-dot" style="background:${item.color}"></span>
                <span class="severity-legend-label">${item.label}</span>
            </div>
            <span class="severity-legend-count">${item.count}</span>
        </div>
    `).join("");
}

// ══════════════════════════════════════════
// ACTIONS — Analyze, Upload, Clear
// ══════════════════════════════════════════
async function analyzePcap() {
    const btn = document.getElementById("btnAnalyze");
    btn.classList.add("loading");
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/analyze`, { method: "POST" });
        const data = await res.json();

        if (res.ok) {
            showToast(`Analysis complete! ${data.total_packets} packets, ${data.total_alerts} alerts.`, "success");
            fetchAllData();
        } else {
            showToast(data.error || "Analysis failed.", "error");
        }
    } catch (e) {
        showToast("Could not connect to server.", "error");
    } finally {
        btn.classList.remove("loading");
        btn.disabled = false;
    }
}

async function uploadPcap(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("pcap", file);

    const btn = document.getElementById("btnUpload");
    btn.classList.add("loading");

    try {
        const res = await fetch(`${API_BASE}/upload`, {
            method: "POST",
            body: formData,
        });
        const data = await res.json();

        if (res.ok) {
            showToast(`"${file.name}" analyzed! ${data.total_packets} packets, ${data.total_alerts} alerts.`, "success");
            fetchAllData();
        } else {
            showToast(data.error || "Upload failed.", "error");
        }
    } catch (e) {
        showToast("Could not connect to server.", "error");
    } finally {
        btn.classList.remove("loading");
        event.target.value = ""; // reset file input
    }
}

async function clearData() {
    if (!confirm("Clear all alerts and traffic data?")) return;

    try {
        await fetch(`${API_BASE}/clear`, { method: "POST" });
        showToast("All data cleared.", "info");
        fetchAllData();
    } catch (e) {
        showToast("Could not clear data.", "error");
    }
}

// ══════════════════════════════════════════
// TOAST NOTIFICATION
// ══════════════════════════════════════════
function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    const msgEl = document.getElementById("toastMessage");
    const iconEl = document.getElementById("toastIcon");

    msgEl.textContent = message;
    toast.className = `toast ${type} show`;

    // Set icon
    if (type === "success") iconEl.textContent = "\u2713"; // checkmark
    else if (type === "error") iconEl.textContent = "\u2717"; // cross
    else iconEl.textContent = "\u2139"; // info

    // Auto-hide after 4 seconds
    setTimeout(() => {
        toast.classList.remove("show");
    }, 4000);
}
