"""Lightweight real-time visual analytics and threat intelligence dashboard."""

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aiohttp import web

from ..config import AppConfig
from ..storage import DatabaseManager

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Indian Bank Phishing Monitor — SOC Visual Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: ui-sans-serif, system-ui, sans-serif; }
    .card { background-color: #111827; border: 1px solid #1f2937; }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-moderate { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
  </style>
</head>
<body class="min-h-screen p-4 md:p-8">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Header -->
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-gray-800 pb-5">
      <div>
        <div class="flex items-center gap-3">
          <span class="text-3xl">🛡️</span>
          <h1 class="text-2xl md:text-3xl font-bold tracking-tight text-white">
            Indian Bank Phishing Domain Monitor
          </h1>
          <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            LIVE CT INTERCEPTOR
          </span>
        </div>
        <p class="text-gray-400 text-sm mt-1">Real-time Certificate Transparency phishing detection & forensic triage for Indian financial institutions</p>
      </div>
      <div class="flex items-center gap-3">
        <button onclick="loadDashboardData()" class="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm font-medium transition border border-gray-700 flex items-center gap-2">
          <span>🔄</span> Refresh Telemetry
        </button>
      </div>
    </header>

    <!-- Metrics Overview Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="card p-5 rounded-xl">
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400">Total Flagged Threats</div>
        <div class="text-3xl font-extrabold text-white mt-2" id="metric-total">0</div>
        <div class="text-xs text-gray-500 mt-1">Recorded in SQLite WAL store</div>
      </div>
      <div class="card p-5 rounded-xl border-l-4 border-l-red-500">
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400">Critical Risk (Score &ge; 80)</div>
        <div class="text-3xl font-extrabold text-red-400 mt-2" id="metric-critical">0</div>
        <div class="text-xs text-red-500/70 mt-1">Requires immediate takedown</div>
      </div>
      <div class="card p-5 rounded-xl border-l-4 border-l-cyan-500">
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400">Target Brands Targeted</div>
        <div class="text-3xl font-extrabold text-cyan-400 mt-2" id="metric-brands">0</div>
        <div class="text-xs text-gray-500 mt-1">Banks, UPI & fintechs</div>
      </div>
      <div class="card p-5 rounded-xl border-l-4 border-l-amber-500">
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400">Average Risk Score</div>
        <div class="text-3xl font-extrabold text-amber-400 mt-2" id="metric-avg-score">0</div>
        <div class="text-xs text-gray-500 mt-1">Heuristic severity scale (0-100)</div>
      </div>
    </div>

    <!-- Charts Section -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="card p-5 rounded-xl">
        <h3 class="text-base font-semibold text-white mb-4">Targeted Financial Brands Distribution</h3>
        <div class="h-64 flex items-center justify-center">
          <canvas id="brandsChart"></canvas>
        </div>
      </div>
      <div class="card p-5 rounded-xl">
        <h3 class="text-base font-semibold text-white mb-4">Top Threat Keywords & Lures</h3>
        <div class="h-64 flex items-center justify-center">
          <canvas id="keywordsChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Live Detections Table Section -->
    <div class="card rounded-xl overflow-hidden">
      <div class="p-5 border-b border-gray-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h3 class="text-lg font-bold text-white">Live Threat Detection Feed</h3>
          <p class="text-xs text-gray-400 mt-0.5">Real-time forensic telemetry captured by the CT monitoring daemon</p>
        </div>
        <div class="flex items-center gap-3 w-full md:w-auto">
          <input type="text" id="searchInput" oninput="filterTable()" placeholder="Search domain, brand, or keyword..."
                 class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 w-full md:w-64">
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-gray-300">
          <thead class="bg-gray-900/60 text-xs uppercase tracking-wider text-gray-400 border-b border-gray-800">
            <tr>
              <th class="px-5 py-3">Timestamp (UTC)</th>
              <th class="px-5 py-3">Flagged FQDN</th>
              <th class="px-5 py-3">Target Brand</th>
              <th class="px-5 py-3">Risk Score</th>
              <th class="px-5 py-3">Detected Keywords</th>
              <th class="px-5 py-3">Resolved IP</th>
              <th class="px-5 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="detectionsTableBody" class="divide-y divide-gray-800/60">
            <tr><td colspan="7" class="px-5 py-8 text-center text-gray-500">Loading live telemetry...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- Takedown Notice Modal -->
  <div id="takedownModal" class="fixed inset-0 bg-black/80 hidden items-center justify-center p-4 z-50">
    <div class="card max-w-3xl w-full rounded-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
      <div class="flex justify-between items-center border-b border-gray-800 pb-3">
        <div class="flex items-center gap-2">
          <span class="text-xl">📋</span>
          <h3 class="text-lg font-bold text-white" id="modalTitle">CERT-In / Registrar Abuse Takedown Packet</h3>
        </div>
        <button onclick="closeModal()" class="text-gray-400 hover:text-white text-lg">&times;</button>
      </div>
      <p class="text-xs text-gray-400">Pre-formatted formal takedown notification ready to send to domain registrars, hosting abuse desks, and CERT-In (<code class="text-cyan-400">incident@cert-in.org.in</code>).</p>
      <textarea id="takedownText" readonly class="w-full h-80 bg-gray-950 font-mono text-xs text-emerald-400 p-4 rounded-xl border border-gray-800 focus:outline-none select-all"></textarea>
      <div class="flex justify-end gap-3 pt-2">
        <button onclick="copyTakedownText()" id="copyBtn" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition">
          Copy Notice to Clipboard
        </button>
        <button onclick="closeModal()" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition">
          Close
        </button>
      </div>
    </div>
  </div>

  <script>
    let rawDetections = [];
    let brandsChart = null;
    let keywordsChart = null;

    async function loadDashboardData() {
      try {
        const [statsRes, detRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/detections')
        ]);
        const stats = await statsRes.json();
        const detections = await detRes.json();
        rawDetections = detections;

        // Populate metrics
        document.getElementById('metric-total').innerText = stats.total_detections || 0;
        document.getElementById('metric-critical').innerText = stats.critical_count || 0;
        document.getElementById('metric-brands').innerText = Object.keys(stats.brand_counts || {}).length;
        document.getElementById('metric-avg-score').innerText = stats.avg_risk_score || 0;

        // Render charts
        renderBrandsChart(stats.brand_counts || {});
        renderKeywordsChart(stats.keyword_counts || {});

        // Render table
        renderTable(detections);
      } catch (err) {
        console.error('Failed to load telemetry:', err);
      }
    }

    function renderBrandsChart(brandCounts) {
      const ctx = document.getElementById('brandsChart').getContext('2d');
      const labels = Object.keys(brandCounts);
      const data = Object.values(brandCounts);

      if (brandsChart) brandsChart.destroy();
      brandsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: labels.length ? labels : ['No Data'],
          datasets: [{
            data: data.length ? data : [1],
            backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 11 } } } }
        }
      });
    }

    function renderKeywordsChart(keywordCounts) {
      const ctx = document.getElementById('keywordsChart').getContext('2d');
      const sorted = Object.entries(keywordCounts).sort((a,b) => b[1] - a[1]).slice(0, 7);
      const labels = sorted.map(s => s[0]);
      const data = sorted.map(s => s[1]);

      if (keywordsChart) keywordsChart.destroy();
      keywordsChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels.length ? labels : ['No Keywords'],
          datasets: [{
            label: 'Occurrences',
            data: data.length ? data : [0],
            backgroundColor: '#38bdf8',
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#9ca3af' }, grid: { display: false } },
            y: { ticks: { color: '#9ca3af', stepSize: 1 }, grid: { color: '#1f2937' } }
          }
        }
      });
    }

    function renderTable(data) {
      const tbody = document.getElementById('detectionsTableBody');
      if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-5 py-8 text-center text-gray-500">No threat detections found in database.</td></tr>';
        return;
      }

      tbody.innerHTML = data.map(d => {
        let badgeClass = 'badge-moderate';
        if (d.risk_score >= 80) badgeClass = 'badge-critical';
        else if (d.risk_score >= 60) badgeClass = 'badge-high';

        const brands = (d.matched_brands || []).join(', ') || '-';
        const keywords = (d.matched_keywords || []).slice(0, 3).join(', ') || '-';
        const ips = (d.dns_records && d.dns_records.a && d.dns_records.a.length) ? d.dns_records.a.join(', ') : 'Unresolved';
        const timeStr = d.first_seen ? d.first_seen.replace('T', ' ').substring(0, 19) : '-';

        return `
          <tr class="hover:bg-gray-800/40 transition">
            <td class="px-5 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">${timeStr}</td>
            <td class="px-5 py-3 font-mono font-medium text-white">${escapeHtml(d.domain)}</td>
            <td class="px-5 py-3 font-semibold text-cyan-400">${escapeHtml(brands)}</td>
            <td class="px-5 py-3">
              <span class="px-2.5 py-1 rounded-full text-xs font-bold ${badgeClass}">${d.risk_score} / 100</span>
            </td>
            <td class="px-5 py-3 text-xs text-gray-400">${escapeHtml(keywords)}</td>
            <td class="px-5 py-3 font-mono text-xs text-gray-400">${escapeHtml(ips)}</td>
            <td class="px-5 py-3 text-right">
              <button onclick="openTakedownModal('${encodeURIComponent(d.domain)}')" class="px-2.5 py-1 rounded bg-red-950 hover:bg-red-900 text-red-300 text-xs font-medium border border-red-800 transition">
                Takedown Notice
              </button>
            </td>
          </tr>
        `;
      }).join('');
    }

    function filterTable() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      const filtered = rawDetections.filter(d => {
        return (d.domain && d.domain.toLowerCase().includes(q)) ||
               (d.matched_brands && d.matched_brands.some(b => b.toLowerCase().includes(q))) ||
               (d.matched_keywords && d.matched_keywords.some(k => k.toLowerCase().includes(q)));
      });
      renderTable(filtered);
    }

    async function openTakedownModal(encodedDomain) {
      const domain = decodeURIComponent(encodedDomain);
      document.getElementById('modalTitle').innerText = 'Abuse Takedown Notice — ' + domain;
      try {
        const res = await fetch('/api/takedown/' + encodeURIComponent(domain));
        const json = await res.json();
        document.getElementById('takedownText').value = json.takedown_notice || 'Notice unavailable';
        document.getElementById('takedownModal').classList.remove('hidden');
        document.getElementById('takedownModal').classList.add('flex');
      } catch (err) {
        alert('Failed to load takedown notice');
      }
    }

    function closeModal() {
      document.getElementById('takedownModal').classList.remove('flex');
      document.getElementById('takedownModal').classList.add('hidden');
      document.getElementById('copyBtn').innerText = 'Copy Notice to Clipboard';
    }

    function copyTakedownText() {
      const textarea = document.getElementById('takedownText');
      textarea.select();
      navigator.clipboard.writeText(textarea.value);
      const btn = document.getElementById('copyBtn');
      btn.innerText = '✅ Copied to Clipboard!';
      setTimeout(() => btn.innerText = 'Copy Notice to Clipboard', 2500);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    window.addEventListener('DOMContentLoaded', loadDashboardData);
  </script>
</body>
</html>
"""


def generate_takedown_notice(d: Dict[str, Any]) -> str:
    """Generate formal abuse takedown notification ready for CERT-In or registrar abuse desk."""
    domain = d.get("domain", "unknown")
    brands = ", ".join(d.get("matched_brands", [])) or "Indian Financial Institutions"
    score = d.get("risk_score", 0)
    reasons = d.get("reasons", [])
    first_seen = d.get("first_seen", datetime.now(timezone.utc).isoformat())

    dns_info = d.get("dns_records") or {}
    a_records = ", ".join(dns_info.get("a", [])) or "None resolved (Dormant / Fast-flux)"
    ns_records = ", ".join(dns_info.get("ns", [])) or "None resolved"

    reasons_formatted = (
        "\n".join([f"  - {r}" for r in reasons])
        if reasons
        else "  - Brand impersonation and deceptive SSL/TLS issuance"
    )

    return f"""URGENT: Phishing Domain Takedown Request — Brand Impersonation Incident
================================================================================
TO:
  - Domain Registrar Abuse Desk / Hosting Provider NOC
  - Indian Computer Emergency Response Team (CERT-In) — incident@cert-in.org.in
  - National Cyber Crime Reporting Portal (cybercrime.gov.in)

DATE OF INCIDENT DISCOVERY: {first_seen} (UTC)
CASE REFERENCE:             CERTIN-TAKEDOWN-{domain.upper()}

1. TARGET ENTITY UNDER ATTACK:
--------------------------------------------------------------------------------
Financial Institution / Payment System: {brands}
Deceptive Fully Qualified Domain Name: {domain}
Assigned Risk Severity Score:           {score} / 100 (CRITICAL MALICIOUS PHISHING)

2. TECHNICAL TELEMETRY & ATTRIBUTION:
--------------------------------------------------------------------------------
A (IPv4) Records:     {a_records}
NS (Nameservers):     {ns_records}

Observed Threat Activity:
The domain '{domain}' was intercepted during SSL/TLS certificate issuance
exhibiting characteristics of fraudulent credential harvesting, fake KYC/PAN
verification, unauthorized banking APK distribution, or UPI cashback deception.

Forensic Rule Violations Triggered:
{reasons_formatted}

3. REQUESTED IMMEDIATE MITIGATION ACTIONS:
--------------------------------------------------------------------------------
Pursuant to international cybercrime conventions and IT Act guidelines:
1. Immediately suspend DNS resolution for '{domain}' at registrar level.
2. Sinkhole all nameserver mappings to prevent victim credential harvesting.
3. Terminate associated hosting services and preserve web server access logs.
4. Provide WHOIS subscriber registration records for criminal law enforcement.

NOTICE GENERATED BY:
Indian Bank Phishing Domain Monitor — Autonomous SOC Threat Intelligence Engine
Contact / Security Operations: Arya Rakshit <aryarakshitgl@gmail.com>
================================================================================
"""


def create_dashboard_app(
    config: Optional[AppConfig] = None, db_manager: Optional[DatabaseManager] = None
) -> web.Application:
    """Create and configure aiohttp web application for the dashboard."""
    cfg = config or AppConfig()
    db = db_manager or DatabaseManager(config=cfg)

    app = web.Application()

    async def handle_index(request: web.Request) -> web.Response:
        return web.Response(text=DASHBOARD_HTML, content_type="text/html")

    async def handle_stats(request: web.Request) -> web.Response:
        """Compute summary telemetry statistics from database."""
        try:
            with db.get_connection() as conn:
                total_row = conn.execute("SELECT COUNT(*) AS total FROM detections").fetchone()
                total = total_row["total"] if total_row else 0

                crit_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM detections WHERE risk_score >= 80"
                ).fetchone()
                critical = crit_row["cnt"] if crit_row else 0

                mod_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM detections WHERE risk_score >= 60 AND risk_score < 80"
                ).fetchone()
                moderate = mod_row["cnt"] if mod_row else 0

                avg_row = conn.execute(
                    "SELECT AVG(risk_score) AS avg_score FROM detections"
                ).fetchone()
                avg_score = round(avg_row["avg_score"] or 0, 1) if avg_row else 0

                rows = conn.execute(
                    "SELECT matched_brands, matched_keywords FROM detections"
                ).fetchall()

            brand_counter: Counter[str] = Counter()
            kw_counter: Counter[str] = Counter()

            for r in rows:
                if r["matched_brands"]:
                    try:
                        for b in json.loads(r["matched_brands"]):
                            brand_counter[b] += 1
                    except Exception:
                        pass
                if r["matched_keywords"]:
                    try:
                        for kw in json.loads(r["matched_keywords"]):
                            kw_counter[kw] += 1
                    except Exception:
                        pass

            return web.json_response(
                {
                    "total_detections": total,
                    "critical_count": critical,
                    "moderate_count": moderate,
                    "avg_risk_score": avg_score,
                    "brand_counts": dict(brand_counter.most_common(10)),
                    "keyword_counts": dict(kw_counter.most_common(10)),
                }
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_detections(request: web.Request) -> web.Response:
        """Fetch detections list with optional limit and filtering."""
        limit = int(request.query.get("limit", 100))
        min_score = int(request.query.get("min_score", 0))

        detections = db.get_recent_detections(limit=limit, min_score=min_score)
        result: List[Dict[str, Any]] = [d.model_dump(mode="json") for d in detections]
        return web.json_response(result)

    async def handle_takedown(request: web.Request) -> web.Response:
        """Generate takedown notice for a specific domain."""
        domain = request.match_info.get("domain", "")
        detection = db.get_detection_by_domain(domain)
        if not detection:
            return web.json_response(
                {"error": f"Domain '{domain}' not found in database"}, status=404
            )

        det_dict = detection.model_dump(mode="json")
        notice = generate_takedown_notice(det_dict)

        return web.json_response(
            {
                "domain": domain,
                "risk_score": detection.risk_score,
                "matched_brands": detection.matched_brands,
                "takedown_notice": notice,
            }
        )

    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_stats)
    app.router.add_get("/api/detections", handle_detections)
    app.router.add_get("/api/takedown/{domain}", handle_takedown)

    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    config: Optional[AppConfig] = None,
    db_manager: Optional[DatabaseManager] = None,
) -> None:
    """Run visual dashboard web server synchronously."""
    app = create_dashboard_app(config=config, db_manager=db_manager)
    print(f"\n[+] Starting Indian Bank Phishing Visual Dashboard at http://{host}:{port}")
    web.run_app(app, host=host, port=port)
