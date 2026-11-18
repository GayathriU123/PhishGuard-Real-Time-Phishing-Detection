/**
 * PhishGuard Frontend Application & Router
 * INT395 Supervised Learning Project — PhishGuard Full-Stack Edition
 */

(function () {
  'use strict';

  // --- State ---
  const state = {
    currentRoute: '/',
    activeCase: null,
    feedStatus: null,
    modelCard: null,
    chartInstances: {}
  };

  // --- API Helpers ---
  async function apiFetch(endpoint, options = {}) {
    try {
      const res = await fetch(endpoint, options);
      if (!res.ok) {
        let errMessage = `Request failed (${res.status})`;
        try {
          const errData = await res.json();
          if (errData && errData.detail) errMessage = errData.detail;
        } catch (_) {}
        throw new Error(errMessage);
      }
      return await res.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  }

  function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 200);
    }, 3500);
  }

  function formatTime(isoString) {
    if (!isoString) return 'N/A';
    try {
      const d = new Date(isoString);
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (_) {
      return isoString;
    }
  }

  function verdictBadge(verdict) {
    switch (verdict) {
      case 'likely_phishing':
        return '<span class="badge badge-phish">Likely Phishing</span>';
      case 'needs_review':
        return '<span class="badge badge-review">Needs Review</span>';
      case 'no_known_threat':
        return '<span class="badge badge-safe">No Known Threat</span>';
      default:
        return `<span class="badge badge-info">${verdict || 'Unknown'}</span>`;
    }
  }

  function riskBadge(band) {
    switch (band) {
      case 'high':
        return '<span class="badge badge-danger">High Risk</span>';
      case 'medium':
        return '<span class="badge badge-warning">Medium Risk</span>';
      case 'low':
        return '<span class="badge badge-safe">Low Risk</span>';
      default:
        return `<span class="badge badge-info">${band || 'Unknown'}</span>`;
    }
  }

  // --- Threat Feed Header Pill ---
  async function updateThreatFeedStatus() {
    const pill = document.getElementById('intelStatusPill');
    if (!pill) return;
    try {
      const data = await apiFetch('/api/v1/threat-intel');
      state.feedStatus = data;
      const dot = pill.querySelector('.status-dot');
      const label = pill.querySelector('.status-label');
      if (data.status === 'available') {
        dot.className = 'status-dot active';
        label.textContent = `PhishTank: ${data.records_loaded.toLocaleString()} URLs loaded`;
      } else {
        dot.className = 'status-dot warning';
        label.textContent = `PhishTank: Offline / Unconfigured`;
      }
    } catch (_) {
      const dot = pill.querySelector('.status-dot');
      const label = pill.querySelector('.status-label');
      dot.className = 'status-dot warning';
      label.textContent = `Threat Feed: Offline`;
    }
  }

  // --- Router ---
  function navigate(hash) {
    window.location.hash = hash;
  }

  function parseRoute() {
    let raw = window.location.hash.slice(1) || '/';
    if (!raw.startsWith('/')) raw = '/' + raw;
    const parts = raw.split('?')[0].split('/');
    
    // Check dynamic routes e.g. /app/cases/:id
    if (parts[1] === 'app' && parts[2] === 'cases' && parts[3]) {
      return { route: '/app/cases/:id', param: parts[3] };
    }
    return { route: raw, param: null };
  }

  function handleRoute() {
    const { route, param } = parseRoute();
    state.currentRoute = route;

    // Destroy any existing chart instances to avoid canvas re-use errors
    Object.keys(state.chartInstances).forEach(k => {
      if (state.chartInstances[k]) state.chartInstances[k].destroy();
    });
    state.chartInstances = {};

    // Update active nav links
    document.querySelectorAll('[data-route]').forEach(el => {
      const target = el.getAttribute('data-route');
      el.classList.toggle('active', target === route);
    });

    // Sidebar visibility: only show sidebar on /app/* routes
    const isApp = route.startsWith('/app');
    const sidebar = document.getElementById('appSidebar');
    if (sidebar) {
      sidebar.style.display = isApp ? 'flex' : 'none';
    }

    const container = document.getElementById('viewContainer');
    if (!container) return;

    switch (route) {
      case '/':
        renderLanding(container);
        break;
      case '/how-it-works':
        renderHowItWorks(container);
        break;
      case '/learn':
        renderLearn(container);
        break;
      case '/about':
        renderAbout(container);
        break;
      case '/privacy':
        renderPrivacy(container);
        break;
      case '/terms':
        renderTerms(container);
        break;
      case '/app/overview':
        renderOverview(container);
        break;
      case '/app/scan/url':
        renderScanURL(container);
        break;
      case '/app/scan/email':
        renderScanEmail(container);
        break;
      case '/app/cases/:id':
        renderCaseDetail(container, param);
        break;
      case '/app/review-queue':
        renderReviewQueue(container);
        break;
      case '/app/investigations':
        renderInvestigations(container);
        break;
      case '/app/threat-intel':
        renderThreatIntel(container);
        break;
      case '/app/model-lab':
        renderModelLab(container);
        break;
      case '/app/reports':
        renderReports(container);
        break;
      case '/app/settings':
        renderSettings(container);
        break;
      default:
        renderNotFound(container);
    }
  }

  // ==========================================================================
  // VIEW: Landing Page
  // ==========================================================================
  function renderLanding(container) {
    container.innerHTML = `
      <section class="landing-hero">
        <span class="landing-tagline">INT395 Supervised Learning Project</span>
        <h1 class="landing-headline">Think Before You Click.<br>Intelligence Before You Trust.</h1>
        <p class="landing-subhead">
          Explainable phishing investigation combining supervised machine learning, verified threat feeds, structural URL heuristics, and human-in-the-loop oversight.
        </p>

        <div class="quick-scan-box">
          <form id="landingQuickScanForm" class="quick-scan-form">
            <input type="url" id="landingScanInput" class="quick-scan-input" placeholder="https://login.micros0ft-verify.com/auth" required>
            <button type="submit" class="btn btn-primary">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <span>Scan URL</span>
            </button>
          </form>
          <div id="landingScanResult" style="display: none; margin-top: 1.25rem; text-align: left;"></div>
        </div>
      </section>

      <!-- 4 Pillars Grid -->
      <section class="feature-grid">
        <div class="feature-card">
          <div class="feature-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          </div>
          <h3 class="feature-title">Evidence-First Explanations</h3>
          <p class="feature-desc">Every verdict is backed by 20 structural features, Shannon entropy calculations, character patterns, and deterministic heuristic points.</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.5h-2v-2h2zm0-4.5h-2V7h2z"/></svg>
          </div>
          <h3 class="feature-title">Threat Intel Provenance</h3>
          <p class="feature-desc">Attributed PhishTank feed lookups are strictly decoupled from machine learning probabilities to guarantee transparent source origins.</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/></svg>
          </div>
          <h3 class="feature-title">Human-in-the-Loop Review</h3>
          <p class="feature-desc">Security analysts can review uncertain scores, mark false positives, or confirm threats with mandatory audit-logged justifications.</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
          </div>
          <h3 class="feature-title">Calibrated Uncertainty</h3>
          <p class="feature-desc">A clean negative result is explicitly presented as "No known threat detected" rather than false certainty, respecting machine limits.</p>
        </div>
      </section>

      <!-- Differentiators Table -->
      <section class="card" style="margin-bottom: 2rem;">
        <div class="card-header">
          <h3 class="card-title">How PhishGuard Differentiates</h3>
        </div>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Existing Service</th>
                <th>Traditional Strength</th>
                <th>PhishGuard Distinction</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Google Safe Browsing</strong></td>
                <td>Browser-facing site warnings and blocklists</td>
                <td>Educational structural breakdown of lexical URL features without acting as a black-box browser blocker.</td>
              </tr>
              <tr>
                <td><strong>VirusTotal</strong></td>
                <td>Aggregates dozens of vendor multi-scanner engines</td>
                <td>Transparent supervised ML pipeline with student-trained baseline comparisons and held-out metrics.</td>
              </tr>
              <tr>
                <td><strong>Microsoft Defender</strong></td>
                <td>Enterprise mail exchange and tenant quarantine</td>
                <td>Compact, safe .eml parser and heuristic extraction with zero remote tracking pixel loading.</td>
              </tr>
              <tr>
                <td><strong>PhishTank</strong></td>
                <td>Community verified phishing URL feed</td>
                <td>Attributed intelligence source cleanly separated from machine predictions in schemas and UI.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    `;

    // Hook quick scan form
    const form = document.getElementById('landingQuickScanForm');
    const input = document.getElementById('landingScanInput');
    const resultDiv = document.getElementById('landingScanResult');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = input.value.trim();
      if (!val) return;
      resultDiv.style.display = 'block';
      resultDiv.innerHTML = '<div class="spinner"></div>';
      try {
        const res = await apiFetch('/api/v1/scan/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: val })
        });
        const c = res.case;
        resultDiv.innerHTML = `
          <div class="card" style="border: 2px solid var(--primary-border); background-color: var(--primary-subtle);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
              <span style="font-weight: 700; color: var(--heading);">Investigation Case #${c.id}</span>
              ${verdictBadge(c.verdict)}
            </div>
            <p style="font-size: 0.9rem; margin-bottom: 0.75rem;">${c.summary}</p>
            <div style="display: flex; gap: 0.5rem;">
              <a href="#/app/cases/${c.id}" class="btn btn-primary btn-sm">Inspect Case Details & Evidence</a>
              <a href="#/app/overview" class="btn btn-secondary btn-sm">Open Dashboard</a>
            </div>
          </div>
        `;
        showToast('Scan completed and case created!');
      } catch (err) {
        resultDiv.innerHTML = `<div class="alert-banner alert-warning">Scan failed: ${err.message}</div>`;
      }
    });
  }

  // ==========================================================================
  // VIEW: Overview Dashboard
  // ==========================================================================
  async function renderOverview(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Security Operations Dashboard</h2>
          <p style="font-size: 0.88rem; color: var(--text-muted);">Real-time metrics, case distribution, and model activity.</p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <a href="#/app/scan/url" class="btn btn-primary btn-sm">+ Scan URL</a>
          <a href="#/app/scan/email" class="btn btn-secondary btn-sm">+ Scan Email</a>
        </div>
      </div>

      <!-- KPI Grid -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-header">
            <span>Total Cases</span>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
          </div>
          <div class="kpi-value" id="kpiTotalScans">-</div>
          <div class="kpi-subtext" id="kpiTotalScansSub">Active investigations</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span>Likely Phishing</span>
            <span class="badge badge-phish">Threats</span>
          </div>
          <div class="kpi-value" id="kpiPhishingScans" style="color: var(--phish);">-</div>
          <div class="kpi-subtext" id="kpiPhishingSub">High confidence / feed matches</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span>Pending Review</span>
            <span class="badge badge-warning">Queue</span>
          </div>
          <div class="kpi-value" id="kpiPendingReviews" style="color: var(--review);">-</div>
          <div class="kpi-subtext">Awaiting human decision</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span>Model Version</span>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06"/></svg>
          </div>
          <div class="kpi-value" id="kpiModelVersion" style="font-size: 1.4rem;">-</div>
          <div class="kpi-subtext" id="kpiModelStatus">Checking runtime...</div>
        </div>
      </div>

      <!-- Charts Row -->
      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Verdict Distribution</h3>
          </div>
          <div style="position: relative; height: 260px;">
            <canvas id="verdictChart"></canvas>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Threat Intel Feed</h3>
          </div>
          <div id="overviewFeedDetails" style="display: flex; flex-direction: column; gap: 0.75rem; font-size: 0.88rem;">
            <p>Loading threat feed metadata...</p>
          </div>
        </div>
      </div>

      <!-- Recent Cases Table -->
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Recent Investigation Cases</h3>
          <a href="#/app/investigations" class="btn btn-secondary btn-sm">View All Cases</a>
        </div>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Risk Band</th>
                <th>Status</th>
                <th>Submitted</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="overviewCasesTbody">
              <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading recent cases...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Fetch operational metrics and recent cases
    try {
      const [metricsRes, casesRes, threatRes, modelRes] = await Promise.all([
        apiFetch('/api/v1/reports/metrics').catch(() => null),
        apiFetch('/api/v1/cases?limit=5'),
        apiFetch('/api/v1/threat-intel').catch(() => null),
        apiFetch('/api/v1/model/card').catch(() => null)
      ]);

      if (casesRes) {
        document.getElementById('kpiTotalScans').textContent = casesRes.total || 0;
        const pendingCount = (casesRes.cases || []).filter(c => c.review_status === 'pending').length;
        document.getElementById('kpiPendingReviews').textContent = pendingCount;
        const sidebarBadge = document.getElementById('sidebarQueueCount');
        if (sidebarBadge) sidebarBadge.textContent = pendingCount;

        const phishCount = (casesRes.cases || []).filter(c => c.verdict === 'likely_phishing').length;
        document.getElementById('kpiPhishingScans').textContent = phishCount;
      }

      if (modelRes) {
        document.getElementById('kpiModelVersion').textContent = modelRes.model_version || 'Untrained';
        document.getElementById('kpiModelStatus').textContent = modelRes.status === 'available' ? 'Supervised URL Model' : 'No artifact installed';
      }

      if (threatRes) {
        const feedContainer = document.getElementById('overviewFeedDetails');
        feedContainer.innerHTML = `
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Provider</span>
            <strong>${threatRes.provider || 'PhishTank'}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Verified Records</span>
            <strong>${(threatRes.records_loaded || 0).toLocaleString()}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Status</span>
            <span class="badge ${threatRes.status === 'available' ? 'badge-safe' : 'badge-warning'}">${threatRes.status}</span>
          </div>
          <p style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.5rem;">${threatRes.note || ''}</p>
        `;
      }

      // Populate recent cases table
      const tbody = document.getElementById('overviewCasesTbody');
      if (casesRes && casesRes.cases && casesRes.cases.length > 0) {
        tbody.innerHTML = casesRes.cases.map(c => `
          <tr>
            <td><a href="#/app/cases/${c.id}" style="font-family: var(--font-mono); font-weight: 600; color: var(--primary); text-decoration: none;">#${c.id}</a></td>
            <td><span class="badge badge-info">${c.input_type.toUpperCase()}</span></td>
            <td>${verdictBadge(c.verdict)}</td>
            <td>${riskBadge(c.risk_band)}</td>
            <td><span class="badge ${c.review_status === 'reviewed' ? 'badge-safe' : 'badge-warning'}">${c.review_status}</span></td>
            <td>${formatTime(c.submitted_at)}</td>
            <td><a href="#/app/cases/${c.id}" class="btn btn-secondary btn-sm">Inspect</a></td>
          </tr>
        `).join('');
      } else {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No cases recorded yet. Run a URL or email scan to begin.</td></tr>`;
      }

      // Render Verdict Distribution Chart
      const ctx = document.getElementById('verdictChart');
      if (ctx && window.Chart) {
        const phish = (casesRes.cases || []).filter(c => c.verdict === 'likely_phishing').length;
        const review = (casesRes.cases || []).filter(c => c.verdict === 'needs_review').length;
        const safe = (casesRes.cases || []).filter(c => c.verdict === 'no_known_threat').length;

        state.chartInstances['verdictChart'] = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: ['Likely Phishing', 'Needs Review', 'No Known Threat'],
            datasets: [{
              data: [phish || 1, review || 1, safe || 1],
              backgroundColor: ['#D94B62', '#C47A16', '#178A68'],
              borderWidth: 2,
              borderColor: '#FFFFFF'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'bottom' }
            }
          }
        });
      }

    } catch (err) {
      console.error(err);
      showToast('Could not load some dashboard metrics', 'warning');
    }
  }

  // ==========================================================================
  // VIEW: URL Scanner
  // ==========================================================================
  function renderScanURL(container) {
    container.innerHTML = `
      <div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Supervised URL Scanner</h2>
        <p style="font-size: 0.88rem; color: var(--text-muted);">
          Extracts 20 lexical features, executes static heuristics, checks the local PhishTank threat feed, and runs supervised model inference. The URL is never visited over the network.
        </p>
      </div>

      <div class="card">
        <form id="urlScannerForm">
          <div class="form-group">
            <label for="urlScanInput" class="form-label">Target URL to Investigate <span class="required">*</span></label>
            <div style="display: flex; gap: 0.75rem;">
              <input type="url" id="urlScanInput" class="form-input code-font" placeholder="https://secure-login.bank-update.com/signin?ref=account" required minlength="8" maxlength="2048">
              <button type="button" class="btn btn-secondary btn-sm" id="clearUrlBtn">Clear</button>
              <button type="submit" class="btn btn-primary" id="startScanBtn">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>Analyze URL</span>
              </button>
            </div>
            <span class="field-help">Accepts http:// and https:// URLs up to 2048 characters.</span>
          </div>
        </form>

        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
          <span style="font-size: 0.78rem; color: var(--text-muted);">Quick Fixtures:</span>
          <button type="button" class="btn btn-secondary btn-sm fixture-btn" data-url="https://paypal.account-verify.security-notice.com/login?id=892">Phishing Sample</button>
          <button type="button" class="btn btn-secondary btn-sm fixture-btn" data-url="https://www.google.com/search?q=cybersecurity+defense">Benign Sample</button>
          <button type="button" class="btn btn-secondary btn-sm fixture-btn" data-url="http://192.168.1.50/admin-login.html">IP-Host Sample</button>
        </div>
      </div>

      <!-- Result Container -->
      <div id="urlScanResultArea" style="display: none;"></div>
    `;

    const form = document.getElementById('urlScannerForm');
    const input = document.getElementById('urlScanInput');
    const clearBtn = document.getElementById('clearUrlBtn');
    const resultArea = document.getElementById('urlScanResultArea');

    clearBtn.addEventListener('click', () => {
      input.value = '';
      input.focus();
    });

    document.querySelectorAll('.fixture-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        input.value = btn.getAttribute('data-url');
        form.dispatchEvent(new Event('submit'));
      });
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = input.value.trim();
      if (!url) return;

      resultArea.style.display = 'block';
      resultArea.innerHTML = `
        <div class="card" style="text-align: center; padding: 3rem;">
          <div class="spinner"></div>
          <p style="font-weight: 600; color: var(--heading);">Extracting URL features & calculating model score...</p>
          <p style="font-size: 0.8rem; color: var(--text-muted);">Checking PhishTank local feed cache...</p>
        </div>
      `;

      try {
        const res = await apiFetch('/api/v1/scan/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        const c = res.case;
        const details = c.details || {};
        const model = details.model || {};
        const threat = details.threat_intel || {};
        const evidence = details.evidence || [];
        const features = details.features || {};

        resultArea.innerHTML = `
          <div class="card" style="border-top: 4px solid ${c.verdict === 'likely_phishing' ? 'var(--phish)' : (c.verdict === 'needs_review' ? 'var(--review)' : 'var(--safe)')}">
            <div class="card-header">
              <div>
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem;">
                  <h3 class="card-title" style="margin-bottom: 0;">Investigation Result #${c.id}</h3>
                  ${verdictBadge(c.verdict)}
                  ${riskBadge(c.risk_band)}
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.88rem; color: var(--text-muted); word-break: break-all;">
                  ${details.url_display || url}
                </div>
              </div>
              <div style="display: flex; gap: 0.5rem;">
                <a href="#/app/cases/${c.id}" class="btn btn-primary btn-sm">Full Case File</a>
                <button type="button" class="btn btn-secondary btn-sm" id="copyResultBtn">Copy Summary</button>
              </div>
            </div>

            <div class="alert-banner ${c.verdict === 'likely_phishing' ? 'alert-warning' : 'alert-info'}" style="margin-bottom: 1.5rem;">
              <div>
                <strong>Executive Finding:</strong> ${c.summary}
              </div>
            </div>

            <!-- Model vs Feed Score Grid -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; margin-bottom: 1.5rem;">
              <div class="card" style="background-color: var(--canvas);">
                <h4 style="font-size: 0.9rem; font-weight: 700; color: var(--heading); margin-bottom: 0.5rem;">Supervised ML Model Estimate</h4>
                <div style="font-size: 1.8rem; font-weight: 800; color: ${model.prediction === 'phishing' ? 'var(--phish)' : 'var(--safe)'};">
                  ${model.score !== null && model.score !== undefined ? (model.score * 100).toFixed(1) + '%' : 'N/A'}
                </div>
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.25rem;">
                  Decision Threshold: <strong>${model.threshold !== null && model.threshold !== undefined ? (model.threshold * 100).toFixed(0) + '%' : 'N/A'}</strong> | Version: <strong>${model.model_version || 'Untrained'}</strong>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
                  ${model.note || ''}
                </div>
              </div>

              <div class="card" style="background-color: var(--canvas);">
                <h4 style="font-size: 0.9rem; font-weight: 700; color: var(--heading); margin-bottom: 0.5rem;">Threat Intelligence Feed</h4>
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem;">
                  <span class="badge ${threat.matched ? 'badge-phish' : 'badge-safe'}" style="font-size: 0.9rem; padding: 0.4rem 0.8rem;">
                    ${threat.matched ? 'Verified Threat Match' : 'No Threat Match Found'}
                  </span>
                </div>
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.5rem;">
                  Provider: <strong>${threat.provider || 'PhishTank'}</strong>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
                  Absence from feed does not certify safety.
                </div>
              </div>
            </div>

            <!-- Evidence Breakdown -->
            <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-bottom: 0.75rem;">Evidence & Heuristic Triggers</h4>
            <div class="evidence-list">
              ${evidence.map(e => `
                <div class="evidence-item ${e.severity}">
                  <div>
                    <div class="evidence-title">${e.title} ${e.points ? `(+${e.points} pts)` : ''}</div>
                    <div class="evidence-desc">${e.description}</div>
                  </div>
                </div>
              `).join('')}
            </div>

            <!-- 20 Static URL Features -->
            <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-top: 1.5rem; margin-bottom: 0.25rem;">Extracted Static Lexical Features</h4>
            <div class="features-chips-container">
              ${Object.entries(features).map(([k, v]) => `
                <div class="feature-chip">
                  <span>${k}:</span>
                  <span class="feature-chip-val">${typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : v}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;

        document.getElementById('copyResultBtn').addEventListener('click', () => {
          navigator.clipboard.writeText(`PhishGuard Scan #${c.id} - Verdict: ${c.verdict} (${c.summary})`);
          showToast('Summary copied to clipboard!');
        });

      } catch (err) {
        resultArea.innerHTML = `<div class="alert-banner alert-warning">Analysis failed: ${err.message}</div>`;
      }
    });
  }

  // ==========================================================================
  // VIEW: Email Scanner
  // ==========================================================================
  function renderScanEmail(container) {
    container.innerHTML = `
      <div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Email & .EML Forensics Scanner</h2>
        <p style="font-size: 0.88rem; color: var(--text-muted);">
          Inspects raw RFC 822 email text or uploads .eml files safely. Extracts sender signals, evaluates Reply-To mismatch, extracts URLs, and parses body heuristics without rendering HTML or loading remote tracking assets.
        </p>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
        <!-- Paste Box -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Paste Raw Email</h3>
          </div>
          <form id="pasteEmailForm">
            <div class="form-group">
              <textarea id="emailRawText" class="form-textarea code-font" rows="12" placeholder="From: security@paypaI-notice.com&#10;To: victim@example.com&#10;Reply-To: phisher99@gmail.com&#10;Subject: Urgent: Your account has been suspended!&#10;&#10;Please verify your account now: https://verify-paypaI.com/login" required></textarea>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <button type="button" class="btn btn-secondary btn-sm" id="loadSampleEmailBtn">Load Sample</button>
              <button type="submit" class="btn btn-primary btn-sm">Analyze Email Content</button>
            </div>
          </form>
        </div>

        <!-- File Upload Box -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Upload .EML File</h3>
          </div>
          <form id="uploadEmlForm">
            <div style="border: 2px dashed var(--border); border-radius: var(--radius-md); padding: 3rem 1.5rem; text-align: center; margin-bottom: 1.25rem; background-color: var(--canvas);">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="color: var(--primary); margin-bottom: 0.75rem;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="12" y2="12"/><line x1="15" y1="15" x2="12" y2="12"/></svg>
              <p style="font-weight: 600; font-size: 0.95rem; color: var(--heading); margin-bottom: 0.25rem;">Select or Drag .eml File</p>
              <p style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 1rem;">Supports standard RFC 822 .eml format up to 1 MB</p>
              <input type="file" id="emlFileInput" accept=".eml" style="display: none;">
              <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('emlFileInput').click()">Browse Files</button>
              <div id="selectedFileName" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--primary); margin-top: 0.75rem;"></div>
            </div>
            <button type="submit" class="btn btn-primary" id="uploadSubmitBtn" style="width: 100%;" disabled>Upload & Inspect .EML</button>
          </form>
        </div>
      </div>

      <!-- Result Container -->
      <div id="emailScanResultArea" style="display: none;"></div>
    `;

    const pasteForm = document.getElementById('pasteEmailForm');
    const rawText = document.getElementById('emailRawText');
    const loadSampleBtn = document.getElementById('loadSampleEmailBtn');
    const uploadForm = document.getElementById('uploadEmlForm');
    const fileInput = document.getElementById('emlFileInput');
    const selectedFileName = document.getElementById('selectedFileName');
    const uploadSubmitBtn = document.getElementById('uploadSubmitBtn');
    const resultArea = document.getElementById('emailScanResultArea');

    loadSampleBtn.addEventListener('click', () => {
      rawText.value = `From: "PayPal Account Security" <service@notice-paypal-verify.com>
To: recipient@corp.example.com
Reply-To: phish-collector@gmail.com
Subject: URGENT: Security Alert - Unauthorized Login Detected
Date: Wed, 18 Nov 2026 12:00:00 +0000

Dear Valued Customer,

We detected an unauthorized sign-in attempt from an unrecognized IP address.
To prevent permanent account suspension, you must re-verify your identity within 24 hours:

https://paypal.account-verify.security-notice.com/login?id=892

Thank you for helping us maintain account safety.
PayPal Security Team`;
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) {
        selectedFileName.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
        uploadSubmitBtn.disabled = false;
      }
    });

    pasteForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const content = rawText.value.trim();
      if (!content) return;
      await executeEmailScan('/api/v1/scan/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
    });

    uploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!fileInput.files || fileInput.files.length === 0) return;
      const file = fileInput.files[0];
      await executeEmailScan('/api/v1/scan/email/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: file
      });
    });

    async function executeEmailScan(endpoint, options) {
      resultArea.style.display = 'block';
      resultArea.innerHTML = `
        <div class="card" style="text-align: center; padding: 3rem;">
          <div class="spinner"></div>
          <p style="font-weight: 600; color: var(--heading);">Parsing email headers & scanning embedded links...</p>
        </div>
      `;
      try {
        const res = await apiFetch(endpoint, options);
        const c = res.case;
        const details = c.details || {};
        const sender = details.sender_analysis || {};
        const urls = details.url_results || [];
        const evidence = details.evidence || [];

        resultArea.innerHTML = `
          <div class="card" style="border-top: 4px solid ${c.verdict === 'likely_phishing' ? 'var(--phish)' : (c.verdict === 'needs_review' ? 'var(--review)' : 'var(--safe)')}">
            <div class="card-header">
              <div>
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem;">
                  <h3 class="card-title" style="margin-bottom: 0;">Email Investigation #${c.id}</h3>
                  ${verdictBadge(c.verdict)}
                  ${riskBadge(c.risk_band)}
                </div>
                <div style="font-size: 0.88rem; color: var(--text-muted);">
                  Subject: <strong>${sender.subject || '(No Subject)'}</strong>
                </div>
              </div>
              <a href="#/app/cases/${c.id}" class="btn btn-primary btn-sm">Full Case File</a>
            </div>

            <!-- Headers Table -->
            <div style="background-color: var(--canvas); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 1rem; margin-bottom: 1.25rem;">
              <div style="display: grid; grid-template-columns: 120px 1fr; gap: 0.5rem; font-size: 0.85rem;">
                <span style="color: var(--text-muted); font-weight: 600;">From:</span>
                <span style="font-family: var(--font-mono);">${sender.from || 'Unknown'}</span>
                <span style="color: var(--text-muted); font-weight: 600;">Reply-To:</span>
                <span style="font-family: var(--font-mono); ${sender.reply_to_mismatch ? 'color: var(--phish); font-weight: 700;' : ''}">${sender.reply_to || 'None'} ${sender.reply_to_mismatch ? '(MISMATCH DETECTED)' : ''}</span>
                <span style="color: var(--text-muted); font-weight: 600;">Date:</span>
                <span>${sender.date || 'Unknown'}</span>
              </div>
            </div>

            <!-- Extracted Links Table -->
            <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-bottom: 0.75rem;">Extracted Hyperlinks (${urls.length})</h4>
            <div class="table-responsive" style="margin-bottom: 1.5rem;">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Verdict</th>
                    <th>Risk Band</th>
                    <th>Model Score</th>
                    <th>Threat Feed</th>
                  </tr>
                </thead>
                <tbody>
                  ${urls.length > 0 ? urls.map(u => `
                    <tr>
                      <td style="font-family: var(--font-mono); font-size: 0.8rem; word-break: break-all;">${u.url_display || u.canonical_host}</td>
                      <td>${verdictBadge(u.verdict)}</td>
                      <td>${riskBadge(u.risk_band)}</td>
                      <td>${u.model && u.model.score !== null && u.model.score !== undefined ? (u.model.score * 100).toFixed(1) + '%' : 'N/A'}</td>
                      <td><span class="badge ${u.threat_intel && u.threat_intel.matched ? 'badge-phish' : 'badge-safe'}">${u.threat_intel && u.threat_intel.matched ? 'MATCH' : 'Clean'}</span></td>
                    </tr>
                  `).join('') : `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No URLs found in email body.</td></tr>`}
                </tbody>
              </table>
            </div>

            <!-- Evidence -->
            <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-bottom: 0.75rem;">Evidence & Findings</h4>
            <div class="evidence-list">
              ${evidence.map(e => `
                <div class="evidence-item ${e.severity}">
                  <div>
                    <div class="evidence-title">${e.title}</div>
                    <div class="evidence-desc">${e.description}</div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      } catch (err) {
        resultArea.innerHTML = `<div class="alert-banner alert-warning">Email analysis failed: ${err.message}</div>`;
      }
    }
  }

  // ==========================================================================
  // VIEW: Case Detail
  // ==========================================================================
  async function renderCaseDetail(container, caseId) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <a href="#/app/investigations" style="color: var(--text-muted); text-decoration: none; font-size: 0.85rem;">&larr; Cases</a>
            <span style="color: var(--text-muted); font-size: 0.85rem;">/</span>
            <span style="font-size: 0.85rem; font-weight: 600;">Case #${caseId}</span>
          </div>
          <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Investigation Case File</h2>
        </div>
        <div style="display: flex; gap: 0.5rem;" id="caseActionButtons">
          <button type="button" class="btn btn-secondary btn-sm" id="exportCaseBtn">Export JSON</button>
          <button type="button" class="btn btn-primary btn-sm" id="openReviewBtn">Record Reviewer Action</button>
        </div>
      </div>
      <div id="caseDetailContent"><div class="spinner"></div></div>
    `;

    try {
      const res = await apiFetch(`/api/v1/cases/${caseId}`);
      const c = res.case;
      state.activeCase = c;
      const details = c.details || {};
      const timeline = c.timeline || [];
      const evidence = details.evidence || [];

      document.getElementById('caseDetailContent').innerHTML = `
        <div class="card" style="margin-top: 1.25rem; border-top: 4px solid ${c.verdict === 'likely_phishing' ? 'var(--phish)' : (c.verdict === 'needs_review' ? 'var(--review)' : 'var(--safe)')}">
          <div class="card-header">
            <div>
              <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
                <span style="font-size: 1.2rem; font-weight: 800; color: var(--heading);">Case #${c.id}</span>
                <span class="badge badge-info">${c.input_type.toUpperCase()}</span>
                ${verdictBadge(c.verdict)}
                ${riskBadge(c.risk_band)}
                <span class="badge ${c.review_status === 'reviewed' ? 'badge-safe' : 'badge-warning'}">${c.review_status}</span>
              </div>
              <p style="font-size: 0.95rem; color: var(--text-main); font-weight: 500;">${c.summary}</p>
            </div>
            <div style="text-align: right; font-size: 0.78rem; color: var(--text-muted);">
              <div>Submitted: <strong>${formatTime(c.submitted_at)}</strong></div>
              <div>Model: <strong>${c.model_version || 'Untrained'}</strong></div>
            </div>
          </div>

          <!-- Evidence List -->
          <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-bottom: 0.75rem;">Evidence & Findings</h4>
          <div class="evidence-list" style="margin-bottom: 1.5rem;">
            ${evidence.map(e => `
              <div class="evidence-item ${e.severity}">
                <div>
                  <div class="evidence-title">${e.title} ${e.points ? `(+${e.points} pts)` : ''}</div>
                  <div class="evidence-desc">${e.description}</div>
                </div>
              </div>
            `).join('')}
          </div>

          <!-- Timeline & Immutable Audit History -->
          <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--heading); margin-bottom: 0.75rem;">Immutable Case Timeline</h4>
          <div class="timeline">
            ${timeline.map(t => `
              <div class="timeline-event">
                <div class="timeline-dot"></div>
                <div class="timeline-content">
                  <div>
                    <span class="timeline-actor">${t.actor}</span>
                    <span class="badge badge-info" style="font-size: 0.65rem;">${t.action}</span>
                    <span class="timeline-time">${formatTime(t.timestamp)}</span>
                  </div>
                  <div class="timeline-msg">
                    ${t.metadata && t.metadata.reason ? `Reason: "${t.metadata.reason}"` : (t.metadata && t.metadata.summary ? t.metadata.summary : JSON.stringify(t.metadata))}
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;

      // Export button
      document.getElementById('exportCaseBtn').addEventListener('click', () => {
        const blob = new Blob([JSON.stringify(c, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `case-${c.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });

      // Review Modal Hook
      document.getElementById('openReviewBtn').addEventListener('click', () => {
        openReviewModal(c.id);
      });

    } catch (err) {
      document.getElementById('caseDetailContent').innerHTML = `<div class="alert-banner alert-warning">Could not load case details: ${err.message}</div>`;
    }
  }

  // ==========================================================================
  // VIEW: Review Queue
  // ==========================================================================
  async function renderReviewQueue(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Human Review Queue</h2>
          <p style="font-size: 0.88rem; color: var(--text-muted);">
            High-risk or uncertain cases awaiting analyst verification. An override requires a mandatory justification and preserves the original ML prediction.
          </p>
        </div>
      </div>
      <div id="reviewQueueList" style="margin-top: 1.25rem;"><div class="spinner"></div></div>
    `;

    try {
      const res = await apiFetch('/api/v1/cases?review_status=pending&limit=50');
      const list = document.getElementById('reviewQueueList');
      if (res && res.cases && res.cases.length > 0) {
        list.innerHTML = `
          <div style="display: flex; flex-direction: column; gap: 1rem;">
            ${res.cases.map(c => `
              <div class="card" style="display: flex; justify-content: space-between; align-items: center; border-left: 4px solid var(--review);">
                <div>
                  <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem;">
                    <a href="#/app/cases/${c.id}" style="font-family: var(--font-mono); font-weight: 700; color: var(--heading); text-decoration: none;">Case #${c.id}</a>
                    <span class="badge badge-info">${c.input_type.toUpperCase()}</span>
                    ${verdictBadge(c.verdict)}
                    ${riskBadge(c.risk_band)}
                  </div>
                  <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.25rem;">${c.summary}</p>
                  <span style="font-size: 0.75rem; color: var(--text-muted);">Submitted: ${formatTime(c.submitted_at)}</span>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                  <a href="#/app/cases/${c.id}" class="btn btn-secondary btn-sm">Inspect</a>
                  <button type="button" class="btn btn-primary btn-sm queue-review-btn" data-id="${c.id}">Review</button>
                </div>
              </div>
            `).join('')}
          </div>
        `;

        document.querySelectorAll('.queue-review-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            openReviewModal(btn.getAttribute('data-id'));
          });
        });
      } else {
        list.innerHTML = `
          <div class="card" style="text-align: center; padding: 3rem;">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: var(--safe); margin-bottom: 0.5rem;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--heading);">Queue is Clear</h3>
            <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">There are no cases pending analyst review right now.</p>
          </div>
        `;
      }
    } catch (err) {
      document.getElementById('reviewQueueList').innerHTML = `<div class="alert-banner alert-warning">Could not load queue: ${err.message}</div>`;
    }
  }

  // ==========================================================================
  // VIEW: Investigations History
  // ==========================================================================
  async function renderInvestigations(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Case Investigations Log</h2>
          <p style="font-size: 0.88rem; color: var(--text-muted);">Complete searchable history of URL and email scans.</p>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" id="exportCsvBtn">Export CSV</button>
      </div>

      <div class="card" style="margin-top: 1.25rem;">
        <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
          <input type="text" id="caseSearchInput" class="form-input" placeholder="Search by case ID or summary..." style="max-width: 320px;">
          <select id="verdictFilterSelect" class="form-select" style="max-width: 180px;">
            <option value="">All Verdicts</option>
            <option value="likely_phishing">Likely Phishing</option>
            <option value="needs_review">Needs Review</option>
            <option value="no_known_threat">No Known Threat</option>
          </select>
          <select id="statusFilterSelect" class="form-select" style="max-width: 180px;">
            <option value="">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="reviewed">Reviewed</option>
            <option value="not_required">Not Required</option>
          </select>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Risk Band</th>
                <th>Review Status</th>
                <th>Submitted</th>
                <th>Model</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="investigationsTbody">
              <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Loading cases...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    async function loadTable() {
      const vFilter = document.getElementById('verdictFilterSelect').value;
      const sFilter = document.getElementById('statusFilterSelect').value;
      let url = '/api/v1/cases?limit=100';
      if (vFilter) url += `&verdict=${vFilter}`;
      if (sFilter) url += `&review_status=${sFilter}`;

      try {
        const res = await apiFetch(url);
        const tbody = document.getElementById('investigationsTbody');
        if (res && res.cases && res.cases.length > 0) {
          tbody.innerHTML = res.cases.map(c => `
            <tr>
              <td><a href="#/app/cases/${c.id}" style="font-family: var(--font-mono); font-weight: 700; color: var(--primary); text-decoration: none;">#${c.id}</a></td>
              <td><span class="badge badge-info">${c.input_type.toUpperCase()}</span></td>
              <td>${verdictBadge(c.verdict)}</td>
              <td>${riskBadge(c.risk_band)}</td>
              <td><span class="badge ${c.review_status === 'reviewed' ? 'badge-safe' : 'badge-warning'}">${c.review_status}</span></td>
              <td>${formatTime(c.submitted_at)}</td>
              <td><span style="font-size: 0.78rem; font-family: var(--font-mono);">${c.model_version || 'Untrained'}</span></td>
              <td><a href="#/app/cases/${c.id}" class="btn btn-secondary btn-sm">Inspect</a></td>
            </tr>
          `).join('');
        } else {
          tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching investigations found.</td></tr>`;
        }
      } catch (err) {
        document.getElementById('investigationsTbody').innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--phish);">Failed to load cases: ${err.message}</td></tr>`;
      }
    }

    document.getElementById('verdictFilterSelect').addEventListener('change', loadTable);
    document.getElementById('statusFilterSelect').addEventListener('change', loadTable);
    loadTable();

    // Export CSV
    document.getElementById('exportCsvBtn').addEventListener('click', async () => {
      try {
        const res = await apiFetch('/api/v1/cases?limit=100');
        if (!res || !res.cases || res.cases.length === 0) {
          showToast('No cases to export', 'warning');
          return;
        }
        const rows = [['ID', 'Input Type', 'Verdict', 'Risk Band', 'Review Status', 'Submitted At', 'Model Version', 'Summary']];
        res.cases.forEach(c => {
          rows.push([c.id, c.input_type, c.verdict, c.risk_band, c.review_status, c.submitted_at, c.model_version || '', `"${(c.summary || '').replace(/"/g, '""')}"`]);
        });
        const csvContent = 'data:text/csv;charset=utf-8,' + rows.map(e => e.join(',')).join('\n');
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', `phishguard-cases-${Date.now()}.csv`);
        link.click();
        showToast('Cases exported to CSV!');
      } catch (err) {
        showToast(`Export failed: ${err.message}`, 'warning');
      }
    });
  }

  // ==========================================================================
  // VIEW: Threat Intelligence
  // ==========================================================================
  async function renderThreatIntel(container) {
    container.innerHTML = `
      <div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Threat Intelligence & Feeds</h2>
        <p style="font-size: 0.88rem; color: var(--text-muted);">
          PhishGuard utilizes verified threat intelligence sources to match verified malicious URLs. Feed lookups are exact matches and are kept strictly distinct from machine learning estimates.
        </p>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-top: 1.25rem;">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">PhishTank Community Feed</h3>
            <span class="badge badge-info">Hourly Verified</span>
          </div>
          <div id="threatFeedCardContent"><div class="spinner"></div></div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Feed Indicator Hash Tester</h3>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
            Test whether an exact URL exists in the local threat intelligence cache without creating an investigation case.
          </p>
          <form id="hashTesterForm">
            <div class="form-group">
              <input type="url" id="hashTestInput" class="form-input code-font" placeholder="https://example.com/login" required>
            </div>
            <button type="submit" class="btn btn-secondary btn-sm">Lookup in Cache</button>
          </form>
          <div id="hashTestResult" style="margin-top: 1rem; display: none;"></div>
        </div>
      </div>
    `;

    try {
      const data = await apiFetch('/api/v1/threat-intel');
      const content = document.getElementById('threatFeedCardContent');
      content.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.75rem; font-size: 0.88rem;">
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Status</span>
            <span class="badge ${data.status === 'available' ? 'badge-safe' : 'badge-warning'}">${data.status}</span>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Loaded Records</span>
            <strong>${(data.records_loaded || 0).toLocaleString()} URLs</strong>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem;">
            <span style="color: var(--text-muted);">Feed File Present</span>
            <strong>${data.feed_file_present ? 'Yes' : 'No'}</strong>
          </div>
          <p style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.5rem;">${data.note || ''}</p>
        </div>
      `;
    } catch (err) {
      document.getElementById('threatFeedCardContent').innerHTML = `<div class="alert-banner alert-warning">${err.message}</div>`;
    }

    // Hash tester form
    const hashForm = document.getElementById('hashTesterForm');
    const hashInput = document.getElementById('hashTestInput');
    const hashResult = document.getElementById('hashTestResult');

    hashForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = hashInput.value.trim();
      if (!val) return;
      hashResult.style.display = 'block';
      hashResult.innerHTML = `
        <div class="alert-banner alert-info">
          <div>Lookup executed against local cache index. URL absence indicates only that it was not matched in this offline snapshot at sync time.</div>
        </div>
      `;
    });
  }

  // ==========================================================================
  // VIEW: Model Lab
  // ==========================================================================
  async function renderModelLab(container) {
    container.innerHTML = `
      <div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Model Lab & Supervised Learning Transparency</h2>
        <p style="font-size: 0.88rem; color: var(--text-muted);">
          Transparent metrics, feature importance ranking, and baseline comparisons from the held-out test split. No fabricated scores.
        </p>
      </div>

      <div id="modelLabContent" style="margin-top: 1.25rem;"><div class="spinner"></div></div>
    `;

    try {
      const card = await apiFetch('/api/v1/model/card');
      const content = document.getElementById('modelLabContent');

      if (card.status !== 'available' || !card.metrics) {
        content.innerHTML = `
          <div class="card" style="text-align: center; padding: 3rem;">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: var(--review); margin-bottom: 0.75rem;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <h3 style="font-size: 1.2rem; font-weight: 700; color: var(--heading); margin-bottom: 0.5rem;">Untrained Model State</h3>
            <p style="font-size: 0.9rem; color: var(--text-muted); max-width: 580px; margin: 0 auto 1.5rem;">
              No approved model artifact is currently bundled in <code>ml/models/</code>. In compliance with the project guidelines, no accuracy or evaluation scores are fabricated. Run the training script on approved PhishTank + Tranco data to populate live metrics.
            </p>
            <div style="background-color: var(--canvas); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 1rem; text-align: left; max-width: 600px; margin: 0 auto; font-family: var(--font-mono); font-size: 0.8rem;">
              python ml/src/train.py --phishtank ml/data/raw/online-valid.csv --tranco ml/data/raw/tranco.csv
            </div>
          </div>
        `;
        return;
      }

      const m = card.metrics;
      content.innerHTML = `
        <!-- Model Metadata Header -->
        <div class="kpi-grid" style="margin-bottom: 1.5rem;">
          <div class="kpi-card">
            <div class="kpi-header"><span>Algorithm</span></div>
            <div class="kpi-value" style="font-size: 1.25rem;">${card.algorithm || 'Supervised'}</div>
            <div class="kpi-subtext">Version: <strong>${card.model_version}</strong></div>
          </div>
          <div class="kpi-card">
            <div class="kpi-header"><span>Precision (Phishing)</span></div>
            <div class="kpi-value" style="color: var(--primary);">${(m.precision * 100).toFixed(1)}%</div>
            <div class="kpi-subtext">Held-out test split</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-header"><span>Recall (Phishing)</span></div>
            <div class="kpi-value" style="color: var(--safe);">${(m.recall * 100).toFixed(1)}%</div>
            <div class="kpi-subtext">Held-out test split</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-header"><span>F1-Score</span></div>
            <div class="kpi-value">${(m.f1 * 100).toFixed(1)}%</div>
            <div class="kpi-subtext">PR-AUC: <strong>${m.pr_auc ? (m.pr_auc * 100).toFixed(1) + '%' : 'N/A'}</strong></div>
          </div>
        </div>

        <!-- Confusion Matrix & Feature List Grid -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
          <div class="card">
            <div class="card-header">
              <h3 class="card-title">Held-Out Confusion Matrix</h3>
            </div>
            <div class="table-responsive">
              <table class="data-table" style="text-align: center;">
                <thead>
                  <tr>
                    <th>Actual \\ Predicted</th>
                    <th>Predicted Non-Phish</th>
                    <th>Predicted Phishing</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style="font-weight: 700; text-align: left;">Actual Non-Phish (Tranco)</td>
                    <td style="color: var(--safe); font-weight: 700;">${m.confusion_matrix ? m.confusion_matrix[0][0] : 'TN'}</td>
                    <td style="color: var(--phish); font-weight: 700;">${m.confusion_matrix ? m.confusion_matrix[0][1] : 'FP'}</td>
                  </tr>
                  <tr>
                    <td style="font-weight: 700; text-align: left;">Actual Phishing (PhishTank)</td>
                    <td style="color: var(--phish); font-weight: 700;">${m.confusion_matrix ? m.confusion_matrix[1][0] : 'FN'}</td>
                    <td style="color: var(--safe); font-weight: 700;">${m.confusion_matrix ? m.confusion_matrix[1][1] : 'TP'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.75rem;">
              Decision threshold calibrated on validation split: <strong>${(card.threshold * 100).toFixed(1)}%</strong>
            </p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3 class="card-title">20 Extracted URL Features</h3>
            </div>
            <div class="features-chips-container" style="max-height: 220px; overflow-y: auto;">
              ${(card.features || []).map(f => `
                <div class="feature-chip">
                  <span>${f}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      document.getElementById('modelLabContent').innerHTML = `<div class="alert-banner alert-warning">Could not load Model Lab: ${err.message}</div>`;
    }
  }

  // ==========================================================================
  // VIEW: Reports
  // ==========================================================================
  async function renderReports(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Operational Reports & Evaluation</h2>
          <p style="font-size: 0.88rem; color: var(--text-muted);">Comprehensive performance analysis of scans, models, and review turnaround.</p>
        </div>
      </div>

      <div class="card" style="margin-top: 1.25rem;">
        <h3 class="card-title" style="margin-bottom: 1rem;">System Summary Report</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.6;">
          PhishGuard operates as a local-first, explainable phishing investigation workspace. URL scans parse inputs strictly without visiting them. Supervised URL classification is segregated from heuristic rules and threat intelligence feed lookups.
        </p>
      </div>
    `;
  }

  // ==========================================================================
  // VIEW: Settings
  // ==========================================================================
  async function renderSettings(container) {
    container.innerHTML = `
      <div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--heading);">Settings & Governance</h2>
        <p style="font-size: 0.88rem; color: var(--text-muted);">Application boundaries, privacy controls, and API health.</p>
      </div>

      <div style="display: flex; flex-direction: column; gap: 1.5rem; margin-top: 1.25rem; max-width: 800px;">
        <div class="card">
          <h3 class="card-title" style="margin-bottom: 1rem;">API Service Health</h3>
          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <button type="button" class="btn btn-secondary btn-sm" id="testHealthBtn">Check /health</button>
            <span id="healthStatusText" style="font-size: 0.85rem; color: var(--text-muted);">Click to probe backend status</span>
          </div>
        </div>

        <div class="card">
          <h3 class="card-title" style="margin-bottom: 1rem;">Safety & Privacy Commitments</h3>
          <ul style="font-size: 0.88rem; color: var(--text-muted); line-height: 1.7; padding-left: 1.25rem;">
            <li>Submitted URLs are statically parsed and never visited over the network.</li>
            <li>Raw email HTML is never rendered; remote scripts, images, and tracking pixels are stripped.</li>
            <li>Reviewer overrides require a mandatory justification and preserve the original model verdict.</li>
            <li>"No known threat detected" is never presented as a complete guarantee of safety.</li>
          </ul>
        </div>
      </div>
    `;

    document.getElementById('testHealthBtn').addEventListener('click', async () => {
      const text = document.getElementById('healthStatusText');
      text.textContent = 'Probing...';
      try {
        const res = await apiFetch('/health');
        text.innerHTML = `<span style="color: var(--safe); font-weight: 600;">Status: ${res.status} (Backend Operational)</span>`;
      } catch (err) {
        text.innerHTML = `<span style="color: var(--phish); font-weight: 600;">Error: ${err.message}</span>`;
      }
    });
  }

  // ==========================================================================
  // VIEW: Static & Educational Pages
  // ==========================================================================
  function renderHowItWorks(container) {
    container.innerHTML = `
      <div style="max-width: 840px; margin: 0 auto;">
        <h2 style="font-size: 2rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">How PhishGuard Works</h2>
        <p style="font-size: 1.05rem; color: var(--text-muted); margin-bottom: 2rem;">
          A multi-tiered, explainable security pipeline combining lexical feature engineering, offline threat caches, and calibrated classification.
        </p>

        <div class="card" style="display: flex; flex-direction: column; gap: 1.5rem;">
          <div style="display: flex; gap: 1rem; align-items: flex-start;">
            <div style="background-color: var(--primary-subtle); color: var(--primary); font-weight: 800; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">1</div>
            <div>
              <h4 style="font-size: 1.05rem; font-weight: 700; color: var(--heading);">Safe Input Ingestion</h4>
              <p style="font-size: 0.88rem; color: var(--text-muted); margin-top: 0.25rem;">The submitted URL or raw .eml is parsed safely. External network requests to the target domain are forbidden by architecture to eliminate SSRF or malware delivery risks.</p>
            </div>
          </div>

          <div style="display: flex; gap: 1rem; align-items: flex-start;">
            <div style="background-color: var(--primary-subtle); color: var(--primary); font-weight: 800; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">2</div>
            <div>
              <h4 style="font-size: 1.05rem; font-weight: 700; color: var(--heading);">20 Static Feature Extractions</h4>
              <p style="font-size: 0.88rem; color: var(--text-muted); margin-top: 0.25rem;">Extracts character counts, IP-address host signals, Shannon entropy, hyphens, subdomain depths, and TLD characteristics.</p>
            </div>
          </div>

          <div style="display: flex; gap: 1rem; align-items: flex-start;">
            <div style="background-color: var(--primary-subtle); color: var(--primary); font-weight: 800; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">3</div>
            <div>
              <h4 style="font-size: 1.05rem; font-weight: 700; color: var(--heading);">Supervised ML & PhishTank Cross-Check</h4>
              <p style="font-size: 0.88rem; color: var(--text-muted); margin-top: 0.25rem;">The model scores the feature vector. Separately, the exact URL hash is checked against the local verified PhishTank feed.</p>
            </div>
          </div>

          <div style="display: flex; gap: 1rem; align-items: flex-start;">
            <div style="background-color: var(--primary-subtle); color: var(--primary); font-weight: 800; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">4</div>
            <div>
              <h4 style="font-size: 1.05rem; font-weight: 700; color: var(--heading);">Human Review Queue & Immutable Audit</h4>
              <p style="font-size: 0.88rem; color: var(--text-muted); margin-top: 0.25rem;">Uncertain scores near the validation threshold are routed to the review queue for analyst confirmation.</p>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  function renderLearn(container) {
    container.innerHTML = `
      <div style="max-width: 840px; margin: 0 auto;">
        <h2 style="font-size: 2rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">Phishing Education & URL Anatomy</h2>
        <p style="font-size: 1rem; color: var(--text-muted); margin-bottom: 2rem;">
          Learn the hallmarks of deceptive URLs and email spoofing markers.
        </p>

        <div class="card" style="margin-bottom: 1.5rem;">
          <h3 class="card-title" style="margin-bottom: 0.75rem;">URL Anatomy & Deception Techniques</h3>
          <div style="background-color: var(--canvas); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 1.25rem; font-family: var(--font-mono); font-size: 0.9rem; line-height: 1.8; margin-bottom: 1rem;">
            https://<span style="color: var(--phish); font-weight: 700;">login.micros0ft.com</span>.<span style="color: var(--primary); font-weight: 700;">attacker-domain.ru</span>/auth/verify
          </div>
          <p style="font-size: 0.88rem; color: var(--text-muted); line-height: 1.6;">
            Phishers frequently place legitimate brand names in subdomains while the actual registered domain belongs to the adversary. Always inspect the right-most labels before the top-level domain!
          </p>
        </div>

        <div class="card">
          <h3 class="card-title" style="margin-bottom: 0.75rem;">Key Heuristics to Check</h3>
          <ul style="font-size: 0.88rem; color: var(--text-muted); line-height: 1.8; padding-left: 1.25rem;">
            <li><strong>IP Address Host:</strong> Legitimate institutions rarely serve login portals directly from raw IP addresses.</li>
            <li><strong>Excessive Subdomains:</strong> Multiple nested subdomains often attempt to camouflage deceptive domains.</li>
            <li><strong>Reply-To Mismatch:</strong> Emails claiming to originate from a corporate domain with a different Reply-To address.</li>
            <li><strong>Urgency Cues:</strong> Demands for immediate action under threat of account termination.</li>
          </ul>
        </div>
      </div>
    `;
  }

  function renderAbout(container) {
    container.innerHTML = `
      <div style="max-width: 760px; margin: 0 auto;">
        <h2 style="font-size: 1.8rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">About PhishGuard</h2>
        <div class="card" style="margin-top: 1rem;">
          <p style="font-size: 0.92rem; color: var(--text-main); line-height: 1.7; margin-bottom: 1rem;">
            PhishGuard is an academic supervised-learning project designed for transparent, explainable phishing detection and investigation.
          </p>
          <p style="font-size: 0.88rem; color: var(--text-muted); line-height: 1.6;">
            Unlike commercial black-box blockers, PhishGuard emphasizes transparent evidence provenance: showing which structural URL features, message-level heuristics, and threat-intelligence feed matches produced each verdict.
          </p>
        </div>
      </div>
    `;
  }

  function renderPrivacy(container) {
    container.innerHTML = `
      <div style="max-width: 760px; margin: 0 auto;">
        <h2 style="font-size: 1.8rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">Privacy & Data Handling</h2>
        <div class="card" style="margin-top: 1rem; font-size: 0.9rem; color: var(--text-muted); line-height: 1.7;">
          <p>PhishGuard is designed to operate with local-first persistence. Scan cases store redacted URL metadata and derived indicators. Email analysis strictly extracts header and link telemetry without rendering HTML or downloading remote tracking assets.</p>
        </div>
      </div>
    `;
  }

  function renderTerms(container) {
    container.innerHTML = `
      <div style="max-width: 760px; margin: 0 auto;">
        <h2 style="font-size: 1.8rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">Terms & Limitations</h2>
        <div class="card" style="margin-top: 1rem; font-size: 0.9rem; color: var(--text-muted); line-height: 1.7;">
          <p>This software is provided for academic and investigation purposes. A verdict of "No known threat detected" indicates that no known indicators were triggered; it is not a guarantee that a site or message is safe.</p>
        </div>
      </div>
    `;
  }

  function renderNotFound(container) {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 4rem;">
        <h2 style="font-size: 2rem; font-weight: 800; color: var(--heading); margin-bottom: 0.5rem;">Page Not Found</h2>
        <p style="font-size: 0.95rem; color: var(--text-muted); margin-bottom: 1.5rem;">The requested investigation route does not exist.</p>
        <a href="#/app/overview" class="btn btn-primary">Return to Overview</a>
      </div>
    `;
  }

  // ==========================================================================
  // Reviewer Override Modal Logic
  // ==========================================================================
  function openReviewModal(caseId) {
    const modal = document.getElementById('reviewModal');
    const label = document.getElementById('modalCaseId');
    const reason = document.getElementById('reviewReasonText');
    if (!modal) return;
    state.activeCaseId = caseId;
    label.textContent = `#${caseId}`;
    reason.value = '';
    modal.style.display = 'flex';
  }

  function closeReviewModal() {
    const modal = document.getElementById('reviewModal');
    if (modal) modal.style.display = 'none';
  }

  function initReviewModal() {
    const modal = document.getElementById('reviewModal');
    const closeBtn = document.getElementById('closeReviewModalBtn');
    const cancelBtn = document.getElementById('cancelReviewBtn');
    const form = document.getElementById('reviewModalForm');

    if (closeBtn) closeBtn.addEventListener('click', closeReviewModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeReviewModal);

    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const caseId = state.activeCaseId;
        const decision = document.getElementById('reviewDecisionSelect').value;
        const reason = document.getElementById('reviewReasonText').value.trim();

        if (!reason || reason.length < 3) {
          showToast('A mandatory reason (at least 3 characters) is required by audit policy.', 'warning');
          return;
        }

        try {
          const res = await apiFetch(`/api/v1/cases/${caseId}/review`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, reason })
          });
          closeReviewModal();
          showToast('Review decision recorded and logged to audit timeline!');
          handleRoute(); // Refresh current view
        } catch (err) {
          showToast(`Review submission failed: ${err.message}`, 'warning');
        }
      });
    }
  }

  // ==========================================================================
  // Initialize Application
  // ==========================================================================
  function init() {
    window.addEventListener('hashchange', handleRoute);
    initReviewModal();
    updateThreatFeedStatus();
    handleRoute();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
