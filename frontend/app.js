/**
 * LeakGuard Static Analyzer Dashboard Controller
 * Connects frontend UI to live Python AST analyzer via /api/scan and manages dashboard states.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Action Controls
  const btnScan = document.getElementById('btn-scan');
  const btnScanText = document.getElementById('btn-scan-text');
  const scanTargetSelect = document.getElementById('scan-target-select');
  const btnUploadFile = document.getElementById('btn-upload-file');
  const inputUploadFile = document.getElementById('input-upload-file');
  const btnUploadFolder = document.getElementById('btn-upload-folder');
  const inputUploadFolder = document.getElementById('input-upload-folder');
  const btnClear = document.getElementById('btn-clear');
  const dropzone = document.getElementById('dropzone');

  // DOM Elements - Status Banner
  const statusBanner = document.getElementById('scan-status-banner');
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusDesc = document.getElementById('status-desc');
  const statusProgressSteps = document.getElementById('status-progress-steps');
  const statusStepText = document.getElementById('status-step-text');

  // DOM Elements - Last Scan Info
  const lastScanText = document.getElementById('last-scan-text');
  const lastScanDuration = document.getElementById('last-scan-duration');

  // DOM Elements - Metrics
  const valScanned = document.getElementById('val-scanned');
  const valClean = document.getElementById('val-clean');
  const valSyntax = document.getElementById('val-syntax-errors');
  const valLeaks = document.getElementById('val-leaks');

  // DOM Elements - Findings & Syntax
  const findingsContainer = document.getElementById('findings-container');
  const findingsCountBadge = document.getElementById('findings-count');
  const syntaxPanel = document.getElementById('syntax-panel');
  const syntaxList = document.getElementById('syntax-list');
  const syntaxCountBadge = document.getElementById('syntax-count');

  // DOM Elements - Files Table
  const tbody = document.getElementById('results-tbody');
  const filesCountBadge = document.getElementById('results-count');

  // Runtime State
  let isScanning = false;

  /**
   * Format browser local time for "Last Scan" indicator
   */
  function formatLocalTime(date) {
    try {
      const options = {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      };
      return new Intl.DateTimeFormat(undefined, options).format(date);
    } catch (e) {
      return date.toLocaleTimeString();
    }
  }

  /**
   * Helper: Escape HTML to avoid injection
   */
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Set Status Banner State: NOT_SCANNED, SCANNING, PASS, FAILED, or ERROR
   */
  function setStatus(state, details = {}) {
    if (!statusBanner) return;
    statusBanner.className = 'status-banner';
    if (statusProgressSteps) statusProgressSteps.style.display = 'none';

    switch (state) {
      case 'NOT_SCANNED':
        statusBanner.classList.add('status-not-scanned');
        if (statusIcon) statusIcon.textContent = '○';
        if (statusTitle) statusTitle.textContent = 'NOT SCANNED';
        if (statusDesc) statusDesc.textContent = 'Run a Python project scan to begin.';
        break;

      case 'SCANNING':
        statusBanner.classList.add('status-scanning');
        if (statusIcon) statusIcon.innerHTML = '<div class="spinner"></div>';
        if (statusTitle) statusTitle.textContent = 'SCANNING PYTHON PROJECT...';
        if (statusDesc) statusDesc.textContent = details.desc || 'Analyzing Python AST and tracing resource lifecycles...';
        if (statusProgressSteps) {
          statusProgressSteps.style.display = 'flex';
          if (statusStepText) statusStepText.textContent = details.step || 'Scanning Python files...';
        }
        break;

      case 'PASS':
        statusBanner.classList.add('status-pass');
        if (statusIcon) statusIcon.textContent = '✅';
        if (statusTitle) statusTitle.textContent = 'PASS — No Blocking Leaks';
        if (statusDesc) statusDesc.textContent = 'All Python files parsed cleanly. Zero resource leaks detected.';
        break;

      case 'FAILED':
        statusBanner.classList.add('status-failed');
        if (statusIcon) statusIcon.textContent = '❌';
        const leakCount = details.leaksCount !== undefined ? details.leaksCount : 1;
        const leakLabel = leakCount === 1 ? '1 Resource Leak' : `${leakCount} Resource Leaks`;
        if (statusTitle) statusTitle.textContent = `FAILED — ${leakLabel}`;
        if (statusDesc) statusDesc.textContent = `${leakLabel} detected in scanned Python code. Remediation required.`;
        break;

      case 'ERROR':
        statusBanner.classList.add('status-failed');
        if (statusIcon) statusIcon.textContent = '⚠️';
        if (statusTitle) statusTitle.textContent = details.title || 'FAILED — Syntax or Parsing Error';
        if (statusDesc) statusDesc.textContent = details.message || 'The analyzer encountered errors during execution.';
        break;
    }
  }

  /**
   * Reset Dashboard View to Exact Initial State (STATE 6 — RESET)
   */
  function resetDashboard() {
    setStatus('NOT_SCANNED');

    if (lastScanText) lastScanText.textContent = 'Not scanned yet';
    if (lastScanDuration) {
      lastScanDuration.style.display = 'none';
      lastScanDuration.textContent = '';
    }

    if (valScanned) valScanned.textContent = '0';
    if (valClean) valClean.textContent = '0';
    if (valSyntax) valSyntax.textContent = '0';
    if (valLeaks) valLeaks.textContent = '0';

    if (findingsCountBadge) findingsCountBadge.textContent = '0 findings';
    if (findingsContainer) {
      findingsContainer.innerHTML = `
        <div class="empty-state" id="findings-empty-state">
          ○ No analysis performed yet. Click <strong>Scan Python Project</strong> above to begin.
        </div>
      `;
    }

    if (syntaxPanel) syntaxPanel.style.display = 'none';
    if (syntaxList) syntaxList.innerHTML = '';
    if (syntaxCountBadge) syntaxCountBadge.textContent = '0 errors';

    if (filesCountBadge) filesCountBadge.textContent = '0 files';
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="empty-state">No analysis report loaded. Click "Scan Python Project" above.</td>
        </tr>
      `;
    }

    if (scanTargetSelect) {
      scanTargetSelect.value = 'examples';
    }

    if (btnScan) {
      btnScan.disabled = false;
      if (btnScanText) btnScanText.textContent = 'Scan Python Project';
    }

    isScanning = false;
  }

  /**
   * Render Analysis Report from Live Backend Result
   */
  function renderReport(data, scanDate = new Date()) {
    const filesScanned = data.files_scanned || (data.summary && data.summary.files_scanned) || 0;
    const cleanFiles = data.clean_files !== undefined ? data.clean_files : (data.summary ? data.summary.clean_files : 0);
    const syntaxErrorsCount = data.syntax_errors !== undefined ? data.syntax_errors : (data.summary ? data.summary.syntax_errors_count : 0);
    const leaksDetected = data.leaks_detected !== undefined ? data.leaks_detected : (data.summary ? data.summary.issues_count : 0);

    // 1. Update Metrics
    if (valScanned) valScanned.textContent = filesScanned;
    if (valClean) valClean.textContent = cleanFiles;
    if (valSyntax) valSyntax.textContent = syntaxErrorsCount;
    if (valLeaks) valLeaks.textContent = leaksDetected;

    // 2. Update Last Scan
    if (lastScanText) lastScanText.textContent = formatLocalTime(scanDate);
    const durSec = data.duration_seconds || (data.summary && data.summary.duration_seconds);
    if (lastScanDuration && durSec !== undefined && durSec !== null) {
      lastScanDuration.textContent = `Scan duration: ${Number(durSec).toFixed(4)}s`;
      lastScanDuration.style.display = 'block';
    }

    // 3. Update PASS / FAILED Status Banner
    if (leaksDetected > 0) {
      setStatus('FAILED', { leaksCount: leaksDetected });
    } else if (syntaxErrorsCount > 0) {
      setStatus('ERROR', {
        title: `FAILED — ${syntaxErrorsCount} Syntax Error${syntaxErrorsCount === 1 ? '' : 's'}`,
        message: 'AST parsing encountered invalid Python syntax. Fix syntax errors to analyze resources.'
      });
    } else {
      setStatus('PASS');
    }

    // 4. Render Syntax Errors (Separated from Resource Leaks)
    const syntaxListItems = data.syntax_errors_list || data.syntax_errors || [];
    if (syntaxPanel && syntaxList) {
      if (Array.isArray(syntaxListItems) && syntaxListItems.length > 0) {
        syntaxPanel.style.display = 'block';
        if (syntaxCountBadge) syntaxCountBadge.textContent = `${syntaxListItems.length} error${syntaxListItems.length === 1 ? '' : 's'}`;
        syntaxList.innerHTML = syntaxListItems.map(err => `
          <div class="syntax-card">
            <div class="syntax-card-header">
              <span class="syntax-file">📄 ${escapeHtml(err.file || err.filename)}</span>
              <span class="syntax-loc">Line ${escapeHtml(String(err.line || '-'))}:${escapeHtml(String(err.column || '-'))}</span>
            </div>
            <div class="syntax-msg">${escapeHtml(err.message)}</div>
            ${err.text ? `<div class="syntax-snippet"><code>${escapeHtml(err.text)}</code></div>` : ''}
          </div>
        `).join('');
      } else {
        syntaxPanel.style.display = 'none';
        syntaxList.innerHTML = '';
        if (syntaxCountBadge) syntaxCountBadge.textContent = '0 errors';
      }
    }

    // 5. Render Actionable Resource Leak Findings
    const findings = data.findings || [];
    if (findingsCountBadge) {
      findingsCountBadge.textContent = `${findings.length} finding${findings.length === 1 ? '' : 's'}`;
    }

    if (findingsContainer) {
      if (findings.length === 0) {
        findingsContainer.innerHTML = `
          <div class="empty-clean-state">
            <div class="clean-state-icon">✅</div>
            <div class="clean-state-title">No resource leaks detected</div>
            <div class="clean-state-desc">All opened Python resources are safely managed via context managers or explicit close blocks.</div>
          </div>
        `;
      } else {
        findingsContainer.innerHTML = findings.map(finding => {
          const severity = (finding.severity || 'HIGH').toUpperCase();
          const severityClass = severity === 'HIGH' ? 'severity-high' : (severity === 'MEDIUM' ? 'severity-medium' : 'severity-low');
          const badgeClass = severity === 'HIGH' ? 'badge-severity-high' : (severity === 'MEDIUM' ? 'badge-severity-medium' : 'badge-severity-low');

          return `
            <article class="finding-card ${severityClass}" tabindex="0">
              <div class="finding-header">
                <div class="finding-title-group">
                  <span class="badge ${badgeClass}">${escapeHtml(severity)}</span>
                  <div class="finding-file-info">
                    <span class="finding-file-path">${escapeHtml(finding.file)}</span>
                    <span class="finding-line-badge">Line ${escapeHtml(String(finding.line))}</span>
                  </div>
                </div>
                <div class="finding-resource-badge">Resource: ${escapeHtml(finding.resource || 'File')}</div>
              </div>

              <div class="finding-section">
                <div class="finding-section-label">Reason:</div>
                <div class="finding-reason-text">${escapeHtml(finding.reason || finding.problem)}</div>
              </div>

              ${(finding.leak_path || finding.path) ? `
                <div class="finding-section">
                  <div class="finding-section-label">Leak Path:</div>
                  <div class="finding-leak-path-block">
                    <code>${escapeHtml(finding.leak_path || finding.path)}</code>
                  </div>
                </div>
              ` : ''}

              ${finding.recommendation ? `
                <div class="finding-section">
                  <div class="finding-section-label">Recommendation:</div>
                  <div class="finding-recommendation-block">
                    💡 ${escapeHtml(finding.recommendation)}
                  </div>
                </div>
              ` : ''}
            </article>
          `;
        }).join('');
      }
    }

    // 6. Render Parsed Files Inventory
    const files = data.files || [];
    if (filesCountBadge) filesCountBadge.textContent = `${files.length} items`;
    if (tbody) {
      if (files.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="4" class="empty-state">No individual file parse records found.</td>
          </tr>
        `;
      } else {
        tbody.innerHTML = files.map(item => {
          const statusVal = (item.status || 'CLEAN').toUpperCase();
          let badgeClass = 'badge-clean';
          if (statusVal.includes('LEAK')) badgeClass = 'badge-leak';
          else if (statusVal.includes('ERROR')) badgeClass = 'badge-error';

          return `
            <tr>
              <td><span class="badge ${badgeClass}">${escapeHtml(statusVal)}</span></td>
              <td><code>${escapeHtml(item.file || item.file_path)}</code></td>
              <td>${escapeHtml(item.ast_details || item.details || 'Parsed')}</td>
              <td class="code-loc">${escapeHtml(item.location || '-')}</td>
            </tr>
          `;
        }).join('');
      }
    }
  }

  /**
   * Primary Scan Action: Calls Python backend /api/scan with selected target
   */
  async function runProjectScan() {
    if (isScanning) return;
    isScanning = true;

    const target = scanTargetSelect ? scanTargetSelect.value : 'examples';

    if (btnScan) btnScan.disabled = true;
    if (btnScanText) btnScanText.textContent = 'Scanning...';

    // Step 1: Parsing Python files
    setStatus('SCANNING', {
      step: 'Parsing Python files...',
      desc: `Discovering .py files in '${target}'...`
    });

    await new Promise(r => setTimeout(r, 250));

    // Step 2: Building AST
    setStatus('SCANNING', {
      step: 'Building AST...',
      desc: 'Parsing Python Abstract Syntax Trees without code execution...'
    });

    await new Promise(r => setTimeout(r, 250));

    // Step 3: Checking resource lifecycle
    setStatus('SCANNING', {
      step: 'Checking resource lifecycle...',
      desc: 'Tracing intra-procedural control-flow paths & context managers...'
    });

    try {
      const response = await fetch(`/api/scan?target=${encodeURIComponent(target)}`, {
        cache: 'no-cache'
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP ${response.status}: Failed to analyze target '${target}'`);
      }

      const reportData = await response.json();
      renderReport(reportData, new Date());
      // Refresh admin data in background if scan was persisted
      loadAdminData().catch(() => {});
    } catch (err) {
      console.error('[LeakGuard] Scan request error:', err);
      // Fallback to runtime report.json or static/sample_report.json if live API is temporarily unreachable
      try {
        let fallbackRes = await fetch('./report.json', { cache: 'no-cache' }).catch(() => null);
        if (!fallbackRes || !fallbackRes.ok) {
          fallbackRes = await fetch('./static/sample_report.json', { cache: 'no-cache' }).catch(() => null);
        }
        if (fallbackRes && fallbackRes.ok) {
          const fallbackData = await fallbackRes.json();
          renderReport(fallbackData, new Date());
          return;
        }
      } catch (_) {}

      setStatus('ERROR', {
        title: 'Scan Connection Error',
        message: `Could not connect to Python analyzer backend: ${err.message}. Ensure 'python app.py' is running.`
      });
    } finally {
      isScanning = false;
      if (btnScan) btnScan.disabled = false;
      if (btnScanText) btnScanText.textContent = 'Scan Python Project';
    }
  }

  // Admin DOM Elements
  const tabDev = document.getElementById('tab-dev');
  const tabAdmin = document.getElementById('tab-admin');
  const viewDev = document.getElementById('view-developer');
  const viewAdmin = document.getElementById('view-admin');
  const navModeBadge = document.getElementById('nav-mode-badge');

  // Admin Summary Elements
  const adminValProjects = document.getElementById('admin-val-projects');
  const adminValScans = document.getElementById('admin-val-scans');
  const adminValOpenLeaks = document.getElementById('admin-val-open-leaks');
  const adminValHighSeverity = document.getElementById('admin-val-high-severity');
  const adminValCiBlocked = document.getElementById('admin-val-ci-blocked');

  // Admin Projects Table Elements
  const adminProjectsCount = document.getElementById('admin-projects-count');
  const adminProjectsTbody = document.getElementById('admin-projects-tbody');

  // Admin Project Detail Elements
  const adminProjectDetail = document.getElementById('admin-project-detail');
  const btnCloseProjectDetail = document.getElementById('btn-close-project-detail');
  const detailProjectName = document.getElementById('detail-project-name');
  const detailProjectSub = document.getElementById('detail-project-sub');
  const detailProjectHealthBadge = document.getElementById('detail-project-health-badge');
  const detailFilesScanned = document.getElementById('detail-files-scanned');
  const detailCleanFiles = document.getElementById('detail-clean-files');
  const detailSyntaxErrors = document.getElementById('detail-syntax-errors');
  const detailLeaks = document.getElementById('detail-leaks');
  const detailFindingsContainer = document.getElementById('detail-findings-container');
  const detailHistoryTbody = document.getElementById('detail-history-tbody');

  // Admin Scans Table Elements
  const adminScansCount = document.getElementById('admin-scans-count');
  const adminScansTbody = document.getElementById('admin-scans-tbody');

  // Admin Analytics Elements
  const analyticsEmptyState = document.getElementById('analytics-empty-state');
  const analyticsContent = document.getElementById('analytics-content');
  const analyticsResourceList = document.getElementById('analytics-resource-list');
  const analyticsProjectList = document.getElementById('analytics-project-list');
  const analyticsCiBox = document.getElementById('analytics-ci-box');

  let adminPollTimer = null;
  let activeTab = 'dev';

  /**
   * Switch between Developer and Admin tabs
   */
  function switchTab(tab) {
    activeTab = tab;
    if (tab === 'admin') {
      if (tabDev) {
        tabDev.classList.remove('active');
        tabDev.setAttribute('aria-selected', 'false');
      }
      if (tabAdmin) {
        tabAdmin.classList.add('active');
        tabAdmin.setAttribute('aria-selected', 'true');
      }
      if (viewDev) viewDev.style.display = 'none';
      if (viewAdmin) viewAdmin.style.display = 'block';
      if (navModeBadge) {
        navModeBadge.textContent = 'Admin Portfolio Mode';
        navModeBadge.classList.add('admin-mode');
      }
      if (typeof window !== 'undefined' && window.location) {
        window.location.hash = '#admin';
      }
      loadAdminData();
      if (!adminPollTimer) {
        adminPollTimer = setInterval(loadAdminData, 10000);
      }
    } else {
      if (tabAdmin) {
        tabAdmin.classList.remove('active');
        tabAdmin.setAttribute('aria-selected', 'false');
      }
      if (tabDev) {
        tabDev.classList.add('active');
        tabDev.setAttribute('aria-selected', 'true');
      }
      if (viewAdmin) viewAdmin.style.display = 'none';
      if (viewDev) viewDev.style.display = 'block';
      if (navModeBadge) {
        navModeBadge.textContent = 'Developer Mode';
        navModeBadge.classList.remove('admin-mode');
      }
      if (typeof window !== 'undefined' && window.location) {
        window.location.hash = '';
      }
      if (adminPollTimer) {
        clearInterval(adminPollTimer);
        adminPollTimer = null;
      }
    }
  }

  /**
   * Fetch and render all Admin Portfolio data
   */
  async function loadAdminData() {
    try {
      const [summaryRes, projectsRes, scansRes, analyticsRes] = await Promise.all([
        fetch('/api/admin/summary', { cache: 'no-cache' }).catch(() => null),
        fetch('/api/admin/projects', { cache: 'no-cache' }).catch(() => null),
        fetch('/api/admin/scans?limit=25', { cache: 'no-cache' }).catch(() => null),
        fetch('/api/admin/analytics', { cache: 'no-cache' }).catch(() => null)
      ]);

      if (summaryRes && summaryRes.ok) {
        const summaryData = await summaryRes.json();
        renderAdminSummary(summaryData.summary || summaryData);
      }

      if (projectsRes && projectsRes.ok) {
        const projData = await projectsRes.json();
        renderAdminProjects(projData.projects || []);
      }

      if (scansRes && scansRes.ok) {
        const scansData = await scansRes.json();
        renderAdminScans(scansData.scans || []);
      }

      if (analyticsRes && analyticsRes.ok) {
        const analyticsData = await analyticsRes.json();
        renderAdminAnalytics(analyticsData.analytics || analyticsData);
      }
    } catch (err) {
      console.warn('[LeakGuard Admin] Error loading portfolio data:', err);
    }
  }

  /**
   * Render Admin Summary KPI Cards
   */
  function renderAdminSummary(summary) {
    if (adminValProjects) adminValProjects.textContent = summary.projects_count ?? summary.total_projects ?? 0;
    if (adminValScans) adminValScans.textContent = summary.total_scans ?? 0;
    if (adminValOpenLeaks) adminValOpenLeaks.textContent = summary.open_leaks ?? 0;
    if (adminValHighSeverity) adminValHighSeverity.textContent = summary.high_severity ?? summary.high_severity_leaks ?? 0;
    if (adminValCiBlocked) adminValCiBlocked.textContent = summary.ci_blocked ?? summary.ci_blocked_projects ?? 0;
  }

  /**
   * Render Projects Table
   */
  function renderAdminProjects(projects) {
    if (adminProjectsCount) {
      adminProjectsCount.textContent = `${projects.length} project${projects.length === 1 ? '' : 's'}`;
    }

    if (!adminProjectsTbody) return;

    if (!projects || projects.length === 0) {
      adminProjectsTbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">No scan history available yet. Run a scan in Developer view to initialize.</td>
        </tr>
      `;
      return;
    }

    adminProjectsTbody.innerHTML = projects.map(p => {
      const projId = p.project_id || p.id || '';
      const projName = p.name || projId;
      const repoName = p.repository || p.repo || 'Local Workspace';
      const branchName = p.branch || 'main';
      const health = p.status || p.health || 'HEALTHY';
      const latestScan = p.latest_scan || null;
      const lastStatus = latestScan ? latestScan.status : (p.last_status || 'NOT_SCANNED');
      const openLeaks = latestScan ? (latestScan.leaks_detected ?? 0) : (p.open_leaks ?? 0);
      const lastScanTime = latestScan ? latestScan.timestamp : p.last_scan;

      let healthBadge = '<span class="badge badge-healthy">HEALTHY</span>';
      if (health === 'AT_RISK') {
        healthBadge = '<span class="badge badge-at-risk">AT RISK</span>';
      } else if (health === 'REVIEW') {
        healthBadge = '<span class="badge badge-review">REVIEW</span>';
      } else if (health === 'NOT_SCANNED') {
        healthBadge = '<span class="badge badge-not-scanned">NOT SCANNED</span>';
      }

      let ciBadge = '<span class="ci-status-tag unscanned">PENDING</span>';
      if (lastStatus === 'PASS') {
        ciBadge = '<span class="ci-status-tag pass">PASSED</span>';
      } else if (lastStatus === 'FAILED') {
        ciBadge = '<span class="ci-status-tag failed">FAILED</span>';
      }

      const formattedTime = lastScanTime ? formatLocalTime(new Date(lastScanTime)) : 'Never';
      const leaksClass = openLeaks > 0 ? 'text-amber' : 'text-green';

      return `
        <tr>
          <td><strong>${escapeHtml(projName)}</strong></td>
          <td><code>${escapeHtml(repoName)}</code></td>
          <td><span class="badge">${escapeHtml(branchName)}</span></td>
          <td class="code-loc">${escapeHtml(formattedTime)}</td>
          <td><span class="${leaksClass}"><strong>${escapeHtml(String(openLeaks))}</strong></span></td>
          <td>${ciBadge}</td>
          <td>${healthBadge}</td>
          <td>
            <button class="btn btn-secondary btn-sm btn-project-detail" data-project-id="${escapeHtml(projId)}">Details</button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach click events for detail buttons
    const detailBtns = adminProjectsTbody.querySelectorAll('.btn-project-detail');
    detailBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const pid = btn.getAttribute('data-project-id');
        if (pid) showProjectDetail(pid);
      });
    });
  }

  /**
   * Helper: Format Scan Type Tag Badge
   */
  function getScanTypeTag(type) {
    const t = (type || 'LOCAL SCAN').toUpperCase();
    let tagClass = 'local-scan';
    if (t === 'FILE UPLOAD') tagClass = 'file-upload';
    else if (t === 'PROJECT UPLOAD') tagClass = 'project-upload';
    else if (t === 'CI') tagClass = 'ci';
    return `<span class="scan-type-tag ${tagClass}">${escapeHtml(t)}</span>`;
  }

  /**
   * Render Recent Scans Activity Stream
   */
  function renderAdminScans(scans) {
    if (adminScansCount) {
      adminScansCount.textContent = `${scans.length} scan${scans.length === 1 ? '' : 's'}`;
    }

    if (!adminScansTbody) return;

    if (!scans || scans.length === 0) {
      adminScansTbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">No scan history available yet.</td>
        </tr>
      `;
      return;
    }

    adminScansTbody.innerHTML = scans.map(s => {
      const scanDate = s.timestamp ? formatLocalTime(new Date(s.timestamp)) : '-';
      let statusBadge = '<span class="ci-status-tag pass">PASS</span>';
      if (s.status === 'FAILED') {
        statusBadge = '<span class="ci-status-tag failed">FAILED</span>';
      }

      const shortId = s.scan_id ? s.scan_id.substring(0, 16) : '-';
      const projName = s.project_name || s.project_id || '-';
      const typeTag = getScanTypeTag(s.scan_type);

      return `
        <tr>
          <td><strong>${escapeHtml(projName)}</strong></td>
          <td><code>${escapeHtml(shortId)}</code></td>
          <td>${typeTag}</td>
          <td class="code-loc">${escapeHtml(scanDate)}</td>
          <td><code>${escapeHtml(s.target)}</code></td>
          <td>${escapeHtml(String(s.files_scanned))}</td>
          <td><span class="${s.leaks_detected > 0 ? 'text-amber' : 'text-green'}"><strong>${escapeHtml(String(s.leaks_detected))}</strong></span></td>
          <td>${statusBadge}</td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Render Analytics Posture
   */
  function renderAdminAnalytics(analyticsData) {
    if (!analyticsResourceList || !analyticsProjectList || !analyticsCiBox) return;

    const analytics = (analyticsData && analyticsData.analytics) || analyticsData || {};

    if (!analytics.has_data) {
      if (analyticsEmptyState) analyticsEmptyState.style.display = 'block';
      if (analyticsContent) analyticsContent.style.display = 'none';
      return;
    }

    if (analyticsEmptyState) analyticsEmptyState.style.display = 'none';
    if (analyticsContent) analyticsContent.style.display = 'block';

    // Resources
    const resList = Array.isArray(analytics.leaks_by_resource)
      ? analytics.leaks_by_resource
      : Object.entries(analytics.leaks_by_resource || {}).map(([resource, count]) => ({ resource, count }));

    if (resList.length === 0) {
      analyticsResourceList.innerHTML = '<li class="analytics-list-item"><span class="analytics-list-key">All Resources</span><span class="analytics-list-val text-green">0 leaks</span></li>';
    } else {
      analyticsResourceList.innerHTML = resList.map(item => `
        <li class="analytics-list-item">
          <span class="analytics-list-key">${escapeHtml(item.resource)}</span>
          <span class="analytics-list-val text-amber">${escapeHtml(String(item.count))} leak${item.count === 1 ? '' : 's'}</span>
        </li>
      `).join('');
    }

    // Projects
    const projList = Array.isArray(analytics.leaks_by_project)
      ? analytics.leaks_by_project
      : Object.entries(analytics.leaks_by_project || {}).map(([project_name, leaks]) => ({ project_name, leaks }));

    if (projList.length === 0) {
      analyticsProjectList.innerHTML = '<li class="analytics-list-item"><span class="analytics-list-key">All Projects</span><span class="analytics-list-val text-green">0 leaks</span></li>';
    } else {
      analyticsProjectList.innerHTML = projList.map(item => `
        <li class="analytics-list-item">
          <span class="analytics-list-key">${escapeHtml(item.project_name)}</span>
          <span class="analytics-list-val ${item.leaks > 0 ? 'text-red' : 'text-green'}">${escapeHtml(String(item.leaks))} leak${item.leaks === 1 ? '' : 's'}</span>
        </li>
      `).join('');
    }

    // CI Box
    const ciStats = analytics.ci_stats || {};
    const total = ciStats.total ?? (analytics.total_scans ?? 0);
    const passes = ciStats.passes ?? (analytics.passed_scans ?? 0);
    const failures = ciStats.failures ?? (analytics.failed_scans ?? 0);
    const passRate = total > 0 ? Math.round((passes / total) * 100) : 100;
    const rateClass = passRate >= 80 ? 'text-green' : (passRate >= 50 ? 'text-amber' : 'text-red');

    analyticsCiBox.innerHTML = `
      <div class="ci-stat-line">
        <span>CI Gate Success Rate</span>
        <strong class="${rateClass}">${passRate}%</strong>
      </div>
      <div class="ci-stat-line">
        <span>Passed Scans</span>
        <strong class="text-green">${passes}</strong>
      </div>
      <div class="ci-stat-line">
        <span>Blocked / Failed Scans</span>
        <strong class="text-red">${failures}</strong>
      </div>
      <div class="ci-stat-line">
        <span>Total Evaluated Scans</span>
        <strong>${total}</strong>
      </div>
    `;
  }

  /**
   * Fetch and display Project Detail Drilldown
   */
  async function showProjectDetail(projectId) {
    try {
      const res = await fetch(`/api/admin/project?id=${encodeURIComponent(projectId)}`, { cache: 'no-cache' });
      if (!res.ok) return;
      const data = await res.json();
      const p = data.project || {};
      const latest = p.latest_scan || data.latest_scan || {};
      const findings = p.open_findings || data.open_findings || [];
      const history = p.scan_history || data.scan_history || data.history || [];

      if (detailProjectName) detailProjectName.textContent = p.name || projectId;
      if (detailProjectSub) detailProjectSub.textContent = `Repository: ${p.repository || p.repo || '-'} | Branch: ${p.branch || 'main'}`;

      if (detailProjectHealthBadge) {
        const health = p.status || p.health || 'HEALTHY';
        detailProjectHealthBadge.textContent = health.replace('_', ' ');
        detailProjectHealthBadge.className = `badge ${health === 'HEALTHY' ? 'badge-healthy' : (health === 'AT_RISK' ? 'badge-at-risk' : (health === 'NOT_SCANNED' ? 'badge-not-scanned' : 'badge-review'))}`;
      }

      if (detailFilesScanned) detailFilesScanned.textContent = latest.files_scanned || 0;
      if (detailCleanFiles) detailCleanFiles.textContent = latest.clean_files || 0;
      if (detailSyntaxErrors) detailSyntaxErrors.textContent = latest.syntax_errors || 0;
      if (detailLeaks) detailLeaks.textContent = latest.leaks_detected || 0;

      // Findings
      if (detailFindingsContainer) {
        if (findings.length === 0) {
          detailFindingsContainer.innerHTML = `
            <div class="empty-clean-state">
              <div class="clean-state-icon">✅</div>
              <div class="clean-state-title">No open leaks detected</div>
              <div class="clean-state-desc">All opened resources in this project are properly managed.</div>
            </div>
          `;
        } else {
          detailFindingsContainer.innerHTML = findings.map(f => {
            const severity = (f.severity || 'HIGH').toUpperCase();
            const badgeClass = severity === 'HIGH' ? 'badge-severity-high' : (severity === 'MEDIUM' ? 'badge-severity-medium' : 'badge-severity-low');
            const filePath = f.file || f.file_path || '-';
            const lineNum = f.line || f.line_number || '-';
            const resource = f.resource || f.resource_type || 'Resource';
            const reason = f.reason || f.message || f.problem || 'Resource leak detected';

            return `
              <article class="finding-card severity-high" tabindex="0">
                <div class="finding-header">
                  <div class="finding-title-group">
                    <span class="badge ${badgeClass}">${escapeHtml(severity)}</span>
                    <div class="finding-file-info">
                      <span class="finding-file-path">${escapeHtml(filePath)}</span>
                      <span class="finding-line-badge">Line ${escapeHtml(String(lineNum))}</span>
                    </div>
                  </div>
                  <div class="finding-resource-badge">Resource: ${escapeHtml(resource)}</div>
                </div>
                <div class="finding-section">
                  <div class="finding-section-label">Reason:</div>
                  <div class="finding-reason-text">${escapeHtml(reason)}</div>
                </div>
                ${f.leak_path ? `
                  <div class="finding-section">
                    <div class="finding-section-label">Leak Path:</div>
                    <div class="finding-leak-path-block">
                      <code>${escapeHtml(f.leak_path)}</code>
                    </div>
                  </div>
                ` : ''}
                ${f.recommendation ? `
                  <div class="finding-section">
                    <div class="finding-section-label">Recommendation:</div>
                    <div class="finding-recommendation-block">💡 ${escapeHtml(f.recommendation)}</div>
                  </div>
                ` : ''}
              </article>
            `;
          }).join('');
        }
      }

      // History Table
      if (detailHistoryTbody) {
        if (history.length === 0) {
          detailHistoryTbody.innerHTML = `
            <tr>
              <td colspan="9" class="empty-state">No historical scans recorded.</td>
            </tr>
          `;
        } else {
          detailHistoryTbody.innerHTML = history.map(h => {
            const hTime = h.timestamp ? formatLocalTime(new Date(h.timestamp)) : '-';
            const shortId = h.scan_id ? h.scan_id.substring(0, 16) : '-';
            const durMs = h.duration_ms !== undefined ? `${Number(h.duration_ms).toFixed(1)}ms` : (h.duration_seconds ? `${Number(h.duration_seconds).toFixed(4)}s` : '-');
            const statusBadge = h.status === 'PASS' ? '<span class="ci-status-tag pass">PASSED</span>' : '<span class="ci-status-tag failed">FAILED</span>';
            const typeTag = getScanTypeTag(h.scan_type);

            return `
              <tr>
                <td><code>${escapeHtml(shortId)}</code></td>
                <td>${typeTag}</td>
                <td class="code-loc">${escapeHtml(hTime)}</td>
                <td><code>${escapeHtml(h.target)}</code></td>
                <td>${escapeHtml(String(h.files_scanned))}</td>
                <td>${escapeHtml(String(h.clean_files))}</td>
                <td><span class="${h.leaks_detected > 0 ? 'text-amber' : 'text-green'}"><strong>${escapeHtml(String(h.leaks_detected))}</strong></span></td>
                <td>${escapeHtml(durMs)}</td>
                <td>${statusBadge}</td>
              </tr>
            `;
          }).join('');
        }
      }

      if (adminProjectDetail) {
        adminProjectDetail.style.display = 'block';
        adminProjectDetail.scrollIntoView({ behavior: 'smooth' });
      }
    } catch (err) {
      console.warn('[LeakGuard Admin] Error fetching project details:', err);
    }
  }

  // Close Detail Drawer
  if (btnCloseProjectDetail && adminProjectDetail) {
    btnCloseProjectDetail.addEventListener('click', () => {
      adminProjectDetail.style.display = 'none';
    });
  }

  // Tab Switching Listeners
  if (tabDev) {
    tabDev.addEventListener('click', () => switchTab('dev'));
  }
  if (tabAdmin) {
    tabAdmin.addEventListener('click', () => switchTab('admin'));
  }

  // Check URL Hash for direct #admin navigation
  if (typeof window !== 'undefined' && window.location && window.location.hash === '#admin') {
    switchTab('admin');
  }

  if (typeof window !== 'undefined' && window.addEventListener) {
    window.addEventListener('hashchange', () => {
      if (window.location && window.location.hash === '#admin') {
        switchTab('admin');
      } else {
        switchTab('dev');
      }
    });
  }

  /**
   * Handle Upload of Python Files or Folders
   */
  async function handleFilesUpload(fileList, mode = 'file') {
    if (!fileList || fileList.length === 0) return;
    if (isScanning) return;

    isScanning = true;
    if (btnScan) btnScan.disabled = true;
    if (btnUploadFile) btnUploadFile.disabled = true;
    if (btnUploadFolder) btnUploadFolder.disabled = true;

    setStatus('SCANNING', {
      step: 'Reading uploaded files...',
      desc: 'Preparing Python source files for isolated AST analysis...'
    });

    try {
      const fileItems = [];
      let detectedFolder = null;

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const relPath = (file.webkitRelativePath || file.name || '').replace(/\\/g, '/');
        if (!relPath) continue;

        if (relPath.includes('/') && !detectedFolder) {
          detectedFolder = relPath.split('/')[0];
        }

        // Filter: In folder mode, ignore non-Python files
        if (mode === 'folder' && !relPath.toLowerCase().endsWith('.py')) {
          continue;
        }

        const text = await file.text();
        fileItems.push({
          path: relPath,
          content: text
        });
      }

      if (fileItems.length === 0) {
        throw new Error(mode === 'folder' ? 'No Python (.py) files found in uploaded folder.' : 'No files selected.');
      }

      if (mode === 'file' && !fileItems[0].path.toLowerCase().endsWith('.py')) {
        throw new Error('Invalid file type: Only Python (.py) files are supported.');
      }

      setStatus('SCANNING', {
        step: 'Parsing Python AST...',
        desc: 'Analyzing AST nodes and tracing resource lifecycles with zero code execution...'
      });

      const payload = {
        target_name: mode === 'folder' ? (detectedFolder || 'uploaded_project') : fileItems[0].path,
        files: fileItems
      };

      const res = await fetch('/api/scan/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Upload scan failed with status ${res.status}`);
      }

      const reportData = await res.json();
      renderReport(reportData, new Date());
      loadAdminData().catch(() => {});
    } catch (err) {
      console.error('[LeakGuard] Upload scan error:', err);
      setStatus('ERROR', {
        title: 'Upload Analysis Error',
        message: err.message || 'An error occurred while uploading and analyzing Python files.'
      });
    } finally {
      isScanning = false;
      if (btnScan) btnScan.disabled = false;
      if (btnUploadFile) btnUploadFile.disabled = false;
      if (btnUploadFolder) btnUploadFolder.disabled = false;
    }
  }

  // Action Control Event Listeners
  if (btnScan) {
    btnScan.addEventListener('click', runProjectScan);
  }

  if (btnClear) {
    btnClear.addEventListener('click', () => {
      if (isScanning) return;
      resetDashboard();
    });
  }

  if (btnUploadFile && inputUploadFile) {
    btnUploadFile.addEventListener('click', () => {
      if (!isScanning) inputUploadFile.click();
    });
    inputUploadFile.addEventListener('change', async () => {
      if (inputUploadFile.files && inputUploadFile.files.length > 0) {
        const files = inputUploadFile.files;
        inputUploadFile.value = '';
        await handleFilesUpload(files, 'file');
      }
    });
  }

  if (btnUploadFolder && inputUploadFolder) {
    btnUploadFolder.addEventListener('click', () => {
      if (!isScanning) inputUploadFolder.click();
    });
    inputUploadFolder.addEventListener('change', async () => {
      if (inputUploadFolder.files && inputUploadFolder.files.length > 0) {
        const files = inputUploadFolder.files;
        inputUploadFolder.value = '';
        await handleFilesUpload(files, 'folder');
      }
    });
  }

  // Dropzone handling
  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');

      if (isScanning) return;

      const items = e.dataTransfer.items;
      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;

      // Case 1: Dropped report.json
      if (files.length === 1 && files[0].name.toLowerCase().endsWith('.json')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const parsed = JSON.parse(event.target.result);
            renderReport(parsed, new Date());
          } catch (err) {
            alert('Invalid JSON report file: ' + err.message);
          }
        };
        reader.readAsText(files[0]);
        return;
      }

      // Case 2: Handle directory traversal if available
      if (items && items.length > 0 && items[0].webkitGetAsEntry) {
        const collectedFiles = [];
        async function traverseEntry(entry, path = '') {
          if (entry.isFile) {
            const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
            Object.defineProperty(file, 'webkitRelativePath', {
              value: path + file.name,
              writable: false
            });
            collectedFiles.push(file);
          } else if (entry.isDirectory) {
            const dirReader = entry.createReader();
            const entries = await new Promise((resolve, reject) => {
              const all = [];
              function readNext() {
                dirReader.readEntries((results) => {
                  if (!results.length) {
                    resolve(all);
                  } else {
                    all.push(...results);
                    readNext();
                  }
                }, reject);
              }
              readNext();
            });
            for (const child of entries) {
              await traverseEntry(child, path + entry.name + '/');
            }
          }
        }

        try {
          for (let i = 0; i < items.length; i++) {
            const entry = items[i].webkitGetAsEntry();
            if (entry) {
              await traverseEntry(entry);
            }
          }
          if (collectedFiles.length > 0) {
            const isFolder = collectedFiles.length > 1 || (collectedFiles[0].webkitRelativePath && collectedFiles[0].webkitRelativePath.includes('/'));
            handleFilesUpload(collectedFiles, isFolder ? 'folder' : 'file');
            return;
          }
        } catch (dirErr) {
          console.warn('[LeakGuard] Directory traversal fallback:', dirErr);
        }
      }

      // Case 3: Flat files list
      const isFolder = files.length > 1;
      handleFilesUpload(files, isFolder ? 'folder' : 'file');
    });

    dropzone.addEventListener('click', () => {
      if (!isScanning) {
        runProjectScan();
      }
    });
  }

  // Initial State: NOT SCANNED
  resetDashboard();
});
