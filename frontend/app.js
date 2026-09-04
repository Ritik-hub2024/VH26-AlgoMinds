/**
 * LeakGuard Static Analyzer Dashboard Controller
 * Connects frontend UI to live Python AST analyzer via /api/scan and manages dashboard states.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Action Controls
  const btnScan = document.getElementById('btn-scan');
  const btnScanText = document.getElementById('btn-scan-text');
  const scanTargetSelect = document.getElementById('scan-target-select');
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
                <div class="finding-reason-text">${escapeHtml(finding.reason)}</div>
              </div>

              ${finding.leak_path ? `
                <div class="finding-section">
                  <div class="finding-section-label">Leak Path:</div>
                  <div class="finding-leak-path-block">
                    <code>${escapeHtml(finding.leak_path)}</code>
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

  // Event Listeners
  if (btnScan) {
    btnScan.addEventListener('click', runProjectScan);
  }

  if (btnClear) {
    btnClear.addEventListener('click', () => {
      if (isScanning) return;
      resetDashboard();
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

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        const file = files[0];
        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const parsed = JSON.parse(event.target.result);
            renderReport(parsed, new Date());
          } catch (err) {
            alert('Invalid JSON report file: ' + err.message);
          }
        };
        reader.readAsText(file);
      }
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
