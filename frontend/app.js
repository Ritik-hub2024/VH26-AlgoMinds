/**
 * LeakGuard Security Remediation Platform Controller
 * Manages full lifecycle: Upload -> Scan -> Findings -> Fix -> Verify -> Commit -> Pull Request
 */

document.addEventListener('DOMContentLoaded', () => {
  // -------------------------------------------------------------
  // Runtime State
  // -------------------------------------------------------------
  let currentWorkspaceId = 'default';
  let currentProjectName = 'examples/';
  let currentReportData = null;
  let activeFinding = null;
  let activeFix = null;
  let isScanning = false;
  let isFixing = false;
  let githubState = {
    authenticated: false,
    user: null,
    connected_repo: null,
    repositories: [],
    selected_repo: null,
    selected_branch: 'main',
    oauth_configured: false,
    oauth_url: null
  };

  // -------------------------------------------------------------
  // DOM Elements
  // -------------------------------------------------------------
  // Workflow Stepper Nodes & Badges
  const workflowStateBadge = document.getElementById('workflow-state-badge');
  const stepNodes = [1, 2, 3, 4, 5, 6].map(i => document.getElementById(`step-node-${i}`));
  const stepLines = [1, 2, 3, 4, 5].map(i => document.getElementById(`step-line-${i}`));
  const stepSubs = [1, 2, 3, 4, 5, 6].map(i => document.getElementById(`step-sub-${i}`));

  // Status Banner
  const statusBanner = document.getElementById('scan-status-banner');
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusDesc = document.getElementById('status-desc');
  const statusProgressSteps = document.getElementById('status-progress-steps');
  const statusStepText = document.getElementById('status-step-text');

  // Header & Status
  const headerGithubRepo = document.getElementById('header-github-repo');
  const lastScanText = document.getElementById('last-scan-text');
  const lastScanDuration = document.getElementById('last-scan-duration');

  // Project Source Elements
  const btnUploadZip = document.getElementById('btn-upload-zip');
  const inputUploadZip = document.getElementById('input-upload-zip');
  const scanTargetSelect = document.getElementById('scan-target-select');
  const btnUploadFile = document.getElementById('btn-upload-file');
  const inputUploadFile = document.getElementById('input-upload-file');
  const btnUploadFolder = document.getElementById('btn-upload-folder');
  const inputUploadFolder = document.getElementById('input-upload-folder');
  const btnScan = document.getElementById('btn-scan');
  const btnScanText = document.getElementById('btn-scan-text');
  const btnClear = document.getElementById('btn-clear');
  const dropzone = document.getElementById('dropzone');

  // Workspace Summary Box
  const wsProjectName = document.getElementById('ws-project-name');
  const wsStatusBadge = document.getElementById('ws-status-badge');
  const wsFilesCount = document.getElementById('ws-files-count');
  const wsLinesCount = document.getElementById('ws-lines-count');

  // Metrics
  const valScanned = document.getElementById('val-scanned');
  const valClean = document.getElementById('val-clean');
  const valSyntax = document.getElementById('val-syntax-errors');
  const valIssues = document.getElementById('val-issues');
  const valLeaks = document.getElementById('val-leaks');

  // Severity Counters
  const sevValCritical = document.getElementById('sev-val-critical');
  const sevValHigh = document.getElementById('sev-val-high');
  const sevValMedium = document.getElementById('sev-val-medium');
  const sevValLow = document.getElementById('sev-val-low');

  // Findings & Syntax
  const findingsContainer = document.getElementById('findings-container');
  const findingsCountBadge = document.getElementById('findings-count');
  const syntaxPanel = document.getElementById('syntax-panel');
  const syntaxList = document.getElementById('syntax-list');
  const syntaxCountBadge = document.getElementById('syntax-count');

  // Files Table
  const tbody = document.getElementById('results-tbody');
  const filesCountBadge = document.getElementById('results-count');

  // Commit & Verification Workflow Panel
  const commitWorkflowPanel = document.getElementById('commit-workflow-panel');
  const verifyStatusBadge = document.getElementById('verify-status-badge');
  const statIssuesDetected = document.getElementById('stat-issues-detected');
  const statAutoFixed = document.getElementById('stat-auto-fixed');
  const statManualReview = document.getElementById('stat-manual-review');
  const statFilesChanged = document.getElementById('stat-files-changed');
  const statLinesAdded = document.getElementById('stat-lines-added');
  const statLinesRemoved = document.getElementById('stat-lines-removed');
  const inputBranchName = document.getElementById('input-branch-name');
  const inputCommitMsg = document.getElementById('input-commit-msg');
  const btnCommitChanges = document.getElementById('btn-commit-changes');
  const btnCreatePr = document.getElementById('btn-create-pr');
  const gitActionResult = document.getElementById('git-action-result');

  // Modals
  const modalCodeView = document.getElementById('modal-code-view');
  const codeModalBadge = document.getElementById('code-modal-badge');
  const codeModalTitle = document.getElementById('code-modal-title');
  const codeModalSubtitle = document.getElementById('code-modal-subtitle');
  const codeModalCallout = document.getElementById('code-modal-callout');
  const codeModalLines = document.getElementById('code-modal-lines');
  const btnCloseCodeModal = document.getElementById('btn-close-code-modal');
  const btnCancelCodeModal = document.getElementById('btn-cancel-code-modal');
  const btnModalGenerateFix = document.getElementById('btn-modal-generate-fix');

  const modalDiffView = document.getElementById('modal-diff-view');
  const diffModalTitle = document.getElementById('diff-modal-title');
  const diffModalSubtitle = document.getElementById('diff-modal-subtitle');
  const diffStatAdditions = document.getElementById('diff-stat-additions');
  const diffStatDeletions = document.getElementById('diff-stat-deletions');
  const diffStatRule = document.getElementById('diff-stat-rule');
  const diffBeforeBox = document.getElementById('diff-before-box');
  const diffAfterBox = document.getElementById('diff-after-box');
  const diffVerifyProgress = document.getElementById('diff-verify-progress');
  const diffVerifyText = document.getElementById('diff-verify-text');
  const diffVerifyResult = document.getElementById('diff-verify-result');
  const btnCloseDiffModal = document.getElementById('btn-close-diff-modal');
  const btnRejectDiff = document.getElementById('btn-reject-diff');
  const btnApplyDiff = document.getElementById('btn-apply-diff');
  const btnApplyDiffText = document.getElementById('btn-apply-diff-text');

  // GitHub Dashboard Card Elements
  const cardConnectGithub = document.getElementById('card-connect-github');
  const ghCardTitle = document.getElementById('gh-card-title');
  const ghCardDesc = document.getElementById('gh-card-desc');
  const ghCardConnectedDetails = document.getElementById('gh-card-connected-details');
  const ghCardBadge = document.getElementById('gh-card-badge');
  const ghCardRepoName = document.getElementById('gh-card-repo-name');
  const ghCardBranchName = document.getElementById('gh-card-branch-name');
  const ghCardConnectedBtns = document.getElementById('gh-card-connected-btns');
  const btnGhChangeRepo = document.getElementById('btn-gh-change-repo');
  const btnGhDisconnect = document.getElementById('btn-gh-disconnect');
  const btnOpenGithubModal = document.getElementById('btn-open-github-modal');
  const btnOpenGithubText = document.getElementById('btn-open-github-text');

  // GitHub Modal Elements
  const modalGithubConnect = document.getElementById('modal-github-connect');
  const btnCloseGithubModal = document.getElementById('btn-close-github-modal');
  const btnCancelGithubModal = document.getElementById('btn-cancel-github-modal');
  const btnSaveGithubConnect = document.getElementById('btn-save-github-connect');
  const btnSaveGithubText = document.getElementById('btn-save-github-text');

  const ghViewUnauthenticated = document.getElementById('gh-view-unauthenticated');
  const btnGhAuthorize = document.getElementById('btn-gh-authorize');
  const ghDevModeBox = document.getElementById('gh-dev-mode-box');
  const ghDevText = document.getElementById('gh-dev-text');

  const ghViewAuthenticated = document.getElementById('gh-view-authenticated');
  const ghUserAvatar = document.getElementById('gh-user-avatar');
  const ghUserName = document.getElementById('gh-user-name');
  const btnGhSignOut = document.getElementById('btn-gh-sign-out');

  const ghRepoSearchInput = document.getElementById('gh-repo-search-input');
  const ghRepoListContainer = document.getElementById('gh-repo-list-container');
  const ghRepoList = document.getElementById('gh-repo-list');

  const ghBranchSection = document.getElementById('gh-branch-section');
  const ghBranchSelect = document.getElementById('gh-branch-select');
  const ghBranchHint = document.getElementById('gh-branch-hint');

  const ghModalStatusBox = document.getElementById('gh-modal-status-box');
  const ghModalSpinner = document.getElementById('gh-modal-spinner');
  const ghModalStatusText = document.getElementById('gh-modal-status-text');

  // Navigation & Admin Elements
  const tabDev = document.getElementById('tab-dev');
  const tabAdmin = document.getElementById('tab-admin');
  const viewDev = document.getElementById('view-developer');
  const viewAdmin = document.getElementById('view-admin');
  const navModeBadge = document.getElementById('nav-mode-badge');

  // -------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatLocalTime(date) {
    try {
      return new Intl.DateTimeFormat(undefined, {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
      }).format(date);
    } catch (e) {
      return date.toLocaleTimeString();
    }
  }

  // -------------------------------------------------------------
  // Workflow Progress Stepper State Management
  // -------------------------------------------------------------
  function updateWorkflowProgress(stepNumber, stateText, details = {}) {
    if (workflowStateBadge) workflowStateBadge.textContent = `STATE: ${stateText}`;

    stepNodes.forEach((node, idx) => {
      const stepIdx = idx + 1;
      if (!node) return;
      node.classList.remove('active', 'completed', 'pending');

      if (stepIdx < stepNumber) {
        node.classList.add('completed');
        const badge = node.querySelector('.step-badge');
        if (badge) badge.textContent = '✓';
        if (stepSubs[idx]) stepSubs[idx].textContent = 'Done';
      } else if (stepIdx === stepNumber) {
        node.classList.add('active');
        const badge = node.querySelector('.step-badge');
        if (badge) badge.textContent = String(stepIdx);
        if (stepSubs[idx]) stepSubs[idx].textContent = details.sub || 'In Progress';
      } else {
        node.classList.add('pending');
        const badge = node.querySelector('.step-badge');
        if (badge) badge.textContent = String(stepIdx);
        if (stepSubs[idx]) stepSubs[idx].textContent = 'Pending';
      }
    });

    stepLines.forEach((line, idx) => {
      if (!line) return;
      if (idx + 1 < stepNumber) {
        line.classList.add('completed');
      } else {
        line.classList.remove('completed');
      }
    });
  }

  // -------------------------------------------------------------
  // Banner Status
  // -------------------------------------------------------------
  function setStatus(state, details = {}) {
    if (!statusBanner) return;
    statusBanner.className = 'status-banner';
    if (statusProgressSteps) statusProgressSteps.style.display = 'none';

    switch (state) {
      case 'NOT_SCANNED':
      case 'IDLE':
        statusBanner.classList.add('status-not-scanned');
        if (statusIcon) statusIcon.textContent = '○';
        if (statusTitle) statusTitle.textContent = 'PROJECT READY';
        if (statusDesc) statusDesc.textContent = 'Upload a ZIP project, connect GitHub, or select a Python suite to start security remediation.';
        break;

      case 'UPLOADING':
        statusBanner.classList.add('status-scanning');
        if (statusIcon) statusIcon.innerHTML = '<div class="spinner"></div>';
        if (statusTitle) statusTitle.textContent = 'EXTRACTING & VALIDATING ZIP...';
        if (statusDesc) statusDesc.textContent = details.desc || 'Safely unzipping archive and inspecting Python source files...';
        break;

      case 'SCANNING':
        statusBanner.classList.add('status-scanning');
        if (statusIcon) statusIcon.innerHTML = '<div class="spinner"></div>';
        if (statusTitle) statusTitle.textContent = 'SCANNING PROJECT AST...';
        if (statusDesc) statusDesc.textContent = details.desc || 'Parsing Python Abstract Syntax Trees and tracing resource lifecycles...';
        if (statusProgressSteps) {
          statusProgressSteps.style.display = 'flex';
          if (statusStepText) statusStepText.textContent = details.step || 'Scanning Python files...';
        }
        break;

      case 'PASS':
        statusBanner.classList.add('status-pass');
        if (statusIcon) statusIcon.textContent = '✅';
        if (statusTitle) statusTitle.textContent = 'PASS — Clean Codebase';
        if (statusDesc) statusDesc.textContent = 'All Python files parsed cleanly with zero resource leaks or syntax errors.';
        break;

      case 'FAILED':
        statusBanner.classList.add('status-failed');
        if (statusIcon) statusIcon.textContent = '⚠️';
        const leaks = details.leaksCount !== undefined ? details.leaksCount : 1;
        const leakLabel = leaks === 1 ? '1 Security Leak' : `${leaks} Security Leaks`;
        if (statusTitle) statusTitle.textContent = `REMEDIATION REQUIRED — ${leakLabel} Detected`;
        if (statusDesc) statusDesc.textContent = 'LeakGuard detected actionable resource leaks. Generate and verify safe AST fixes below.';
        break;

      case 'ERROR':
        statusBanner.classList.add('status-failed');
        if (statusIcon) statusIcon.textContent = '❌';
        if (statusTitle) statusTitle.textContent = details.title || 'Analyzer Error';
        if (statusDesc) statusDesc.textContent = details.message || 'An error occurred during execution.';
        break;
    }
  }

  // -------------------------------------------------------------
  // Reset Dashboard
  // -------------------------------------------------------------
  function resetDashboard() {
    currentWorkspaceId = 'default';
    currentProjectName = 'examples/';
    currentReportData = null;
    activeFinding = null;
    activeFix = null;
    isScanning = false;

    updateWorkflowProgress(1, 'IDLE', { sub: 'Ready' });
    setStatus('IDLE');

    if (wsProjectName) wsProjectName.textContent = 'examples/';
    if (wsStatusBadge) {
      wsStatusBadge.textContent = 'Ready';
      wsStatusBadge.className = 'badge badge-clean';
    }
    if (wsFilesCount) wsFilesCount.textContent = '3 Python files';
    if (wsLinesCount) wsLinesCount.textContent = '~65 lines';

    if (valScanned) valScanned.textContent = '0';
    if (valClean) valClean.textContent = '0';
    if (valSyntax) valSyntax.textContent = '0';
    if (valIssues) valIssues.textContent = '0';
    if (valLeaks) valLeaks.textContent = '0';

    if (sevValCritical) sevValCritical.textContent = '0';
    if (sevValHigh) sevValHigh.textContent = '0';
    if (sevValMedium) sevValMedium.textContent = '0';
    if (sevValLow) sevValLow.textContent = '0';

    if (findingsCountBadge) findingsCountBadge.textContent = '0 findings';
    if (findingsContainer) {
      findingsContainer.innerHTML = `
        <div class="empty-state" id="findings-empty-state">
          ○ No analysis performed yet. Click <strong>Scan Project</strong> above to begin.
        </div>
      `;
    }

    if (syntaxPanel) syntaxPanel.style.display = 'none';
    if (syntaxList) syntaxList.innerHTML = '';
    if (syntaxCountBadge) syntaxCountBadge.textContent = '0 errors';

    if (commitWorkflowPanel) commitWorkflowPanel.style.display = 'none';
    if (btnCommitChanges) btnCommitChanges.disabled = true;
    if (btnCreatePr) btnCreatePr.disabled = true;
    if (gitActionResult) {
      gitActionResult.style.display = 'none';
      gitActionResult.innerHTML = '';
    }

    if (filesCountBadge) filesCountBadge.textContent = '0 items';
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="empty-state">No analysis report loaded. Click "Scan Project" above.</td>
        </tr>
      `;
    }

    if (scanTargetSelect) scanTargetSelect.value = 'examples';
  }

  // -------------------------------------------------------------
  // Render Scan Report
  // -------------------------------------------------------------
  function renderScanReport(data, scanDate = new Date()) {
    currentReportData = data;
    const filesScanned = data.files_scanned || (data.summary && data.summary.files_scanned) || 0;
    const cleanFiles = data.clean_files !== undefined ? data.clean_files : (data.summary ? data.summary.clean_files : 0);
    const syntaxErrorsCount = data.syntax_errors !== undefined ? data.syntax_errors : (data.summary ? data.summary.syntax_errors_count : 0);
    const leaksDetected = data.leaks_detected !== undefined ? data.leaks_detected : (data.summary ? data.summary.issues_count : 0);
    const totalIssues = data.issues_count !== undefined ? data.issues_count : (leaksDetected + syntaxErrorsCount);

    // 1. Metrics
    if (valScanned) valScanned.textContent = filesScanned;
    if (valClean) valClean.textContent = cleanFiles;
    if (valSyntax) valSyntax.textContent = syntaxErrorsCount;
    if (valIssues) valIssues.textContent = totalIssues;
    if (valLeaks) valLeaks.textContent = leaksDetected;

    // 2. Severity Counters
    const sev = data.severity_counts || { CRITICAL: 0, HIGH: leaksDetected, MEDIUM: 0, LOW: 0 };
    if (sevValCritical) sevValCritical.textContent = sev.CRITICAL || 0;
    if (sevValHigh) sevValHigh.textContent = sev.HIGH || 0;
    if (sevValMedium) sevValMedium.textContent = sev.MEDIUM || 0;
    if (sevValLow) sevValLow.textContent = sev.LOW || 0;

    // 3. Last Scan
    if (lastScanText) lastScanText.textContent = formatLocalTime(scanDate);
    const durSec = data.duration_seconds || (data.summary && data.summary.duration_seconds);
    if (lastScanDuration && durSec !== undefined && durSec !== null) {
      lastScanDuration.textContent = `Scan duration: ${Number(durSec).toFixed(4)}s`;
      lastScanDuration.style.display = 'block';
    }

    // 4. Status Banner & Workflow Stepper
    if (leaksDetected > 0) {
      setStatus('FAILED', { leaksCount: leaksDetected });
      updateWorkflowProgress(3, 'FINDINGS_FOUND', { sub: `${leaksDetected} Leaks` });
    } else if (syntaxErrorsCount > 0) {
      setStatus('ERROR', {
        title: `FAILED — ${syntaxErrorsCount} Syntax Error${syntaxErrorsCount === 1 ? '' : 's'}`,
        message: 'AST parsing encountered invalid Python syntax. Fix syntax errors to trace resources.'
      });
      updateWorkflowProgress(3, 'SYNTAX_ERRORS', { sub: `${syntaxErrorsCount} Errors` });
    } else {
      setStatus('PASS');
      updateWorkflowProgress(3, 'SCAN_COMPLETE', { sub: 'All Clean' });
    }

    // 5. Syntax Errors
    const syntaxItems = data.syntax_errors_list || data.syntax_errors || [];
    if (syntaxPanel && syntaxList) {
      if (Array.isArray(syntaxItems) && syntaxItems.length > 0) {
        syntaxPanel.style.display = 'block';
        if (syntaxCountBadge) syntaxCountBadge.textContent = `${syntaxItems.length} error${syntaxItems.length === 1 ? '' : 's'}`;
        syntaxList.innerHTML = syntaxItems.map(err => `
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
      }
    }

    // 6. Actionable Findings & Fixes
    const findings = data.findings || [];
    if (findingsCountBadge) findingsCountBadge.textContent = `${findings.length} finding${findings.length === 1 ? '' : 's'}`;

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
          const sevStr = (finding.severity || 'HIGH').toUpperCase();
          const sevClass = `severity-${sevStr.toLowerCase()}`;
          const badgeClass = `badge-severity-${sevStr.toLowerCase()}`;
          const isFixable = finding.is_fixable !== false;
          const findingId = finding.id || `f_${finding.file}_${finding.line}`;

          return `
            <article class="finding-card ${sevClass}" id="card-${escapeHtml(findingId)}" data-finding-id="${escapeHtml(findingId)}">
              <div class="finding-header">
                <div class="finding-title-group">
                  <span class="badge ${badgeClass}">${escapeHtml(sevStr)}</span>
                  <div class="finding-file-info">
                    <span class="finding-file-path">${escapeHtml(finding.file)}</span>
                    <span class="finding-line-badge">Line ${escapeHtml(String(finding.line))}</span>
                  </div>
                </div>
                <div class="finding-resource-badge">Resource: ${escapeHtml(finding.resource || finding.resource_name || 'File')}</div>
              </div>

              <div class="finding-section">
                <div class="finding-section-label">Problem / Vulnerability:</div>
                <div class="finding-reason-text">${escapeHtml(finding.problem || finding.reason || 'Resource leak detected')}</div>
              </div>

              <div class="finding-section">
                <div class="finding-section-label">Why It Is Dangerous:</div>
                <div class="finding-why-dangerous">
                  🛡️ ${escapeHtml(finding.why_dangerous || 'Unclosed resources cause file descriptor starvation and memory leaks.')}
                </div>
              </div>

              <div class="finding-actions-row">
                <button class="btn btn-view-code" data-action="view-code" data-finding-id="${escapeHtml(findingId)}">
                  <span>👁️ View Code</span>
                </button>
                ${isFixable ? `
                  <button class="btn btn-generate-fix" data-action="generate-fix" data-finding-id="${escapeHtml(findingId)}">
                    <span>⚡ Generate Fix</span>
                  </button>
                ` : `
                  <span class="btn btn-manual-review" title="Interprocedural transfer or non-standard pattern">
                    <span>⚠️ Manual Fix Required</span>
                  </span>
                `}
              </div>
            </article>
          `;
        }).join('');

        // Attach event listeners to finding card buttons
        findingsContainer.querySelectorAll('button[data-action="view-code"]').forEach(btn => {
          btn.addEventListener('click', () => {
            const fId = btn.getAttribute('data-finding-id');
            const finding = findings.find(f => (f.id || `f_${f.file}_${f.line}`) === fId);
            if (finding) openCodeViewModal(finding);
          });
        });

        findingsContainer.querySelectorAll('button[data-action="generate-fix"]').forEach(btn => {
          btn.addEventListener('click', () => {
            const fId = btn.getAttribute('data-finding-id');
            const finding = findings.find(f => (f.id || `f_${f.file}_${f.line}`) === fId);
            if (finding) triggerGenerateFix(finding);
          });
        });
      }
    }

    // 7. Parsed Files Inventory Table
    const files = data.files || [];
    if (filesCountBadge) filesCountBadge.textContent = `${files.length} items`;
    if (tbody) {
      if (files.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No individual file records.</td></tr>`;
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

  // -------------------------------------------------------------
  // Scan Execution
  // -------------------------------------------------------------
  async function runScan() {
    if (isScanning) return;
    isScanning = true;

    if (btnScan) btnScan.disabled = true;
    if (btnScanText) btnScanText.textContent = 'Scanning AST...';

    updateWorkflowProgress(2, 'SCANNING', { sub: 'Analyzing...' });
    setStatus('SCANNING', {
      step: 'Discovering Python files...',
      desc: `Analyzing Abstract Syntax Trees in workspace '${currentProjectName}'...`
    });

    try {
      const payload = {
        workspace_id: currentWorkspaceId,
        target: scanTargetSelect ? scanTargetSelect.value : ''
      };

<<<<<<< Updated upstream
      const res = await fetch('/api/projects/workspace/scan', {
=======
      const uploadEndpoint = mode === 'folder' ? '/api/scan/upload-folder' : '/api/scan/upload-file';
      let res = await fetch(uploadEndpoint, {
>>>>>>> Stashed changes
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).catch(() => null);

      if (!res || res.status === 404) {
        res = await fetch('/api/scan/upload', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
      }

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Scan failed (HTTP ${res.status})`);
      }

      const reportData = await res.json();
      renderScanReport(reportData, new Date());
      updateVerifySummary();
    } catch (err) {
      console.error('[LeakGuard] Scan error:', err);
      setStatus('ERROR', {
        title: 'Scan Error',
        message: err.message || 'Could not execute static AST scan.'
      });
    } finally {
      isScanning = false;
      if (btnScan) btnScan.disabled = false;
      if (btnScanText) btnScanText.textContent = 'Scan Project';
    }
  }

  // -------------------------------------------------------------
  // ZIP Upload Handling
  // -------------------------------------------------------------
  async function handleZipUpload(file) {
    if (!file || isScanning) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      alert('Please upload a valid .zip archive.');
      return;
    }

    isScanning = true;
    updateWorkflowProgress(1, 'UPLOADING', { sub: 'Unzipping...' });
    setStatus('UPLOADING', {
      desc: `Safely extracting '${file.name}' into isolated sandbox...`
    });

    try {
      const formData = new FormData();
      formData.append('file', file, file.name);

      const res = await fetch('/api/projects/upload-zip', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `ZIP upload failed (HTTP ${res.status})`);
      }

      const wsData = await res.json();
      currentWorkspaceId = wsData.workspace_id;
      currentProjectName = wsData.project_name;

      if (wsProjectName) wsProjectName.textContent = wsData.project_name;
      if (wsStatusBadge) {
        wsStatusBadge.textContent = 'Extracted & Ready';
        wsStatusBadge.className = 'badge badge-clean';
      }
      if (wsFilesCount) wsFilesCount.textContent = `${wsData.files_count} Python files`;
      if (wsLinesCount) wsLinesCount.textContent = `${wsData.lines_count.toLocaleString()} lines`;

      updateWorkflowProgress(1, 'UPLOADED', { sub: 'Extracted' });
      setStatus('IDLE');

      // Automatically run scan on newly extracted ZIP project
      await runScan();
    } catch (err) {
      console.error('[LeakGuard] ZIP upload error:', err);
      setStatus('ERROR', {
        title: 'ZIP Extraction Error',
        message: err.message
      });
      updateWorkflowProgress(1, 'ERROR', { sub: 'Failed' });
    } finally {
      isScanning = false;
    }
  }

  // -------------------------------------------------------------
  // Code View Modal
  // -------------------------------------------------------------
  async function openCodeViewModal(finding) {
    activeFinding = finding;
    if (!modalCodeView) return;

    modalCodeView.style.display = 'flex';
    if (codeModalBadge) {
      codeModalBadge.textContent = (finding.severity || 'HIGH').toUpperCase();
      codeModalBadge.className = `badge badge-severity-${(finding.severity || 'high').toLowerCase()}`;
    }
    if (codeModalTitle) codeModalTitle.textContent = finding.problem || 'Resource Leak Finding';
    if (codeModalSubtitle) codeModalSubtitle.textContent = `${finding.file} : line ${finding.line}`;
    if (codeModalCallout) codeModalCallout.textContent = `Problem: ${finding.problem || finding.reason}`;
    if (codeModalLines) codeModalLines.innerHTML = '<div class="empty-state">Loading source code...</div>';

    try {
      const res = await fetch(`/api/projects/workspace/file?workspace_id=${encodeURIComponent(currentWorkspaceId)}&file=${encodeURIComponent(finding.file)}&line=${finding.line}`);
      if (!res.ok) throw new Error('Could not fetch file content.');
      const fileData = await res.json();

      if (codeModalLines && fileData.lines) {
        codeModalLines.innerHTML = fileData.lines.map(lineObj => `
          <div class="code-line ${lineObj.is_target ? 'target-line' : ''}">
            <span class="code-line-num">${lineObj.line_number}</span>
            <span class="code-line-text">${escapeHtml(lineObj.code)}</span>
          </div>
        `).join('');
      }
    } catch (e) {
      if (codeModalLines) codeModalLines.innerHTML = `<div class="empty-state">Error loading code: ${escapeHtml(e.message)}</div>`;
    }
  }

  function closeCodeModal() {
    if (modalCodeView) modalCodeView.style.display = 'none';
  }

  // -------------------------------------------------------------
  // Fix Generation & Diff Reviewer
  // -------------------------------------------------------------
  async function triggerGenerateFix(finding) {
    if (isFixing) return;
    isFixing = true;
    activeFinding = finding;

    updateWorkflowProgress(4, 'GENERATING_FIX', { sub: 'Synthesizing...' });

    try {
      const payload = {
        workspace_id: currentWorkspaceId,
        finding_id: finding.id,
        finding: finding
      };

      const res = await fetch('/api/findings/generate-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || 'Failed to generate fix.');
      }

      const fixData = await res.json();
      activeFix = fixData.fix;
      openDiffModal(fixData.fix, fixData.diff);
      updateWorkflowProgress(4, 'FIX_READY', { sub: 'Review Diff' });
    } catch (err) {
      alert(`Fix generation error: ${err.message}`);
      updateWorkflowProgress(3, 'FINDINGS_FOUND', { sub: 'Fix Failed' });
    } finally {
      isFixing = false;
    }
  }

  function openDiffModal(fix, diffData) {
    if (!modalDiffView) return;
    closeCodeModal();

    modalDiffView.style.display = 'flex';
    if (diffModalTitle) diffModalTitle.textContent = `Safe Remediation: ${fix.rule_id}`;
    if (diffModalSubtitle) diffModalSubtitle.textContent = `${fix.rel_file} (Line ${fix.line})`;
    if (diffStatAdditions) diffStatAdditions.textContent = `+${diffData.additions || 0}`;
    if (diffStatDeletions) diffStatDeletions.textContent = `-${diffData.deletions || 0}`;
    if (diffStatRule) diffStatRule.textContent = `Rule: ${fix.rule_id} • Variable: ${fix.modified_code ? 'Auto-Wrapped' : 'Patch'}`;

    if (diffBeforeBox) diffBeforeBox.innerHTML = `<code>${escapeHtml(fix.original_code)}</code>`;
    if (diffAfterBox) diffAfterBox.innerHTML = `<code>${escapeHtml(fix.modified_code)}</code>`;

    if (diffVerifyProgress) diffVerifyProgress.style.display = 'none';
    if (diffVerifyResult) diffVerifyResult.style.display = 'none';
    if (btnApplyDiff) {
      btnApplyDiff.disabled = false;
      if (btnApplyDiffText) btnApplyDiffText.textContent = 'Apply Fix & Verify';
    }
  }

  function closeDiffModal() {
    if (modalDiffView) modalDiffView.style.display = 'none';
  }

  // -------------------------------------------------------------
  // Apply Fix & Re-scan Verification
  // -------------------------------------------------------------
  async function applyFixAndVerify() {
    if (!activeFix || isFixing) return;
    isFixing = true;

    if (btnApplyDiff) btnApplyDiff.disabled = true;
    if (btnApplyDiffText) btnApplyDiffText.textContent = 'Applying & Verifying...';

    if (diffVerifyProgress) {
      diffVerifyProgress.style.display = 'flex';
      if (diffVerifyText) diffVerifyText.textContent = 'Applying patch to workspace file, validating Python AST syntax, and re-scanning...';
    }
    if (diffVerifyResult) diffVerifyResult.style.display = 'none';

    updateWorkflowProgress(5, 'VERIFYING', { sub: 'Re-scanning...' });

    try {
      const payload = {
        workspace_id: currentWorkspaceId,
        fix_id: activeFix.fix_id
      };

      const res = await fetch('/api/findings/apply-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const resData = await res.json();
      if (!res.ok || !resData.verified) {
        throw new Error(resData.error || 'Verification failed: issue is still detected after patch.');
      }

      if (diffVerifyProgress) diffVerifyProgress.style.display = 'none';
      if (diffVerifyResult) {
        diffVerifyResult.style.display = 'block';
        diffVerifyResult.innerHTML = `
          <strong>✓ Patch Applied & Verified!</strong><br>
          AST Static Analysis confirmed: Resource leak on line ${activeFix.line} of <code>${escapeHtml(activeFix.rel_file)}</code> is completely resolved.
        `;
      }

      updateWorkflowProgress(5, 'VERIFIED', { sub: 'Verified ✓' });

      // Refresh scan dashboard
      setTimeout(async () => {
        closeDiffModal();
        await runScan();
        await updateVerifySummary();
      }, 1200);

    } catch (err) {
      if (diffVerifyProgress) diffVerifyProgress.style.display = 'none';
      if (diffVerifyResult) {
        diffVerifyResult.style.display = 'block';
        diffVerifyResult.style.borderColor = 'var(--accent-red)';
        diffVerifyResult.style.color = '#fca5a5';
        diffVerifyResult.innerHTML = `<strong>✗ Fix Verification Failed:</strong> ${escapeHtml(err.message)}<br>Original code was restored safely.`;
      }
      if (btnApplyDiff) btnApplyDiff.disabled = false;
      if (btnApplyDiffText) btnApplyDiffText.textContent = 'Retry Apply Fix';
      updateWorkflowProgress(4, 'FIX_FAILED', { sub: 'Failed' });
    } finally {
      isFixing = false;
    }
  }

  // -------------------------------------------------------------
  // Update Verify Summary & Commit Panel
  // -------------------------------------------------------------
  async function updateVerifySummary() {
    try {
      const res = await fetch(`/api/projects/workspace/verify-summary?workspace_id=${encodeURIComponent(currentWorkspaceId)}`);
      if (!res.ok) return;
      const summary = await res.json();

      if (statIssuesDetected) statIssuesDetected.textContent = summary.total_issues || 0;
      if (statAutoFixed) statAutoFixed.textContent = summary.automatically_fixed || 0;
      if (statManualReview) statManualReview.textContent = summary.manual_review_required || 0;

      const files = summary.files_changed || [];
      if (statFilesChanged) {
        statFilesChanged.textContent = files.length > 0 ? files.join(', ') : 'None';
      }
      if (statLinesAdded) statLinesAdded.textContent = `+${summary.lines_added || 0}`;
      if (statLinesRemoved) statLinesRemoved.textContent = `-${summary.lines_removed || 0}`;

      if (verifyStatusBadge) {
        verifyStatusBadge.textContent = `${summary.automatically_fixed} Verified Fix${summary.automatically_fixed === 1 ? '' : 'es'}`;
      }

      if (summary.automatically_fixed > 0) {
        if (commitWorkflowPanel) commitWorkflowPanel.style.display = 'block';
        if (btnCommitChanges) btnCommitChanges.disabled = false;
        if (btnCreatePr) btnCreatePr.disabled = false;
        updateWorkflowProgress(6, 'COMMIT_READY', { sub: 'Ready' });
      }
    } catch (e) {
      console.warn('Could not fetch verify summary:', e);
    }
  }

  // -------------------------------------------------------------
  // Git Commit & Pull Request Handlers
  // -------------------------------------------------------------
  async function handleCommitChanges() {
    if (btnCommitChanges) btnCommitChanges.disabled = true;
    updateWorkflowProgress(6, 'COMMITTING', { sub: 'Creating Branch...' });

    try {
      const payload = {
        workspace_id: currentWorkspaceId,
        branch_name: inputBranchName ? inputBranchName.value.trim() : '',
        commit_message: inputCommitMsg ? inputCommitMsg.value.trim() : ''
      };

      const res = await fetch('/api/github/commit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const resData = await res.json();
      if (!res.ok) throw new Error(resData.error || 'Commit failed.');

      if (gitActionResult) {
        gitActionResult.style.display = 'block';
        const commitUrl = resData.commit_url;
        const commitLink = commitUrl 
          ? `<a href="${escapeHtml(commitUrl)}" target="_blank" class="btn btn-secondary btn-sm" style="display:inline-flex;align-items:center;margin-top:0.5rem;text-decoration:none;">🔗 View Commit on GitHub</a>` 
          : '';
        gitActionResult.innerHTML = `
          <strong>✓ Changes Committed Successfully!</strong><br>
          • <strong>Branch:</strong> <code>${escapeHtml(resData.branch)}</code><br>
          • <strong>Commit SHA:</strong> <code>${escapeHtml(resData.commit_sha || resData.commit_hash)}</code><br>
          • <strong>Files:</strong> ${escapeHtml((resData.files_committed || []).join(', '))}<br>
          • <strong>Message:</strong> "${escapeHtml(resData.commit_message)}"<br>
          ${commitLink}
        `;
      }
      updateWorkflowProgress(6, 'COMMITTED', { sub: 'Committed ✓' });
    } catch (err) {
      alert(`Commit error: ${err.message}`);
      if (btnCommitChanges) btnCommitChanges.disabled = false;
    }
  }

  async function handleCreatePullRequest() {
    if (btnCreatePr) btnCreatePr.disabled = true;
    updateWorkflowProgress(6, 'CREATING_PR', { sub: 'Opening PR...' });

    try {
      const payload = {
        workspace_id: currentWorkspaceId,
        branch_name: inputBranchName ? inputBranchName.value.trim() : '',
        title: 'LeakGuard: Fix detected resource leaks',
        description: ''
      };

      const res = await fetch('/api/github/pull-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const resData = await res.json();
      if (!res.ok) throw new Error(resData.error || 'Pull Request failed.');

      if (gitActionResult) {
        gitActionResult.style.display = 'block';
        gitActionResult.innerHTML = `
          <strong>🎉 Pull Request #${resData.pr_number} Created!</strong><br>
          • PR Title: <strong>${escapeHtml(resData.title)}</strong><br>
          • Branch: <code>${escapeHtml(resData.branch)}</code> → <code>${escapeHtml(resData.base)}</code><br>
          • Link: <a href="${escapeHtml(resData.pr_url)}" target="_blank" style="color: var(--accent-cyan); text-decoration: underline;">${escapeHtml(resData.pr_url)}</a>
        `;
      }
      updateWorkflowProgress(6, 'PR_CREATED', { sub: 'PR Open 🐙' });
    } catch (err) {
      alert(`Pull Request error: ${err.message}`);
      if (btnCreatePr) btnCreatePr.disabled = false;
    }
  }

  // -------------------------------------------------------------
  // GitHub Integration & OAuth Controller
  // -------------------------------------------------------------
  async function checkGitHubStatus(openModalOnAuth = false) {
    try {
      const res = await fetch('/api/github/status');
      if (!res.ok) return;
      const data = await res.json();
      githubState.authenticated = !!data.authenticated;
      githubState.user = data.user || null;
      githubState.connected_repo = data.connected_repo || null;

      updateGitHubCardAndHeader();

      if (openModalOnAuth && githubState.authenticated) {
        openGitHubModal();
      }
    } catch (e) {
      console.warn('Could not check GitHub status:', e);
    }
  }

  function updateGitHubCardAndHeader() {
    if (githubState.connected_repo) {
      const { repository, branch } = githubState.connected_repo;
      if (ghCardTitle) ghCardTitle.textContent = repository;
      if (ghCardDesc) ghCardDesc.textContent = `Active branch: ${branch}`;
      if (ghCardConnectedDetails) ghCardConnectedDetails.style.display = 'flex';
      if (ghCardRepoName) ghCardRepoName.textContent = repository;
      if (ghCardBranchName) ghCardBranchName.textContent = `🌿 ${branch}`;
      if (btnOpenGithubModal) btnOpenGithubModal.style.display = 'none';
      if (ghCardConnectedBtns) ghCardConnectedBtns.style.display = 'flex';
      if (headerGithubRepo) headerGithubRepo.textContent = `${repository} (${branch})`;
    } else if (githubState.authenticated && githubState.user) {
      if (ghCardTitle) ghCardTitle.textContent = `Connected as @${githubState.user.login}`;
      if (ghCardDesc) ghCardDesc.textContent = 'Select a repository to analyze and remediate Python code.';
      if (ghCardConnectedDetails) ghCardConnectedDetails.style.display = 'none';
      if (btnOpenGithubModal) btnOpenGithubModal.style.display = 'inline-flex';
      if (btnOpenGithubText) btnOpenGithubText.textContent = 'Browse Repositories';
      if (ghCardConnectedBtns) ghCardConnectedBtns.style.display = 'none';
      if (headerGithubRepo) headerGithubRepo.textContent = `@${githubState.user.login}`;
    } else {
      if (ghCardTitle) ghCardTitle.textContent = 'Connect GitHub';
      if (ghCardDesc) ghCardDesc.textContent = 'Link remote repository to commit verified security fixes and generate PRs.';
      if (ghCardConnectedDetails) ghCardConnectedDetails.style.display = 'none';
      if (btnOpenGithubModal) btnOpenGithubModal.style.display = 'inline-flex';
      if (btnOpenGithubText) btnOpenGithubText.textContent = 'Connect GitHub';
      if (ghCardConnectedBtns) ghCardConnectedBtns.style.display = 'none';
      if (headerGithubRepo) headerGithubRepo.textContent = 'Local Workspace';
    }
  }

  function openGitHubModal() {
    if (modalGithubConnect) modalGithubConnect.style.display = 'flex';
    setGitHubModalStatus('', 'none');
    refreshGitHubModal();
  }

  function closeGitHubModal() {
    if (modalGithubConnect) modalGithubConnect.style.display = 'none';
    setGitHubModalStatus('', 'none');
  }

  function setGitHubModalStatus(message, type = 'info') {
    if (!ghModalStatusBox) return;
    if (!message) {
      ghModalStatusBox.style.display = 'none';
      return;
    }
    ghModalStatusBox.style.display = 'flex';
    ghModalStatusBox.className = `gh-modal-status-box ${type}`;
    if (ghModalSpinner) ghModalSpinner.style.display = type === 'loading' ? 'inline-block' : 'none';
    if (ghModalStatusText) ghModalStatusText.textContent = message;
  }

  async function refreshGitHubModal() {
    if (!githubState.authenticated) {
      if (ghViewUnauthenticated) ghViewUnauthenticated.style.display = 'flex';
      if (ghViewAuthenticated) ghViewAuthenticated.style.display = 'none';
      if (btnSaveGithubConnect) btnSaveGithubConnect.disabled = true;

      try {
        const res = await fetch('/api/github/auth');
        if (res.ok) {
          const authData = await res.json();
          githubState.oauth_configured = !!authData.configured;
          githubState.oauth_url = authData.authorize_url || null;

          if (ghDevModeBox) {
            ghDevModeBox.style.display = authData.configured ? 'none' : 'block';
            if (ghDevText && authData.dev_mode) {
              ghDevText.textContent = authData.message || 'OAuth not configured. You can use local simulated repositories or provide GITHUB_CLIENT_ID.';
            }
          }
        }
      } catch (e) {
        console.warn('Could not check OAuth config:', e);
      }
    } else {
      if (ghViewUnauthenticated) ghViewUnauthenticated.style.display = 'none';
      if (ghViewAuthenticated) ghViewAuthenticated.style.display = 'block';

      if (ghUserName) ghUserName.textContent = `@${githubState.user ? githubState.user.login : 'user'}`;
      if (ghUserAvatar && githubState.user && githubState.user.avatar_url) {
        ghUserAvatar.src = githubState.user.avatar_url;
      }

      await loadGitHubRepositories();
    }
  }

  async function loadGitHubRepositories() {
    if (!ghRepoList) return;
    ghRepoList.innerHTML = '<div class="empty-state"><div class="spinner" style="margin-bottom: 0.5rem;"></div>Loading repositories from GitHub...</div>';
    if (btnSaveGithubConnect) btnSaveGithubConnect.disabled = true;

    try {
      const res = await fetch('/api/github/repositories');
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to fetch repositories.');
      }
      const data = await res.json();
      githubState.repositories = data.repositories || [];
      renderRepositoryList(githubState.repositories);

      // If already connected, auto-select
      if (githubState.connected_repo && githubState.connected_repo.repository) {
        selectRepository(githubState.connected_repo.repository, githubState.connected_repo.branch);
      }
    } catch (err) {
      ghRepoList.innerHTML = `<div class="empty-state" style="color: #f87171;">⚠️ ${escapeHtml(err.message)}</div>`;
    }
  }

  function renderRepositoryList(repos) {
    if (!ghRepoList) return;
    const filter = ghRepoSearchInput ? ghRepoSearchInput.value.trim().toLowerCase() : '';
    const filtered = repos.filter(r => 
      r.full_name.toLowerCase().includes(filter) || 
      (r.description && r.description.toLowerCase().includes(filter))
    );

    if (filtered.length === 0) {
      ghRepoList.innerHTML = `<div class="empty-state">No repositories matching "${escapeHtml(filter)}"</div>`;
      return;
    }

    ghRepoList.innerHTML = filtered.map(repo => {
      const isSelected = githubState.selected_repo === repo.full_name;
      const updatedDate = repo.updated_at ? new Date(repo.updated_at).toLocaleDateString() : '';
      return `
        <div class="gh-repo-item ${isSelected ? 'selected' : ''}" data-repo="${escapeHtml(repo.full_name)}" data-branch="${escapeHtml(repo.default_branch || 'main')}">
          <div class="gh-repo-header">
            <span class="gh-repo-name">${escapeHtml(repo.full_name)}</span>
            <span class="gh-repo-badge">${repo.private ? '🔒 Private' : '🌐 Public'}</span>
          </div>
          ${repo.description ? `<div class="gh-repo-desc">${escapeHtml(repo.description)}</div>` : ''}
          <div class="gh-repo-meta">
            <span>🌿 ${escapeHtml(repo.default_branch || 'main')}</span>
            ${repo.language ? `<span>🐍 ${escapeHtml(repo.language)}</span>` : ''}
            ${updatedDate ? `<span>Updated ${escapeHtml(updatedDate)}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');

    // Attach click handlers
    ghRepoList.querySelectorAll('.gh-repo-item').forEach(item => {
      item.addEventListener('click', () => {
        const repoName = item.getAttribute('data-repo');
        const defaultBranch = item.getAttribute('data-branch') || 'main';
        selectRepository(repoName, defaultBranch);
      });
    });
  }

  async function selectRepository(repoName, defaultBranch = 'main') {
    githubState.selected_repo = repoName;

    // Update selected UI item
    if (ghRepoList) {
      ghRepoList.querySelectorAll('.gh-repo-item').forEach(item => {
        if (item.getAttribute('data-repo') === repoName) {
          item.classList.add('selected');
        } else {
          item.classList.remove('selected');
        }
      });
    }

    // Show branch selection
    if (ghBranchSection) ghBranchSection.style.display = 'block';
    if (ghBranchSelect) {
      ghBranchSelect.innerHTML = `<option value="${escapeHtml(defaultBranch)}">${escapeHtml(defaultBranch)} (loading...)</option>`;
    }

    if (btnSaveGithubConnect) {
      btnSaveGithubConnect.disabled = false;
      if (btnSaveGithubText) btnSaveGithubText.textContent = `Connect ${repoName.split('/')[1] || repoName}`;
    }

    // Fetch branches from API
    try {
      const res = await fetch(`/api/github/branches?repo=${encodeURIComponent(repoName)}`);
      if (res.ok && ghBranchSelect) {
        const data = await res.json();
        const branches = data.branches || [defaultBranch];
        ghBranchSelect.innerHTML = branches.map(b => 
          `<option value="${escapeHtml(b)}" ${b === defaultBranch ? 'selected' : ''}>${escapeHtml(b)}</option>`
        ).join('');
        if (ghBranchHint) {
          ghBranchHint.textContent = `${branches.length} branch${branches.length === 1 ? '' : 'es'} available`;
        }
      }
    } catch (e) {
      console.warn('Could not load branches:', e);
    }
  }

  async function connectSelectedRepository() {
    if (!githubState.selected_repo) {
      setGitHubModalStatus('Please select a repository first.', 'error');
      return;
    }

    const selectedBranch = ghBranchSelect ? ghBranchSelect.value : 'main';
    if (btnSaveGithubConnect) btnSaveGithubConnect.disabled = true;
    setGitHubModalStatus('Downloading repository archive and preparing workspace sandbox...', 'loading');

    try {
      const res = await fetch('/api/github/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: githubState.selected_repo,
          branch: selectedBranch
        })
      });

      const resData = await res.json();
      if (!res.ok) throw new Error(resData.error || 'Connection failed.');

      currentWorkspaceId = resData.workspace_id;
      currentProjectName = `${resData.repository} (${resData.base_branch})`;
      githubState.connected_repo = {
        repository: resData.repository,
        branch: resData.base_branch
      };

      if (wsProjectName) wsProjectName.textContent = currentProjectName;
      if (wsStatusBadge) {
        wsStatusBadge.textContent = 'Ready (GitHub)';
        wsStatusBadge.className = 'badge badge-clean';
      }
      if (wsFilesCount) wsFilesCount.textContent = `${resData.files_count || 0} Python files`;
      if (wsLinesCount) wsLinesCount.textContent = `~${resData.lines_count || 0} lines`;

      updateGitHubCardAndHeader();
      closeGitHubModal();

      // Immediately run static analysis on the connected repository
      await runScan();
    } catch (err) {
      setGitHubModalStatus(err.message, 'error');
      if (btnSaveGithubConnect) btnSaveGithubConnect.disabled = false;
    }
  }

  async function disconnectGitHub() {
    try {
      await fetch('/api/github/disconnect', { method: 'POST' });
      githubState.authenticated = false;
      githubState.user = null;
      githubState.connected_repo = null;
      githubState.selected_repo = null;
      updateGitHubCardAndHeader();
      closeGitHubModal();
      resetDashboard();
    } catch (e) {
      console.warn('Error disconnecting GitHub:', e);
    }
  }

  async function startGitHubOAuth() {
    if (btnGhAuthorize) {
      btnGhAuthorize.disabled = true;
      btnGhAuthorize.innerHTML = '<div class="spinner" style="display:inline-block;width:14px;height:14px;margin-right:6px;"></div> <span>Connecting to GitHub...</span>';
    }
    setGitHubModalStatus('Initiating GitHub OAuth authorization...', 'loading');

    try {
      const res = await fetch('/api/github/auth');
      const authData = await res.json();
      if (res.ok && authData.configured && (authData.auth_url || authData.authorize_url)) {
        window.location.href = authData.auth_url || authData.authorize_url;
      } else {
        if (btnGhAuthorize) {
          btnGhAuthorize.disabled = false;
          btnGhAuthorize.innerHTML = '<span class="btn-icon">🐙</span> <span>Authorize with GitHub</span>';
        }
        setGitHubModalStatus(
          authData.message || 'GitHub integration is not configured. Add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to the backend environment or .env file.',
          'error'
        );
      }
    } catch (err) {
      if (btnGhAuthorize) {
        btnGhAuthorize.disabled = false;
        btnGhAuthorize.innerHTML = '<span class="btn-icon">🐙</span> <span>Authorize with GitHub</span>';
      }
      setGitHubModalStatus(`Failed to initiate GitHub authorization: ${err.message}`, 'error');
    }
  }

  const inputQuickToken = document.getElementById('gh-input-quick-token');
  const btnQuickToken = document.getElementById('btn-gh-quick-token');

  async function handleQuickTokenConnect() {
    const rawVal = inputQuickToken ? inputQuickToken.value.trim() : '';
    if (!rawVal) {
      setGitHubModalStatus('Please enter a GitHub Personal Access Token or repository in owner/repo format.', 'error');
      return;
    }

    // If input is in owner/repo format (e.g. octocat/Hello-World), connect directly
    if (rawVal.includes('/') && !rawVal.startsWith('ghp_') && !rawVal.startsWith('github_pat_')) {
      githubState.selected_repo = rawVal;
      await connectSelectedRepository();
      return;
    }

    if (btnQuickToken) {
      btnQuickToken.disabled = true;
      btnQuickToken.innerHTML = '<div class="spinner" style="display:inline-block;width:12px;height:12px;margin-right:4px;"></div> Connecting...';
    }
    setGitHubModalStatus('Validating GitHub token with GitHub API...', 'loading');

    try {
      const res = await fetch('/api/github/auth-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: rawVal })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Token authentication failed.');

      githubState.authenticated = true;
      githubState.user = data.user;
      setGitHubModalStatus(data.message || 'Connected successfully!', 'info');
      await refreshGitHubModal();
      updateGitHubCardAndHeader();
    } catch (err) {
      setGitHubModalStatus(err.message, 'error');
    } finally {
      if (btnQuickToken) {
        btnQuickToken.disabled = false;
        btnQuickToken.innerHTML = '<span class="btn-icon">⚡</span> <span>Connect</span>';
      }
    }
  }

  // Bind GitHub Modal Events
  const githubStatusBox = document.getElementById('github-status-box');
  if (githubStatusBox) githubStatusBox.addEventListener('click', openGitHubModal);
  if (btnOpenGithubModal) btnOpenGithubModal.addEventListener('click', openGitHubModal);
  if (btnGhChangeRepo) btnGhChangeRepo.addEventListener('click', openGitHubModal);
  if (btnGhDisconnect) btnGhDisconnect.addEventListener('click', disconnectGitHub);
  if (btnCloseGithubModal) btnCloseGithubModal.addEventListener('click', closeGitHubModal);
  if (btnCancelGithubModal) btnCancelGithubModal.addEventListener('click', closeGitHubModal);
  if (btnGhAuthorize) btnGhAuthorize.addEventListener('click', startGitHubOAuth);
  if (btnQuickToken) btnQuickToken.addEventListener('click', handleQuickTokenConnect);
  if (inputQuickToken) {
    inputQuickToken.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleQuickTokenConnect();
    });
  }
  if (btnGhSignOut) btnGhSignOut.addEventListener('click', disconnectGitHub);
  if (btnSaveGithubConnect) btnSaveGithubConnect.addEventListener('click', connectSelectedRepository);

  if (ghRepoSearchInput) {
    ghRepoSearchInput.addEventListener('input', () => {
      renderRepositoryList(githubState.repositories);
    });
  }

  // Global keyboard shortcuts (Escape key closes modals)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (modalGithubConnect && modalGithubConnect.style.display !== 'none') {
        closeGitHubModal();
      }
      if (modalDiffView && modalDiffView.style.display !== 'none') {
        closeDiffModal();
      }
      if (modalCodeView && modalCodeView.style.display !== 'none') {
        closeCodeModal();
      }
    }
  });

  // -------------------------------------------------------------
  // Event Listeners
  // -------------------------------------------------------------
  if (btnScan) btnScan.addEventListener('click', runScan);
  if (btnClear) btnClear.addEventListener('click', resetDashboard);

  if (btnUploadZip && inputUploadZip) {
    btnUploadZip.addEventListener('click', () => inputUploadZip.click());
    inputUploadZip.addEventListener('change', async () => {
      if (inputUploadZip.files && inputUploadZip.files[0]) {
        const file = inputUploadZip.files[0];
        inputUploadZip.value = '';
        await handleZipUpload(file);
      }
    });
  }

  if (scanTargetSelect) {
    scanTargetSelect.addEventListener('change', () => {
      currentProjectName = scanTargetSelect.value;
      if (wsProjectName) wsProjectName.textContent = currentProjectName;
      if (wsStatusBadge) {
        wsStatusBadge.textContent = 'Ready';
        wsStatusBadge.className = 'badge badge-clean';
      }
      runScan();
    });
  }

  // Dropzone drag & drop
  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
    dropzone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;

      if (files[0].name.toLowerCase().endsWith('.zip')) {
        await handleZipUpload(files[0]);
      } else {
        runScan();
      }
    });
    dropzone.addEventListener('click', () => {
      if (inputUploadZip) inputUploadZip.click();
    });
  }

  // Modal Closures
  if (btnCloseCodeModal) btnCloseCodeModal.addEventListener('click', closeCodeModal);
  if (btnCancelCodeModal) btnCancelCodeModal.addEventListener('click', closeCodeModal);
  if (btnModalGenerateFix) {
    btnModalGenerateFix.addEventListener('click', () => {
      if (activeFinding) triggerGenerateFix(activeFinding);
    });
  }

  if (btnCloseDiffModal) btnCloseDiffModal.addEventListener('click', closeDiffModal);
  if (btnRejectDiff) btnRejectDiff.addEventListener('click', closeDiffModal);
  if (btnApplyDiff) btnApplyDiff.addEventListener('click', applyFixAndVerify);

  if (btnCommitChanges) btnCommitChanges.addEventListener('click', handleCommitChanges);
  if (btnCreatePr) btnCreatePr.addEventListener('click', handleCreatePullRequest);

  // Tab switching
  if (tabDev && tabAdmin) {
    tabDev.addEventListener('click', () => {
      tabDev.classList.add('active');
      tabAdmin.classList.remove('active');
      if (viewDev) viewDev.style.display = 'block';
      if (viewAdmin) viewAdmin.style.display = 'none';
      if (navModeBadge) {
        navModeBadge.textContent = 'Remediation Mode';
        navModeBadge.classList.remove('admin-mode');
      }
    });

    tabAdmin.addEventListener('click', () => {
      tabAdmin.classList.add('active');
      tabDev.classList.remove('active');
      if (viewAdmin) viewAdmin.style.display = 'block';
      if (viewDev) viewDev.style.display = 'none';
      if (navModeBadge) {
        navModeBadge.textContent = 'Admin Mode';
        navModeBadge.classList.add('admin-mode');
      }
      const hash = typeof window !== 'undefined' && window.location ? (window.location.hash || '') : '';
      if (hash.startsWith('#admin-')) {
        const tabName = hash.replace('#admin-', '');
        switchAdminTab(tabName);
      } else {
        switchAdminTab('overview');
      }
    });
  }

  // ============================================================
  // Admin 5-Tab Switching System
  // ============================================================
  const adminTabBtns = document.querySelectorAll('.admin-tab-btn');
  const adminPanes = {
    overview: document.getElementById('admin-pane-overview'),
    repositories: document.getElementById('admin-pane-repositories'),
    risk: document.getElementById('admin-pane-risk'),
    analytics: document.getElementById('admin-pane-analytics'),
    history: document.getElementById('admin-pane-history')
  };

  let currentAdminTab = 'overview';
  let cachedProjects = [];
  let cachedScans = [];

  function switchAdminTab(tabName) {
    const targetTab = adminPanes[tabName] ? tabName : 'overview';
    currentAdminTab = targetTab;

    // Update Tab Buttons
    adminTabBtns.forEach(btn => {
      const isTarget = btn.getAttribute('data-tab') === targetTab;
      btn.classList.toggle('active', isTarget);
      btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    });

    // Update Tab Panes
    Object.keys(adminPanes).forEach(k => {
      const pane = adminPanes[k];
      if (pane) {
        pane.style.display = k === targetTab ? 'flex' : 'none';
      }
    });

    // Update URL hash without full reload
    if (typeof history !== 'undefined' && history.replaceState) {
      history.replaceState(null, '', '#admin-' + targetTab);
    }

    // Load Tab Specific Data
    if (targetTab === 'overview') {
      loadAdminOverview();
    } else if (targetTab === 'repositories') {
      loadAdminRepositories();
    } else if (targetTab === 'risk') {
      loadAdminRiskRanking();
    } else if (targetTab === 'analytics') {
      const pFilter = document.getElementById('analytics-project-filter');
      const tFilter = document.getElementById('analytics-time-filter');
      loadAdminAnalytics(pFilter ? pFilter.value : 'all', tFilter ? tFilter.value : '30');
    } else if (targetTab === 'history') {
      loadAdminScans();
    }
  }

  // Attach click listeners to admin tab buttons
  adminTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.getAttribute('data-tab');
      switchAdminTab(tabName);
    });
  });

  const btnGotoRepos = document.getElementById('btn-goto-repositories-tab');
  if (btnGotoRepos) {
    btnGotoRepos.addEventListener('click', () => {
      switchAdminTab('repositories');
    });
  }

  // Admin Legacy alias
  async function loadAdminData() {
    await loadAdminOverview();
  }

  // ============================================================
  // Tab 1: Admin Overview Loader
  // ============================================================
  async function loadAdminOverview() {
    try {
      const summaryRes = await fetch('/api/admin/summary');
      if (summaryRes.ok) {
        const sData = await summaryRes.json();
        const sum = sData.summary || {};
        const elProj = document.getElementById('admin-val-projects');
        const elScans = document.getElementById('admin-val-scans');
        const elLeaks = document.getElementById('admin-val-open-leaks');
        const elHigh = document.getElementById('admin-val-high-severity');
        const elCi = document.getElementById('admin-val-ci-blocked');

        if (elProj) elProj.textContent = sum.total_projects || 0;
        if (elScans) elScans.textContent = sum.total_scans || 0;
        if (elLeaks) elLeaks.textContent = sum.total_open_leaks || 0;
        if (elHigh) elHigh.textContent = sum.high_severity_leaks || 0;
        if (elCi) elCi.textContent = sum.ci_blocked_projects || 0;
      }

      await loadAdminRepositories();
    } catch (e) {
      console.warn('Error loading admin overview:', e);
    }
  }

  // ============================================================
  // Tab 2: Admin Repositories Loader
  // ============================================================
  async function loadAdminRepositories() {
    try {
      const projRes = await fetch('/api/admin/projects');
      const projTbody = document.getElementById('admin-projects-tbody');
      const repoTbody = document.getElementById('admin-repositories-tbody');
      const projCountBadge = document.getElementById('admin-projects-count');
      const projSelect = document.getElementById('analytics-project-filter');
      const riskProjSelect = document.getElementById('risk-project-filter');

      if (projRes.ok) {
        const pData = await projRes.json();
        const projects = pData.projects || [];
        cachedProjects = projects;

        if (projCountBadge) {
          projCountBadge.textContent = `${projects.length} ${projects.length === 1 ? 'project' : 'projects'}`;
        }

        // Render Overview Projects Table
        if (projTbody) {
          if (projects.length === 0) {
            projTbody.innerHTML = '<tr><td colspan="7" class="empty-state">No monitored projects yet.</td></tr>';
          } else {
            projTbody.innerHTML = projects.map(p => {
              const pid = p.id || p.project_id || '';
              const score = p.security_score !== undefined ? p.security_score : (p.health_score || 100);
              const leaksCount = p.open_leaks_count !== undefined ? p.open_leaks_count : (p.open_leaks || 0);
              const status = p.health_status || p.status || 'HEALTHY';
              const lastScan = p.last_scanned_at || p.last_scan_time;

              return `
                <tr>
                  <td><span class="badge ${status === 'HEALTHY' ? 'badge-healthy' : 'badge-at-risk'}">${escapeHtml(status)}</span></td>
                  <td><strong>${escapeHtml(p.name || pid)}</strong></td>
                  <td><code>${escapeHtml(p.repository || p.target_path || '-')}</code></td>
                  <td>${score}/100</td>
                  <td>${leaksCount}</td>
                  <td>${lastScan ? formatLocalTime(new Date(lastScan)) : '-'}</td>
                  <td><button class="btn btn-secondary btn-sm" onclick="window.leakguardInspectProject('${escapeHtml(pid)}')">Inspect</button></td>
                </tr>
              `;
            }).join('');
          }
        }

        // Render Full Repositories Table
        if (repoTbody) {
          if (projects.length === 0) {
            repoTbody.innerHTML = '<tr><td colspan="8" class="empty-state">No monitored codebases found.</td></tr>';
          } else {
            repoTbody.innerHTML = projects.map(p => {
              const pid = p.id || p.project_id || '';
              const score = p.security_score !== undefined ? p.security_score : (p.health_score || 100);
              const leaksCount = p.open_leaks_count !== undefined ? p.open_leaks_count : (p.open_leaks || 0);
              const status = p.health_status || p.status || 'HEALTHY';
              const source = p.repository ? 'GitHub' : 'Local Workspace';
              const branch = p.branch || 'main';
              const lastScan = p.last_scanned_at || p.last_scan_time;

              return `
                <tr>
                  <td><span class="badge ${status === 'HEALTHY' ? 'badge-healthy' : 'badge-at-risk'}">${escapeHtml(status)}</span></td>
                  <td><strong>${escapeHtml(p.name || pid)}</strong><br/><small class="text-muted"><code>${escapeHtml(p.repository || p.target_path || '-')}</code></small></td>
                  <td><code>${escapeHtml(branch)}</code></td>
                  <td><span class="badge badge-neutral">${escapeHtml(source)}</span></td>
                  <td><strong>${score}</strong> / 100</td>
                  <td><span class="${leaksCount > 0 ? 'text-amber' : 'text-green'}">${leaksCount}</span></td>
                  <td>${lastScan ? formatLocalTime(new Date(lastScan)) : '-'}</td>
                  <td><button class="btn btn-secondary btn-sm" onclick="window.leakguardInspectProject('${escapeHtml(pid)}')">Inspect Details</button></td>
                </tr>
              `;
            }).join('');
          }
        }

        // Populate dropdown filters
        const options = ['<option value="all">All Repositories</option>'];
        projects.forEach(p => {
          const pid = p.id || p.project_id || '';
          options.push(`<option value="${escapeHtml(pid)}">${escapeHtml(p.name || pid)}</option>`);
        });

        if (projSelect) {
          const currentVal = projSelect.value;
          projSelect.innerHTML = options.join('');
          if (currentVal && projects.some(p => (p.id || p.project_id) === currentVal)) {
            projSelect.value = currentVal;
          }
        }

        if (riskProjSelect) {
          const currentVal = riskProjSelect.value;
          riskProjSelect.innerHTML = options.join('');
          if (currentVal && projects.some(p => (p.id || p.project_id) === currentVal)) {
            riskProjSelect.value = currentVal;
          }
        }
      }
    } catch (e) {
      console.warn('Error loading repositories:', e);
    }
  }

  // Global inspect project handler
  window.leakguardInspectProject = async function(projectId) {
    if (!projectId) return;
    const detailPanel = document.getElementById('admin-project-detail');
    if (!detailPanel) return;

    try {
      const res = await fetch(`/api/admin/project?id=${encodeURIComponent(projectId)}`);
      if (!res.ok) {
        alert(`Project inspection error: ${res.statusText}`);
        return;
      }
      const data = await res.json();
      const p = data.project || {};
      const latestScan = p.latest_scan || {};
      const openFindings = p.open_findings || [];
      const historyList = p.scan_history || [];

      // Badges & title
      const healthBadge = document.getElementById('detail-project-health-badge');
      const scoreBadge = document.getElementById('detail-project-score-badge');
      const nameEl = document.getElementById('detail-project-name');
      const subEl = document.getElementById('detail-project-sub');

      if (healthBadge) {
        healthBadge.textContent = p.status || 'HEALTHY';
        healthBadge.className = `badge ${p.status === 'HEALTHY' ? 'badge-healthy' : 'badge-at-risk'}`;
      }
      if (scoreBadge) scoreBadge.textContent = `Score: ${p.health_score || 100}`;
      if (nameEl) nameEl.textContent = p.name || p.project_id;
      if (subEl) subEl.textContent = p.repository || p.target_path || 'Target inspection';

      // CI Context Strip
      const ciBox = document.getElementById('detail-ci-context');
      if (ciBox) {
        if (latestScan.scan_type === 'CI' || latestScan.commit_sha) {
          ciBox.style.display = 'flex';
          const elSrc = document.getElementById('ci-source');
          const elRepo = document.getElementById('ci-repo');
          const elBranch = document.getElementById('ci-branch');
          const elCommit = document.getElementById('ci-commit');
          const elPr = document.getElementById('ci-pr');
          const elRun = document.getElementById('ci-run');

          if (elSrc) elSrc.textContent = latestScan.scan_type || 'CI';
          if (elRepo) elRepo.textContent = latestScan.repository || '-';
          if (elBranch) elBranch.textContent = latestScan.branch || '-';
          if (elCommit) elCommit.textContent = latestScan.commit_sha ? latestScan.commit_sha.substring(0, 7) : '-';
          if (elPr) elPr.textContent = latestScan.pull_request ? `#${latestScan.pull_request}` : '-';
          if (elRun) elRun.textContent = latestScan.workflow_run || '-';
        } else {
          ciBox.style.display = 'none';
        }
      }

      // Metrics
      const mFiles = document.getElementById('detail-files-scanned');
      const mClean = document.getElementById('detail-clean-files');
      const mSyntax = document.getElementById('detail-syntax-errors');
      const mLeaks = document.getElementById('detail-leaks');
      const mNew = document.getElementById('detail-new-leaks');
      const mBase = document.getElementById('detail-baseline-leaks');

      if (mFiles) mFiles.textContent = latestScan.files_scanned || 0;
      if (mClean) mClean.textContent = latestScan.clean_files || 0;
      if (mSyntax) mSyntax.textContent = latestScan.syntax_errors || 0;
      if (mLeaks) mLeaks.textContent = latestScan.leaks_detected || openFindings.length || 0;
      if (mNew) mNew.textContent = latestScan.new_leaks || openFindings.filter(f => !f.is_baseline).length || 0;
      if (mBase) mBase.textContent = latestScan.baseline_leaks || openFindings.filter(f => f.is_baseline).length || 0;

      // Findings
      const findingsContainer = document.getElementById('detail-findings-container');
      if (findingsContainer) {
        if (openFindings.length === 0) {
          findingsContainer.innerHTML = '<div class="empty-clean-state" style="padding: 1.5rem;"><div class="clean-state-icon">✅</div><div>Zero open resource leaks in codebase.</div></div>';
        } else {
          findingsContainer.innerHTML = openFindings.map(f => `
            <div class="finding-card ${f.severity === 'HIGH' ? 'severity-high' : 'severity-medium'}" style="margin-bottom: 0.75rem;">
              <div class="finding-header">
                <div>
                  <span class="badge ${f.severity === 'HIGH' ? 'badge-severity-high' : 'badge-severity-medium'}">${escapeHtml(f.severity || 'HIGH')}</span>
                  <span style="margin-left: 8px; font-weight:600;">${escapeHtml(f.file || '')}:${f.line || ''}</span>
                </div>
                <div class="finding-resource-badge">${escapeHtml(f.resource || 'Resource')}</div>
              </div>
              <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 6px;">${escapeHtml(f.reason || f.message || 'Unclosed resource')}</div>
              ${f.leak_path ? `<div style="font-size:0.75rem; color:#94a3b8; font-family:monospace; margin-top:4px;">${escapeHtml(f.leak_path)}</div>` : ''}
            </div>
          `).join('');
        }
      }

      // History Table
      const histTbody = document.getElementById('detail-history-tbody');
      if (histTbody) {
        if (historyList.length === 0) {
          histTbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scan history recorded.</td></tr>';
        } else {
          histTbody.innerHTML = historyList.map(h => `
            <tr>
              <td><span class="badge ${h.status === 'PASS' ? 'badge-clean' : 'badge-error'}">${escapeHtml(h.status || 'PASS')}</span></td>
              <td>${h.timestamp ? formatLocalTime(new Date(h.timestamp)) : '-'}</td>
              <td>${escapeHtml(h.scan_type || 'DEVELOPER')}</td>
              <td><code>${escapeHtml(h.branch || '-')}</code></td>
              <td>${h.leaks_detected || 0}</td>
              <td>${h.duration_ms ? (h.duration_ms / 1000).toFixed(3) + 's' : '-'}</td>
            </tr>
          `).join('');
        }
      }

      detailPanel.style.display = 'block';
      detailPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      console.warn('Error inspecting project:', e);
    }
  };

  const btnCloseProjDetail = document.getElementById('btn-close-project-detail');
  if (btnCloseProjDetail) {
    btnCloseProjDetail.addEventListener('click', () => {
      const detailPanel = document.getElementById('admin-project-detail');
      if (detailPanel) detailPanel.style.display = 'none';
    });
  }

  // ============================================================
  // Tab 3: Risk Ranking Loader
  // ============================================================
  async function loadAdminRiskRanking() {
    const riskTbody = document.getElementById('admin-risk-tbody');
    if (!riskTbody) return;

    try {
      const pRes = await fetch('/api/admin/projects');
      if (!pRes.ok) return;

      const pData = await pRes.json();
      const projects = pData.projects || [];

      if (projects.length === 0) {
        riskTbody.innerHTML = '<tr><td colspan="6" class="empty-state">No monitored repositories to rank.</td></tr>';
        return;
      }

      // Compute density metrics based on persisted project findings
      const rankedProjects = projects.map(p => {
        const leaks = Number(p.open_leaks_count !== undefined ? p.open_leaks_count : (p.open_leaks || 0));
        const score = Number(p.security_score !== undefined ? p.security_score : (p.health_score || 100));
        const files = Number(p.files_scanned || 5);
        // Density index formula: (leaks / files) * 10 or leaks normalized
        const density = files > 0 ? ((leaks / files) * 10).toFixed(1) : (leaks * 2).toFixed(1);
        return { ...p, leaks, score, density: parseFloat(density) };
      });

      // Sort descending by risk (highest leaks / lowest security score)
      rankedProjects.sort((a, b) => b.leaks - a.leaks || a.score - b.score);

      riskTbody.innerHTML = rankedProjects.map((p, idx) => {
        const leaks = p.leaks;
        let trendBadgeClass = 'badge-risk-clean';
        let trendLabel = 'CLEAN';

        if (leaks >= 5) {
          trendBadgeClass = 'badge-risk-critical';
          trendLabel = 'CRITICAL';
        } else if (leaks > 0) {
          trendBadgeClass = 'badge-risk-elevated';
          trendLabel = 'ELEVATED';
        } else {
          trendBadgeClass = 'badge-risk-clean';
          trendLabel = 'STABLE';
        }

        const lastScan = p.last_scanned_at || p.last_scan_time;

        return `
          <tr>
            <td><strong>#${idx + 1}</strong></td>
            <td><strong>${escapeHtml(p.name || p.id)}</strong><br/><small class="text-muted"><code>${escapeHtml(p.repository || p.target_path || '-')}</code></small></td>
            <td><strong>${p.density}</strong> <span class="text-muted" style="font-size:0.75rem;">/ 10 Files</span></td>
            <td><span class="badge ${trendBadgeClass}">${trendLabel}</span></td>
            <td>${lastScan ? formatLocalTime(new Date(lastScan)) : '-'}</td>
            <td><span class="badge ${p.health_status === 'HEALTHY' ? 'badge-healthy' : 'badge-at-risk'}">${escapeHtml(p.health_status || p.status || 'HEALTHY')}</span></td>
          </tr>
        `;
      }).join('');

    } catch (e) {
      console.warn('Error loading risk ranking:', e);
      riskTbody.innerHTML = '<tr><td colspan="6" class="empty-state">Unable to calculate risk rankings.</td></tr>';
    }
  }

  // Export Risk Ranking CSV
  const btnExportRisk = document.getElementById('btn-export-risk-ranking');
  if (btnExportRisk) {
    btnExportRisk.addEventListener('click', () => {
      if (!cachedProjects || cachedProjects.length === 0) {
        alert('No risk ranking data available to export.');
        return;
      }
      let csv = 'Rank,Repository,Target,Health Score,Open Leaks,Status\n';
      cachedProjects.forEach((p, idx) => {
        csv += `${idx + 1},"${p.name || p.id}","${p.repository || p.target_path}",${p.security_score || p.health_score || 100},${p.open_leaks_count || 0},"${p.health_status || p.status || 'HEALTHY'}"\n`;
      });
      downloadBlob(csv, 'leakguard_risk_ranking.csv', 'text/csv');
    });
  }

  // ============================================================
  // Tab 4: Admin Analytics Loader
  // ============================================================
  async function loadAdminAnalytics(projectId, timeRange) {
    const emptyMsg = document.getElementById('analytics-empty-message');
    const emptyState = document.getElementById('analytics-empty-state');
    const contentBox = document.getElementById('analytics-content');

    if (emptyMsg) {
      emptyMsg.textContent = 'Loading analytics...';
      emptyMsg.style.display = 'block';
    }

    try {
      const pId = projectId || 'all';
      const tRange = timeRange || '30';
      const res = await fetch(`/api/admin/analytics?project_id=${encodeURIComponent(pId)}&time_range=${encodeURIComponent(tRange)}`);
      if (!res.ok) {
        if (emptyMsg) {
          emptyMsg.textContent = 'Unable to load analytics. Please try again.';
          emptyMsg.style.display = 'block';
        }
        return;
      }

      const data = await res.json();
      const analytics = data.analytics || data;

      // Update meta badges
      const totalLeaksEl = document.getElementById('analytics-meta-total-leaks');
      const unknownEl = document.getElementById('analytics-meta-unknown');
      const periodEl = document.getElementById('analytics-meta-period');

      if (totalLeaksEl) {
        totalLeaksEl.textContent = `Confirmed Leaks: ${analytics.total_confirmed_leaks || 0}`;
      }
      if (unknownEl) {
        unknownEl.textContent = `Unknown Ownership: ${analytics.unknown_ownership_count || analytics.unknown_count || 0} (Excluded)`;
      }
      if (periodEl) {
        const periodLabels = { '7': 'Last 7 Days', '30': 'Last 30 Days', '90': 'Last 90 Days', 'all': 'All Time' };
        periodEl.textContent = `Period: ${periodLabels[tRange] || tRange}`;
      }

      // Empty message handling
      const hasData = (analytics.trend && analytics.trend.length > 0) || (analytics.resource_types && analytics.resource_types.length > 0);

      if (!hasData) {
        if (emptyMsg) {
          emptyMsg.textContent = 'No historical scan data for this period.';
          emptyMsg.style.display = 'block';
        }
      } else {
        if (emptyMsg) emptyMsg.style.display = 'none';
      }

      // Render Visualizations
      renderTrendChart(analytics.trend || []);
      renderResourceTypes(analytics.resource_types || []);
      renderLeakIntelligence(analytics);

    } catch (e) {
      console.warn('Error loading analytics:', e);
      if (emptyMsg) {
        emptyMsg.textContent = 'Unable to load analytics. Please try again.';
        emptyMsg.style.display = 'block';
      }
    }
  }

  // Render SVG Resource Leak Trend Chart
  function renderTrendChart(trend) {
    const svg = document.getElementById('trend-svg-chart');
    const badge = document.getElementById('analytics-trend-badge');
    const tooltip = document.getElementById('trend-chart-tooltip');
    if (!svg) return;

    if (badge) {
      badge.textContent = `${trend.length} ${trend.length === 1 ? 'Scan' : 'Scans'}`;
    }

    if (!trend || trend.length === 0) {
      svg.innerHTML = `
        <text x="270" y="110" text-anchor="middle" fill="#64748b" font-size="13" font-family="Inter, sans-serif">
          No historical scan data for this period.
        </text>
      `;
      return;
    }

    const width = 540;
    const height = 220;
    const padLeft = 45;
    const padRight = 25;
    const padTop = 25;
    const padBottom = 35;

    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const maxLeaks = Math.max(...trend.map(t => Number(t.leak_count || t.leaks) || 0), 4);
    const yTicks = 4;

    // Build SVG Grids & Y-axis labels
    let svgContent = `
      <defs>
        <linearGradient id="trendAreaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#ef4444" stop-opacity="0.35"/>
          <stop offset="100%" stop-color="#ef4444" stop-opacity="0.02"/>
        </linearGradient>
        <linearGradient id="trendLineGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#f87171"/>
          <stop offset="100%" stop-color="#ef4444"/>
        </linearGradient>
      </defs>
    `;

    // Horizontal gridlines & Y labels
    for (let i = 0; i <= yTicks; i++) {
      const yVal = Math.round((maxLeaks / yTicks) * (yTicks - i));
      const yPos = padTop + (chartH / yTicks) * i;
      svgContent += `
        <line x1="${padLeft}" y1="${yPos}" x2="${padLeft + chartW}" y2="${yPos}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" stroke-width="1" />
        <text x="${padLeft - 8}" y="${yPos + 4}" text-anchor="end" fill="#64748b" font-size="10" font-family="Inter, sans-serif">${yVal}</text>
      `;
    }

    // Coordinates calculation
    const points = trend.map((item, idx) => {
      const x = trend.length === 1 
        ? padLeft + chartW / 2 
        : padLeft + (idx / (trend.length - 1)) * chartW;
      const count = Number(item.leak_count || item.leaks) || 0;
      const y = padTop + chartH - (count / maxLeaks) * chartH;
      return { x, y, item, idx };
    });

    // Area path
    if (points.length > 1) {
      let areaD = `M ${points[0].x} ${padTop + chartH}`;
      points.forEach(p => { areaD += ` L ${p.x.toFixed(1)} ${p.y.toFixed(1)}`; });
      areaD += ` L ${points[points.length - 1].x} ${padTop + chartH} Z`;
      svgContent += `<path d="${areaD}" fill="url(#trendAreaGrad)" />`;
    }

    // Line path
    if (points.length > 1) {
      let lineD = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
      for (let i = 1; i < points.length; i++) {
        lineD += ` L ${points[i].x.toFixed(1)} ${points[i].y.toFixed(1)}`;
      }
      svgContent += `<path d="${lineD}" fill="none" stroke="url(#trendLineGrad)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />`;
    }

    // X-axis baseline
    svgContent += `
      <line x1="${padLeft}" y1="${padTop + chartH}" x2="${padLeft + chartW}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.12)" stroke-width="1.5" />
    `;

    // Data points & X labels
    points.forEach((p, idx) => {
      // X Label
      const labelText = `S${idx + 1}`;
      svgContent += `
        <text x="${p.x.toFixed(1)}" y="${padTop + chartH + 18}" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="Inter, sans-serif">${labelText}</text>
      `;

      // Point circle
      svgContent += `
        <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="5.5" fill="#ef4444" stroke="#0f172a" stroke-width="2.5" class="trend-point" data-idx="${idx}" style="cursor: pointer; transition: transform 0.15s ease;" />
      `;
    });

    svg.innerHTML = svgContent;

    // Tooltip interaction
    const circles = svg.querySelectorAll('.trend-point');
    circles.forEach(circle => {
      circle.addEventListener('mouseenter', (e) => {
        const idx = parseInt(circle.getAttribute('data-idx'), 10);
        const pt = points[idx];
        if (!pt || !tooltip) return;

        const scanId = pt.item.scan_id ? pt.item.scan_id.substring(0, 8) : `Scan #${idx + 1}`;
        const dateStr = pt.item.timestamp || pt.item.scanned_at ? formatLocalTime(new Date(pt.item.timestamp || pt.item.scanned_at)) : 'N/A';
        const leakCount = pt.item.leak_count !== undefined ? pt.item.leak_count : (pt.item.leaks || 0);

        tooltip.innerHTML = `
          <div style="font-weight:600; color:#f8fafc; margin-bottom:2px;">Scan ${escapeHtml(scanId)}</div>
          <div style="color:#ef4444; font-size:12px; margin-bottom:2px;"><strong>${leakCount}</strong> confirmed ${leakCount === 1 ? 'leak' : 'leaks'}</div>
          <div style="color:#94a3b8; font-size:10px;">${escapeHtml(dateStr)}</div>
        `;
        tooltip.style.display = 'block';

        const rect = svg.getBoundingClientRect();
        const wrapperRect = svg.parentElement.getBoundingClientRect();
        const scaleX = rect.width / width;
        const scaleY = rect.height / height;
        const tipX = pt.x * scaleX;
        const tipY = pt.y * scaleY;

        tooltip.style.left = `${Math.min(Math.max(10, tipX - 50), wrapperRect.width - 120)}px`;
        tooltip.style.top = `${Math.max(10, tipY - 55)}px`;
      });

      circle.addEventListener('mouseleave', () => {
        if (tooltip) tooltip.style.display = 'none';
      });
    });
  }

  // Render Horizontal Resource Types Bars
  function renderResourceTypes(resourceTypes) {
    const container = document.getElementById('resource-types-bars');
    const badge = document.getElementById('analytics-resource-count-badge');
    if (!container) return;

    if (badge) {
      badge.textContent = `${resourceTypes.length} ${resourceTypes.length === 1 ? 'Type' : 'Types'}`;
    }

    if (!resourceTypes || resourceTypes.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding: 30px 10px;">No resource leak types detected in this period.</div>';
      return;
    }

    const maxCount = Math.max(...resourceTypes.map(r => Number(r.count) || 0), 1);
    const colorClasses = ['bar-file', 'bar-db', 'bar-socket', 'bar-mem', 'bar-subproc', 'bar-lock'];

    container.innerHTML = resourceTypes.map((item, idx) => {
      const count = Number(item.count) || 0;
      const pct = Math.max(8, Math.round((count / maxCount) * 100));
      const colorClass = colorClasses[idx % colorClasses.length];
      const typeName = item.type || item.resource_type || item.resource || 'Unknown Resource';

      return `
        <div class="resource-bar-row">
          <div class="resource-bar-header">
            <span class="resource-bar-name">${escapeHtml(typeName)}</span>
            <span class="resource-bar-count">${count} ${count === 1 ? 'leak' : 'leaks'}</span>
          </div>
          <div class="resource-bar-track">
            <div class="resource-bar-fill ${colorClass}" style="width: ${pct}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Leak Prevention Intelligence
  function renderLeakIntelligence(analytics) {
    const emptyState = document.getElementById('analytics-empty-state');
    const content = document.getElementById('analytics-content');
    const resList = document.getElementById('analytics-resource-list');
    const projList = document.getElementById('analytics-project-list');
    const ciBox = document.getElementById('analytics-ci-box');

    const hasData = analytics && (
      analytics.has_data === true ||
      (analytics.trend && analytics.trend.length > 0) ||
      (analytics.resource_types && analytics.resource_types.length > 0) ||
      (analytics.total_confirmed_leaks > 0)
    );

    if (!hasData) {
      if (emptyState) {
        emptyState.textContent = 'Not enough scan history for intelligence analysis.';
        emptyState.style.display = 'block';
      }
      if (content) content.style.display = 'none';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';
    if (content) content.style.display = 'grid';

    // Top Leaked Resources
    if (resList) {
      const types = analytics.resource_types || analytics.leaks_by_resource || [];
      if (types.length === 0) {
        resList.innerHTML = '<div class="text-muted" style="font-size:0.85rem;">Zero confirmed resource leaks detected.</div>';
      } else {
        resList.innerHTML = types.slice(0, 5).map(r => `
          <div class="analytics-item">
            <span>${escapeHtml(r.type || r.resource_type || r.resource)}</span>
            <span class="analytics-item-count">${r.count}</span>
          </div>
        `).join('');
      }
    }

    // Vulnerable Codebases
    if (projList) {
      const projLeaks = analytics.leaks_by_project || [];
      if (projLeaks.length === 0) {
        projList.innerHTML = '<div class="text-muted" style="font-size:0.85rem;">All monitored codebases clean.</div>';
      } else {
        projList.innerHTML = projLeaks.slice(0, 5).map(p => `
          <div class="analytics-item">
            <span>${escapeHtml(p.project_name || p.name || 'Project')}</span>
            <span class="analytics-item-count">${p.leaks || p.open_leaks || 0}</span>
          </div>
        `).join('');
      }
    }

    // CI Gate Impact
    if (ciBox) {
      const ciStats = analytics.ci_stats || {};
      const failures = ciStats.failures || 0;
      const passes = ciStats.passes || 0;
      const total = ciStats.total || (failures + passes);
      const failRate = total > 0 ? Math.round((failures / total) * 100) : 0;

      ciBox.innerHTML = `
        <div style="font-size: 1.5rem; font-weight:700; color:${failures > 0 ? '#ef4444' : '#10b981'}; margin-bottom:4px;">
          ${failRate}% Blocked
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted);">
          ${failures} blocked of ${total} total automated CI gates
        </div>
      `;
    }
  }

  // ============================================================
  // Tab 5: Scan History Loader
  // ============================================================
  async function loadAdminScans() {
    const scansTbody = document.getElementById('admin-scans-tbody');
    const countBadge = document.getElementById('admin-scans-count');
    const statusFilter = document.getElementById('scans-status-filter');
    if (!scansTbody) return;

    try {
      const res = await fetch('/api/admin/scans');
      if (!res.ok) return;

      const data = await res.json();
      let scans = data.scans || [];
      cachedScans = scans;

      if (statusFilter && statusFilter.value !== 'all') {
        scans = scans.filter(s => s.status === statusFilter.value);
      }

      if (countBadge) {
        countBadge.textContent = `${scans.length} ${scans.length === 1 ? 'scan' : 'scans'}`;
      }

      if (scans.length === 0) {
        scansTbody.innerHTML = '<tr><td colspan="8" class="empty-state">No static analysis scans recorded yet.</td></tr>';
        return;
      }

      scansTbody.innerHTML = scans.map(s => {
        const isPass = s.status === 'PASS';
        const dateStr = s.timestamp ? formatLocalTime(new Date(s.timestamp)) : '-';
        const durationStr = s.duration_ms ? (s.duration_ms / 1000).toFixed(3) + 's' : '-';
        const commitInfo = s.commit_sha ? `<code>${escapeHtml(s.commit_sha.substring(0, 7))}</code>` : (s.branch ? `<code>${escapeHtml(s.branch)}</code>` : '-');

        return `
          <tr>
            <td><span class="badge ${isPass ? 'badge-clean' : 'badge-error'}">${escapeHtml(s.status || 'PASS')}</span></td>
            <td>${dateStr}</td>
            <td><strong>${escapeHtml(s.target || s.project_id || '-')}</strong></td>
            <td><span class="badge badge-neutral">${escapeHtml(s.scan_type || 'DEVELOPER')}</span></td>
            <td>${commitInfo}</td>
            <td>${s.files_scanned || 0}</td>
            <td><span class="${(s.leaks_detected || 0) > 0 ? 'text-red' : 'text-green'}">${s.leaks_detected || 0}</span></td>
            <td>${durationStr}</td>
          </tr>
        `;
      }).join('');

    } catch (e) {
      console.warn('Error loading scans:', e);
      scansTbody.innerHTML = '<tr><td colspan="8" class="empty-state">Unable to load scan audit log.</td></tr>';
    }
  }

  // Scan History Filters & Export
  const scansStatusFilterEl = document.getElementById('scans-status-filter');
  if (scansStatusFilterEl) {
    scansStatusFilterEl.addEventListener('change', () => {
      loadAdminScans();
    });
  }

  const btnExportScans = document.getElementById('btn-export-scans-csv');
  if (btnExportScans) {
    btnExportScans.addEventListener('click', () => {
      if (!cachedScans || cachedScans.length === 0) {
        alert('No scan history available to export.');
        return;
      }
      let csv = 'Scan ID,Status,Timestamp,Target,Scan Type,Branch,Commit,Files,Leaks,Duration (ms)\n';
      cachedScans.forEach(s => {
        csv += `"${s.scan_id || ''}","${s.status || ''}","${s.timestamp || ''}","${s.target || ''}","${s.scan_type || ''}","${s.branch || ''}","${s.commit_sha || ''}",${s.files_scanned || 0},${s.leaks_detected || 0},${s.duration_ms || 0}\n`;
      });
      downloadBlob(csv, 'leakguard_scan_history.csv', 'text/csv');
    });
  }

  // Utility to trigger CSV download
  function downloadBlob(content, filename, contentType) {
    if (typeof Blob === 'undefined' || typeof document === 'undefined') return;
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Analytics Filter Event Listeners
  const projFilterEl = document.getElementById('analytics-project-filter');
  const timeFilterEl = document.getElementById('analytics-time-filter');

  if (projFilterEl) {
    projFilterEl.addEventListener('change', () => {
      loadAdminAnalytics(projFilterEl.value, timeFilterEl ? timeFilterEl.value : '30');
    });
  }
  if (timeFilterEl) {
    timeFilterEl.addEventListener('change', () => {
      loadAdminAnalytics(projFilterEl ? projFilterEl.value : 'all', timeFilterEl.value);
    });
  }

  // Initialize
  resetDashboard();

  // Check URL hash for OAuth redirect callback or direct Admin tab navigation
  const hash = typeof window !== 'undefined' && window.location ? (window.location.hash || '') : '';
  let shouldOpenGhModal = false;
  if (hash.includes('github_connected=true')) {
    shouldOpenGhModal = true;
    if (typeof history !== 'undefined' && history.replaceState) {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  } else if (hash.includes('error=')) {
    const errorMsg = decodeURIComponent(hash.split('error=')[1] || 'Authentication error');
    alert(`GitHub Authentication: ${errorMsg}`);
    if (typeof history !== 'undefined' && history.replaceState) {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  } else if (hash.startsWith('#admin-')) {
    const tabName = hash.replace('#admin-', '');
    if (tabAdmin) tabAdmin.click();
    switchAdminTab(tabName);
  }

  // Handle hashchange for direct browser back/forward navigation
  if (typeof window !== 'undefined') {
    window.addEventListener('hashchange', () => {
      const curHash = window.location.hash || '';
      if (curHash.startsWith('#admin-')) {
        const tabName = curHash.replace('#admin-', '');
        if (tabAdmin && !tabAdmin.classList.contains('active')) {
          tabAdmin.click();
        }
        switchAdminTab(tabName);
      }
    });
  }

  // Load GitHub connection status
  checkGitHubStatus(shouldOpenGhModal);
});

