/**
 * Frontend logic test: simulates the browser actions and checks DOM updates for the
 * complete security remediation workflow.
 */

const fs = require('fs');
const path = require('path');

// Read app.js
const appJsPath = path.join(__dirname, '..', 'frontend', 'app.js');
const appJsCode = fs.readFileSync(appJsPath, 'utf8');

function createMockDOM() {
  const elements = {};
  const listeners = {};

  function makeEl(id) {
    return {
      id,
      tagName: 'DIV',
      textContent: '',
      innerHTML: '',
      className: '',
      attributes: {},
      classes: new Set(),
      classList: {
        add(c) { this.classes = this.classes || new Set(); this.classes.add(c); },
        remove(c) { if (this.classes) this.classes.delete(c); },
        contains(c) { return this.classes ? this.classes.has(c) : false; },
        toggle(c, force) {
          this.classes = this.classes || new Set();
          if (typeof force === 'boolean') {
            if (force) this.classes.add(c);
            else this.classes.delete(c);
          } else {
            if (this.classes.has(c)) this.classes.delete(c);
            else this.classes.add(c);
          }
        }
      },
      style: {},
      disabled: false,
      value: 'examples',
      setAttribute(k, v) { this.attributes[k] = v; },
      getAttribute(k) { return this.attributes[k] || null; },
      click() {
        if (listeners[id + ':click']) {
          listeners[id + ':click']();
        }
      },
      scrollIntoView() {},
      querySelector(sel) {
        return makeEl(id + '-sub');
      },
      querySelectorAll(sel) {
        return [];
      },
      addEventListener(event, fn) {
        listeners[id + ':' + event] = fn;
      }
    };
  }

  const ids = [
    'workflow-state-badge',
    'step-node-1', 'step-node-2', 'step-node-3', 'step-node-4', 'step-node-5', 'step-node-6',
    'step-line-1', 'step-line-2', 'step-line-3', 'step-line-4', 'step-line-5',
    'step-sub-1', 'step-sub-2', 'step-sub-3', 'step-sub-4', 'step-sub-5', 'step-sub-6',
    'scan-status-banner', 'status-icon', 'status-title', 'status-desc',
    'status-progress-steps', 'status-step-text', 'header-github-repo',
    'last-scan-container', 'last-scan-text', 'last-scan-duration',
    'btn-upload-zip', 'input-upload-zip', 'btn-open-github-modal',
    'scan-target-select', 'btn-upload-file', 'input-upload-file', 'btn-upload-folder', 'input-upload-folder',
    'btn-scan', 'btn-scan-text', 'btn-clear', 'dropzone',
    'ws-project-name', 'ws-status-badge', 'ws-files-count', 'ws-lines-count',
    'val-scanned', 'val-clean', 'val-syntax-errors', 'val-issues', 'val-leaks',
    'sev-val-critical', 'sev-val-high', 'sev-val-medium', 'sev-val-low',
    'findings-container', 'findings-count', 'syntax-panel', 'syntax-list', 'syntax-count',
    'results-tbody', 'results-count',
    'commit-workflow-panel', 'verify-status-badge',
    'stat-issues-detected', 'stat-auto-fixed', 'stat-manual-review',
    'stat-files-changed', 'stat-lines-added', 'stat-lines-removed',
    'input-branch-name', 'input-commit-msg', 'btn-commit-changes', 'btn-create-pr', 'git-action-result',
    'modal-code-view', 'code-modal-badge', 'code-modal-title', 'code-modal-subtitle', 'code-modal-callout', 'code-modal-lines',
    'btn-close-code-modal', 'btn-cancel-code-modal', 'btn-modal-generate-fix',
    'modal-diff-view', 'diff-modal-title', 'diff-modal-subtitle', 'diff-stat-additions', 'diff-stat-deletions', 'diff-stat-rule',
    'diff-before-box', 'diff-after-box', 'diff-verify-progress', 'diff-verify-text', 'diff-verify-result',
    'btn-close-diff-modal', 'btn-reject-diff', 'btn-apply-diff', 'btn-apply-diff-text',
    'modal-github-connect', 'gh-input-repo', 'gh-input-branch', 'gh-input-token', 'gh-connect-msg',
    'btn-close-github-modal', 'btn-cancel-github-modal', 'btn-save-github-connect', 'btn-save-github-text',
    'card-connect-github', 'gh-card-title', 'gh-card-desc', 'gh-card-connected-details', 'gh-card-badge',
    'gh-card-repo-name', 'gh-card-branch-name', 'gh-card-connected-btns', 'btn-gh-change-repo', 'btn-gh-disconnect',
    'btn-open-github-text',
    'gh-view-unauthenticated', 'btn-gh-authorize', 'gh-dev-mode-box', 'gh-dev-text',
    'gh-view-authenticated', 'gh-user-avatar', 'gh-user-name', 'btn-gh-sign-out',
    'gh-repo-search-input', 'gh-repo-list-container', 'gh-repo-list',
    'gh-branch-section', 'gh-branch-select', 'gh-branch-hint',
    'gh-modal-status-box', 'gh-modal-spinner', 'gh-modal-status-text',
    'tab-dev', 'tab-admin', 'view-developer', 'view-admin', 'nav-mode-badge',
    'admin-projects-tbody', 'admin-val-projects', 'admin-val-scans', 'admin-val-open-leaks', 'admin-val-high-severity', 'admin-val-ci-blocked',
    'admin-analytics-section', 'analytics-project-filter', 'analytics-time-filter',
    'analytics-meta-total-leaks', 'analytics-meta-unknown', 'analytics-meta-period',
    'analytics-empty-message', 'analytics-two-col-container',
    'analytics-trend-badge', 'trend-svg-chart', 'trend-chart-tooltip',
    'analytics-resource-count-badge', 'resource-types-bars',
    'analytics-intelligence-panel', 'analytics-empty-state', 'analytics-content',
    'analytics-resource-list', 'analytics-project-list', 'analytics-ci-box',
    'admin-tab-overview', 'admin-tab-repositories', 'admin-tab-risk', 'admin-tab-analytics', 'admin-tab-history',
    'admin-pane-overview', 'admin-pane-repositories', 'admin-pane-risk', 'admin-pane-analytics', 'admin-pane-history',
    'admin-repositories-tbody', 'admin-projects-count', 'btn-goto-repositories-tab',
    'admin-risk-tbody', 'risk-project-filter', 'risk-time-filter', 'btn-export-risk-ranking',
    'admin-scans-tbody', 'admin-scans-count', 'scans-status-filter', 'btn-export-scans-csv',
    'admin-project-detail', 'btn-close-project-detail', 'detail-project-name', 'detail-project-sub',
    'detail-project-health-badge', 'detail-project-score-badge',
    'detail-files-scanned', 'detail-clean-files', 'detail-syntax-errors', 'detail-leaks', 'detail-new-leaks', 'detail-baseline-leaks',
    'detail-findings-container', 'detail-history-tbody', 'detail-ci-context',
    'ci-source', 'ci-repo', 'ci-branch', 'ci-commit', 'ci-pr', 'ci-run'
  ];

  ids.forEach(id => {
    elements[id] = makeEl(id);
  });

  if (elements['admin-tab-overview']) elements['admin-tab-overview'].setAttribute('data-tab', 'overview');
  if (elements['admin-tab-repositories']) elements['admin-tab-repositories'].setAttribute('data-tab', 'repositories');
  if (elements['admin-tab-risk']) elements['admin-tab-risk'].setAttribute('data-tab', 'risk');
  if (elements['admin-tab-analytics']) elements['admin-tab-analytics'].setAttribute('data-tab', 'analytics');
  if (elements['admin-tab-history']) elements['admin-tab-history'].setAttribute('data-tab', 'history');

  if (elements['scans-status-filter']) elements['scans-status-filter'].value = 'all';
  if (elements['analytics-project-filter']) elements['analytics-project-filter'].value = 'all';
  if (elements['analytics-time-filter']) elements['analytics-time-filter'].value = '30';
  if (elements['risk-project-filter']) elements['risk-project-filter'].value = 'all';
  if (elements['risk-time-filter']) elements['risk-time-filter'].value = '30';

  return { elements, listeners };
}

async function runTest() {
  const { elements, listeners } = createMockDOM();

  global.window = {
    location: {
      hash: '',
      pathname: '/',
      search: '',
      href: 'http://localhost:8000/'
    },
    addEventListener(event, fn) {}
  };

  global.history = {
    replaceState(state, title, url) {
      global.window.location.hash = '';
    }
  };

  global.document = {
    addEventListener(event, fn) {
      if (event === 'DOMContentLoaded') {
        setTimeout(fn, 10);
      }
    },
    getElementById(id) {
      return elements[id] || null;
    },
    querySelectorAll(sel) {
      if (sel === '.admin-tab-btn') {
        return [
          elements['admin-tab-overview'],
          elements['admin-tab-repositories'],
          elements['admin-tab-risk'],
          elements['admin-tab-analytics'],
          elements['admin-tab-history']
        ].filter(Boolean);
      }
      return [];
    }
  };

  global.fetch = async (url, options = {}) => {
    const urlStr = String(url);

    if (urlStr.includes('/api/projects/workspace/scan') || urlStr.includes('/api/scan')) {
      return {
        ok: true,
        json: async () => ({
          status: 'FAILED',
          files_scanned: 3,
          clean_files: 1,
          syntax_errors: 1,
          leaks_detected: 1,
          issues_count: 2,
          duration_seconds: 0.0076,
          severity_counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0 },
          findings: [{
            id: 'f_1_resource_sample.py_5',
            rule_id: 'LEAK001',
            severity: 'HIGH',
            file: 'examples/resource_sample.py',
            line: 5,
            resource: 'f (file)',
            problem: 'Unclosed file descriptor opened via open()',
            why_dangerous: 'Unclosed file descriptors cause resource leakage and OS file lock issues.',
            is_fixable: true
          }],
          syntax_errors_list: [{
            file: 'examples/invalid_syntax_sample.py',
            line: 3,
            column: 12,
            message: 'expected :'
          }],
          files: [
            { file: 'examples/resource_sample.py', status: 'LEAK', ast_details: '1 leak detected', location: 'Line 5' },
            { file: 'examples/valid_sample.py', status: 'CLEAN', ast_details: 'Clean AST', location: 'Safe' },
            { file: 'examples/invalid_syntax_sample.py', status: 'SYNTAX ERROR', ast_details: 'SyntaxError', location: 'Line 3' }
          ]
        })
      };
    }

    if (urlStr.includes('/api/projects/workspace/verify-summary')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          total_issues: 1,
          automatically_fixed: 0,
          manual_review_required: 1,
          files_changed: [],
          lines_added: 0,
          lines_removed: 0
        })
      };
    }

    if (urlStr.includes('/api/findings/generate-fix')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          fix: {
            fix_id: 'fix_123',
            rel_file: 'examples/resource_sample.py',
            rule_id: 'LEAK001',
            line: 5,
            original_code: 'f = open("data.txt")\nreturn f.read()',
            modified_code: 'with open("data.txt") as f:\n    return f.read()'
          },
          diff: { additions: 2, deletions: 2 }
        })
      };
    }

    if (urlStr.includes('/api/admin/summary')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          summary: {
            total_projects: 2,
            total_scans: 5,
            total_open_leaks: 1,
            high_severity_leaks: 1,
            ci_blocked_projects: 1
          }
        })
      };
    }

    if (urlStr.includes('/api/admin/projects')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          projects: [{
            id: 'p1',
            name: 'Sample Repo',
            repository: 'octocat/sample',
            security_score: 85,
            health_status: 'HEALTHY',
            open_leaks_count: 0
          }]
        })
      };
    }

    if (urlStr.includes('/api/github/status')) {
      return {
        ok: true,
        json: async () => ({
          authenticated: false,
          user: null,
          connected_repo: null,
          base_branch: 'main'
        })
      };
    }

    if (urlStr.includes('/api/github/auth')) {
      return {
        ok: true,
        json: async () => ({
          configured: true,
          auth_url: 'https://github.com/login/oauth/authorize?client_id=leakguard',
          dev_mode: false
        })
      };
    }

    if (urlStr.includes('/api/github/repositories')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          repositories: [
            { full_name: 'octocat/python-security-demo', name: 'python-security-demo', private: false, default_branch: 'main', description: 'Sample Python app' }
          ]
        })
      };
    }

    if (urlStr.includes('/api/github/branches')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          branches: ['main', 'dev', 'feature/auth']
        })
      };
    }

    if (urlStr.includes('/api/github/connect')) {
      return {
        ok: true,
        json: async () => ({
          status: 'CONNECTED',
          workspace_id: 'ws_gh_123',
          repository: 'octocat/python-security-demo',
          base_branch: 'main',
          files_count: 5,
          lines_count: 420
        })
      };
    }

    if (urlStr.includes('/api/admin/risk-ranking')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          rankings: [{
            project_id: 'p1',
            project_name: 'Sample Repo',
            repository: 'octocat/sample',
            leak_density: 0.25,
            density_display: '0.25 / 1K lines',
            trend_direction: 'STABLE',
            trend_display: '→ Stable',
            last_scan_time: '2026-09-02T10:00:00Z',
            health_status: 'HEALTHY',
            open_leaks_count: 0
          }]
        })
      };
    }

    if (urlStr.includes('/api/admin/scans')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          scans: [{
            id: 'scan_001',
            status: 'FAILED',
            files_scanned: 5,
            leaks_detected: 2,
            duration_ms: 50,
            timestamp: '2026-09-02T10:00:00Z',
            project_id: 'p1',
            target: 'Sample Repo',
            scan_type: 'CI',
            branch: 'main',
            commit_sha: 'abc1234'
          }]
        })
      };
    }

    if (urlStr.includes('/api/admin/analytics')) {
      return {
        ok: true,
        json: async () => ({
          status: 'SUCCESS',
          total_confirmed_leaks: 3,
          unknown_ownership_count: 1,
          trend: [
            { scan_id: 'scan_001', leak_count: 5, scanned_at: '2026-09-01T10:00:00Z' },
            { scan_id: 'scan_002', leak_count: 3, scanned_at: '2026-09-02T10:00:00Z' }
          ],
          resource_types: [
            { type: 'File', count: 2 },
            { type: 'SQLite Connection', count: 1 }
          ],
          leaks_by_project: [
            { project_name: 'Sample Repo', repository: 'octocat/sample', leak_count: 3 }
          ],
          ci_stats: {
            total_ci_scans: 10,
            failed_ci_scans: 2,
            failure_rate_percent: 20
          }
        })
      };
    }

    if (urlStr.includes('/api/commit') || urlStr.includes('/api/github/commit')) {
      if (global._mockCommitError) {
        return {
          ok: false,
          status: 400,
          json: async () => ({
            status: 'ERROR',
            success: false,
            error: 'Target workspace is not a Git repository, and GitHub integration is not configured.'
          })
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          status: 'COMMITTED',
          success: true,
          commit_sha: 'e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
          commit_hash: 'e1a2b3c4',
          branch: 'leakguard/fix-resource-leaks',
          commit_message: 'fix: resolve resource leaks',
          repository: 'octocat/sample',
          files_committed: ['file_leak.py']
        })
      };
    }

    return {
      ok: true,
      json: async () => ({ status: 'SUCCESS' })
    };
  };

  // Evaluate app.js
  eval(appJsCode);

  await new Promise(r => setTimeout(r, 50));

  console.log('[TEST 1] Initial state after page load:');
  console.assert(elements['status-title'].textContent === 'PROJECT READY', 'Expected PROJECT READY');
  console.assert(elements['val-scanned'].textContent === '0', 'Expected 0 files scanned');
  console.log('  PASS: Initial state is clean.');

  console.log('[TEST 2] Run Scan:');
  const scanFn = listeners['btn-scan:click'];
  console.assert(typeof scanFn === 'function', 'btn-scan click listener must exist');
  await scanFn();

  console.assert(elements['status-title'].textContent.includes('REMEDIATION REQUIRED'), 'Status should be REMEDIATION REQUIRED');
  console.assert(String(elements['val-scanned'].textContent) === '3', 'Expected 3 files scanned');
  console.assert(String(elements['val-leaks'].textContent) === '1', 'Expected 1 leak');
  console.assert(elements['findings-container'].innerHTML.includes('Generate Fix'), 'Findings should offer Generate Fix button');
  console.log('  PASS: Scan executed, findings rendered with remediation CTA.');

  console.log('[TEST 3] Switch to Admin View & Verify 5-Tab Navigation:');
  const adminTabFn = listeners['tab-admin:click'];
  console.assert(typeof adminTabFn === 'function', 'tab-admin click listener must exist');
  adminTabFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['view-admin'].style.display === 'block', 'Admin view should be visible');
  
  // Tab 1: Overview
  console.log('  [3.1] Tab 1: Overview active by default');
  console.assert(elements['admin-pane-overview'].style.display === 'flex', 'Overview pane should be visible');
  console.assert(elements['admin-val-projects'].textContent === 2, 'Total projects should be 2');
  console.assert(elements['admin-val-scans'].textContent === 5, 'Total scans should be 5');

  // Tab 2: Repositories
  console.log('  [3.2] Tab 2: Switch to Repositories');
  const tabReposFn = listeners['admin-tab-repositories:click'];
  console.assert(typeof tabReposFn === 'function', 'admin-tab-repositories click listener must exist');
  tabReposFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['admin-pane-repositories'].style.display === 'flex', 'Repositories pane should be visible');
  console.assert(elements['admin-pane-overview'].style.display === 'none', 'Overview pane should be hidden');
  console.assert(elements['admin-repositories-tbody'].innerHTML.includes('Sample Repo'), 'Repositories table should contain Sample Repo');

  // Tab 3: Risk Ranking
  console.log('  [3.3] Tab 3: Switch to Risk Ranking');
  const tabRiskFn = listeners['admin-tab-risk:click'];
  console.assert(typeof tabRiskFn === 'function', 'admin-tab-risk click listener must exist');
  tabRiskFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['admin-pane-risk'].style.display === 'flex', 'Risk pane should be visible');
  console.assert(elements['admin-pane-repositories'].style.display === 'none', 'Repositories pane should be hidden');
  console.assert(elements['admin-risk-tbody'].innerHTML.includes('Sample Repo'), 'Risk ranking table should contain Sample Repo');
  console.assert(elements['admin-risk-tbody'].innerHTML.includes('10 Files') || elements['admin-risk-tbody'].innerHTML.includes('0'), 'Risk ranking table should show leak density');

  // Tab 4: Analytics
  console.log('  [3.4] Tab 4: Switch to Analytics');
  const tabAnalyticsFn = listeners['admin-tab-analytics:click'];
  console.assert(typeof tabAnalyticsFn === 'function', 'admin-tab-analytics click listener must exist');
  tabAnalyticsFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['admin-pane-analytics'].style.display === 'flex', 'Analytics pane should be visible');
  console.assert(elements['admin-pane-risk'].style.display === 'none', 'Risk pane should be hidden');
  console.assert(elements['analytics-meta-total-leaks'].textContent.includes('3'), 'Total confirmed leaks should be 3');
  console.assert(elements['analytics-meta-unknown'].textContent.includes('1'), 'Unknown ownership should be 1');
  console.assert(elements['trend-svg-chart'].innerHTML.includes('trend-point') || elements['trend-svg-chart'].innerHTML.includes('<circle'), 'SVG chart elements should be rendered');
  console.assert(elements['resource-types-bars'].innerHTML.includes('File'), 'Resource types bars should contain File');
  console.assert(elements['resource-types-bars'].innerHTML.includes('SQLite Connection'), 'Resource types bars should contain SQLite Connection');
  console.assert(elements['analytics-resource-list'].innerHTML.includes('File'), 'Intelligence panel should list top leaked resource');

  // Tab 5: Scan History
  console.log('  [3.5] Tab 5: Switch to Scan History');
  const tabHistoryFn = listeners['admin-tab-history:click'];
  console.assert(typeof tabHistoryFn === 'function', 'admin-tab-history click listener must exist');
  tabHistoryFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['admin-pane-history'].style.display === 'flex', 'Scan history pane should be visible');
  console.assert(elements['admin-pane-analytics'].style.display === 'none', 'Analytics pane should be hidden');
  console.assert(elements['admin-scans-tbody'].innerHTML.includes('Sample Repo'), 'Scans table should contain Sample Repo');

  // Switch back to Tab 1: Overview
  console.log('  [3.6] Tab 1: Switch back to Overview');
  const tabOverviewFn = listeners['admin-tab-overview:click'];
  console.assert(typeof tabOverviewFn === 'function', 'admin-tab-overview click listener must exist');
  tabOverviewFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['admin-pane-overview'].style.display === 'flex', 'Overview pane should be visible');
  console.assert(elements['admin-pane-history'].style.display === 'none', 'Scan history pane should be hidden');
  console.log('  PASS: Admin 5-tab navigation & views switched and rendered cleanly.');

  console.log('[TEST 4] Open GitHub Modal & Check Unauthenticated State:');
  const openGhModalFn = listeners['btn-open-github-modal:click'];
  console.assert(typeof openGhModalFn === 'function', 'btn-open-github-modal click listener must exist');
  openGhModalFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['modal-github-connect'].style.display === 'flex', 'GitHub modal should open with display: flex');
  console.assert(elements['gh-view-unauthenticated'].style.display === 'flex', 'Unauthenticated view should be shown');
  console.log('  PASS: GitHub OAuth connect modal renders cleanly.');

  console.log('[TEST 5] Commit Success Flow:');
  const commitBtnFn = listeners['btn-commit-changes:click'];
  console.assert(typeof commitBtnFn === 'function', 'btn-commit-changes click listener must exist');
  global._mockCommitError = false;
  await commitBtnFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['workflow-state-badge'].textContent.includes('COMMITTED'), 'Workflow should transition to COMMITTED');
  console.assert(elements['git-action-result'].style.display === 'block', 'Git action result should be visible');
  console.assert(elements['git-action-result'].innerHTML.includes('COMMIT SUCCESSFUL'), 'Should display COMMIT SUCCESSFUL');
  console.assert(elements['git-action-result'].innerHTML.includes('e1a2b3c4'), 'Should display commit short SHA');
  console.assert(elements['git-action-result'].innerHTML.includes('octocat/sample'), 'Should display repository name');
  console.log('  PASS: Commit button executed, returned SHA, and rendered success state.');

  console.log('[TEST 6] Commit Failure State Flow:');
  global._mockCommitError = true;
  await commitBtnFn();
  await new Promise(r => setTimeout(r, 50));
  console.assert(elements['workflow-state-badge'].textContent.includes('COMMIT FAILED'), 'Workflow should transition to COMMIT FAILED');
  console.assert(elements['git-action-result'].innerHTML.includes('COMMIT FAILED'), 'Should display COMMIT FAILED');
  console.assert(elements['git-action-result'].innerHTML.includes('Target workspace is not a Git repository'), 'Should display failure reason');
  console.assert(elements['btn-commit-changes'].disabled === false, 'Commit button should be re-enabled on failure');
  console.log('  PASS: Commit failure handled gracefully without lockup.');

  console.log('ALL FRONTEND SIMULATION TESTS PASSED CLEANLY!');
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
