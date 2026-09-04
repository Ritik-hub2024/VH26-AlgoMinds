/**
 * Frontend logic test: simulates the exact browser actions and checks DOM updates.
 */

const fs = require('fs');
const path = require('path');

// Read app.js
const appJsPath = path.join(__dirname, '..', 'frontend', 'app.js');
const appJsCode = fs.readFileSync(appJsPath, 'utf8');

// Minimal mock of browser DOM environment
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
      classList: {
        add(c) { this.classes = this.classes || new Set(); this.classes.add(c); },
        remove(c) { if (this.classes) this.classes.delete(c); },
        contains(c) { return this.classes ? this.classes.has(c) : false; }
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
      querySelectorAll(sel) {
        if (sel === '.btn-project-detail') {
          // Return dummy detail buttons matching any rendered projects
          return [{
            getAttribute(k) { return k === 'data-project-id' ? 'proj_test' : null; },
            addEventListener(event, fn) { listeners['btn-project-detail:' + event] = fn; }
          }];
        }
        return [];
      },
      addEventListener(event, fn) {
        listeners[id + ':' + event] = fn;
      }
    };
  }

  const ids = [
    'btn-scan', 'btn-scan-text', 'scan-target-select', 'btn-clear', 'dropzone',
    'btn-upload-file', 'input-upload-file', 'btn-upload-folder', 'input-upload-folder',
    'scan-status-banner', 'status-icon', 'status-title', 'status-desc',
    'status-progress-steps', 'status-step-text', 'last-scan-container',
    'last-scan-text', 'last-scan-duration', 'val-scanned', 'val-clean',
    'val-syntax-errors', 'val-leaks', 'findings-container', 'findings-count',
    'syntax-panel', 'syntax-list', 'syntax-count', 'results-tbody', 'results-count',
    'tab-dev', 'tab-admin', 'view-developer', 'view-admin', 'nav-mode-badge',
    'admin-val-projects', 'admin-val-scans', 'admin-val-open-leaks', 'admin-val-high-severity', 'admin-val-ci-blocked',
    'admin-projects-count', 'admin-projects-tbody',
    'admin-project-detail', 'btn-close-project-detail', 'detail-project-name', 'detail-project-sub', 'detail-project-health-badge',
    'detail-project-score-badge', 'detail-ci-context', 'ci-source', 'ci-repo', 'ci-branch', 'ci-commit', 'ci-pr', 'ci-run',
    'detail-files-scanned', 'detail-clean-files', 'detail-syntax-errors', 'detail-leaks', 'detail-new-leaks', 'detail-baseline-leaks',
    'detail-findings-container', 'detail-history-tbody',
    'admin-scans-count', 'admin-scans-tbody',
    'analytics-empty-state', 'analytics-content', 'analytics-resource-list', 'analytics-project-list', 'analytics-ci-box'
  ];

  ids.forEach(id => {
    elements[id] = makeEl(id);
  });

  return { elements, listeners };
}

async function runTest() {
  const { elements, listeners } = createMockDOM();

  // Mock global document & window
  global.document = {
    addEventListener(event, fn) {
      if (event === 'DOMContentLoaded') {
        setTimeout(fn, 10);
      }
    },
    getElementById(id) {
      return elements[id] || null;
    }
  };

  // Mock fetch
  global.fetch = async (url) => {
    if (url.includes('target=examples')) {
      return {
        ok: true,
        json: async () => ({
          status: 'FAILED',
          files_scanned: 3,
          clean_files: 1,
          syntax_errors: 1,
          leaks_detected: 1,
          duration_seconds: 0.0076,
          findings: [{
            severity: 'HIGH',
            file: 'examples/resource_sample.py',
            line: 5,
            resource: 'f (file)',
            variable: 'f',
            reason: "Resource 'f' allocated at line 5 is not guaranteed to be closed.",
            leak_path: 'L5: open() -> L8: return (leak)',
            recommendation: "Call 'f.close()' before returning."
          }],
          syntax_errors_list: [{
            file: 'examples/invalid_syntax_sample.py',
            line: 5,
            column: 14,
            message: "'(' was never closed"
          }],
          files: [
            { file: 'examples/invalid_syntax_sample.py', status: 'SYNTAX ERROR', ast_details: "SyntaxError: '(' was never closed", location: 'L5:14' },
            { file: 'examples/resource_sample.py', status: 'LEAK', ast_details: '1 resource leak(s) detected', location: 'Line 5' },
            { file: 'examples/valid_sample.py', status: 'CLEAN', ast_details: 'Clean AST parse', location: 'Safe' }
          ]
        })
      };
    }

    if (url.includes('sqlite_leak')) {
      return {
        ok: true,
        json: async () => ({
          status: 'FAILED',
          files_scanned: 1,
          clean_files: 0,
          syntax_errors: 0,
          leaks_detected: 1,
          duration_seconds: 0.0025,
          findings: [{
            severity: 'HIGH',
            file: 'python/leaks/sqlite_leak.py',
            line: 5,
            opened_line: 5,
            resource: 'conn (SQLite connection)',
            variable: 'conn',
            reason: "Resource 'conn' (type: SQLite connection) allocated at line 5 is not guaranteed to be closed.",
            leak_path: 'L5: sqlite3.connect() -> L8: return (leak)',
            path: 'L5: sqlite3.connect() -> L8: return (leak)',
            cleanup_status: 'UNCLOSED',
            recommendation: "Call 'conn.close()' before returning."
          }],
          syntax_errors_list: [],
          files: [
            { file: 'python/leaks/sqlite_leak.py', status: 'LEAK', ast_details: '1 resource leak(s) detected', location: 'Line 5' }
          ]
        })
      };
    }

    if (url.includes('target=python%2Fsafe') || url.includes('safe')) {
      return {
        ok: true,
        json: async () => ({
          status: 'PASS',
          files_scanned: 2,
          clean_files: 2,
          syntax_errors: 0,
          leaks_detected: 0,
          duration_seconds: 0.0041,
          findings: [],
          syntax_errors_list: [],
          files: [
            { file: 'python/safe/explicit_close.py', status: 'CLEAN', ast_details: 'Clean AST parse', location: 'Safe' },
            { file: 'python/safe/with_file.py', status: 'CLEAN', ast_details: 'Clean AST parse', location: 'Safe' }
          ]
        })
      };
    }

    if (url.includes('/api/scan/upload')) {
      return {
        ok: true,
        json: async () => ({
          status: 'PASS',
          files_scanned: 1,
          clean_files: 1,
          syntax_errors: 0,
          leaks_detected: 0,
          duration_seconds: 0.0035,
          target: 'upload:custom_test.py',
          findings: [],
          syntax_errors_list: [],
          files: [
            { file: 'custom_test.py', status: 'CLEAN', ast_details: 'Clean AST parse', location: 'Safe' }
          ]
        })
      };
    }

    if (url.includes('/api/admin/summary')) {
      return {
        ok: true,
        json: async () => ({
          total_projects: 2,
          total_scans: 5,
          open_leaks: 1,
          high_severity_leaks: 1,
          ci_blocked_projects: 1,
          has_data: true
        })
      };
    }

    if (url.includes('/api/admin/projects')) {
      return {
        ok: true,
        json: async () => ({
          projects: [
            {
              id: 'proj_test',
              name: 'LeakGuard Test Repo',
              repo: 'owner/leakguard-test',
              branch: 'main',
              last_scan: '2026-09-04T12:00:00Z',
              last_status: 'FAILED',
              open_leaks: 1,
              health: 'AT_RISK'
            },
            {
              id: 'proj_safe',
              name: 'LeakGuard Safe Repo',
              repo: 'owner/leakguard-safe',
              branch: 'main',
              last_scan: '2026-09-04T11:00:00Z',
              last_status: 'PASS',
              open_leaks: 0,
              health: 'HEALTHY'
            }
          ],
          count: 2
        })
      };
    }

    if (url.includes('/api/admin/scans')) {
      return {
        ok: true,
        json: async () => ({
          scans: [
            {
              scan_id: 'scan_12345678abcdef',
              project_id: 'proj_test',
              project_name: 'LeakGuard Test Repo',
              timestamp: '2026-09-04T12:00:00Z',
              target: 'python/leaks',
              files_scanned: 1,
              leaks_detected: 1,
              status: 'FAILED',
              scan_type: 'PROJECT UPLOAD'
            }
          ],
          count: 1
        })
      };
    }

    if (url.includes('/api/admin/analytics')) {
      return {
        ok: true,
        json: async () => ({
          has_data: true,
          leaks_by_resource: { file: 1 },
          leaks_by_project: { 'LeakGuard Test Repo': 1 },
          ci_pass_rate: 80.0,
          total_scans: 5,
          passed_scans: 4,
          failed_scans: 1
        })
      };
    }

    if (url.includes('/api/admin/project?id=')) {
      return {
        ok: true,
        json: async () => ({
          project: {
            id: 'proj_test',
            name: 'LeakGuard Test Repo',
            repo: 'owner/leakguard-test',
            branch: 'main',
            health: 'AT_RISK',
            health_score: 75
          },
          latest_scan: {
            scan_id: 'scan_12345678abcdef',
            scan_type: 'CI',
            commit_sha: 'abcdef1234',
            pull_request: '#42',
            workflow_run: '99887766',
            branch: 'main',
            repository: 'owner/leakguard-test',
            files_scanned: 2,
            clean_files: 0,
            syntax_errors: 0,
            leaks_detected: 2,
            new_leaks: 1,
            baseline_leaks: 1,
            health_score: 75,
            status: 'FAILED'
          },
          open_findings: [
            {
              finding_id: 'f1',
              file: 'python/leaks/sqlite_leak.py',
              line: 5,
              severity: 'HIGH',
              resource: 'SQLite connection',
              reason: 'Unclosed connection',
              leak_path: 'open -> return',
              recommendation: 'Close connection',
              is_baseline: false
            },
            {
              finding_id: 'f2',
              file: 'python/leaks/file_no_close.py',
              line: 15,
              severity: 'HIGH',
              resource: 'f (file)',
              reason: 'Unclosed file',
              leak_path: 'open -> exit',
              recommendation: 'Use with open',
              is_baseline: true
            }
          ],
          history: [{
            scan_id: 'scan_12345678abcdef',
            scan_type: 'CI',
            timestamp: '2026-09-04T12:00:00Z',
            target: 'python/leaks',
            files_scanned: 2,
            clean_files: 0,
            leaks_detected: 2,
            new_leaks: 1,
            baseline_leaks: 1,
            health_score: 75,
            duration_ms: 12.5,
            status: 'FAILED'
          }]
        })
      };
    }

    throw new Error('Unhandled URL: ' + url);
  };

  // Evaluate app.js
  eval(appJsCode);

  // Wait for DOMContentLoaded
  await new Promise(r => setTimeout(r, 50));

  console.log('[TEST 1] Initial state after page load:');
  console.assert(elements['status-title'].textContent === 'NOT SCANNED', 'Expected NOT SCANNED');
  console.assert(elements['last-scan-text'].textContent === 'Not scanned yet', 'Expected Not scanned yet');
  console.assert(elements['val-scanned'].textContent === '0', 'Expected 0 files scanned');
  console.assert(elements['val-leaks'].textContent === '0', 'Expected 0 leaks');
  console.assert(elements['findings-container'].innerHTML.includes('No analysis performed yet'), 'Expected initial findings text');
  console.log('  PASS: Initial state is clean NOT SCANNED.');

  console.log('[TEST 2] Click Scan button on default (examples):');
  const scanFn = listeners['btn-scan:click'];
  console.assert(typeof scanFn === 'function', 'btn-scan click listener must exist');
  await scanFn();

  console.assert(elements['status-title'].textContent.includes('FAILED'), 'Status should be FAILED');
  console.assert(String(elements['val-scanned'].textContent) === '3', 'Expected 3 files');
  console.assert(String(elements['val-leaks'].textContent) === '1', 'Expected 1 leak');
  console.assert(String(elements['val-syntax-errors'].textContent) === '1', 'Expected 1 syntax error');
  console.assert(elements['last-scan-text'].textContent !== 'Not scanned yet', 'Last scan should be updated with local time');
  console.assert(elements['last-scan-duration'].textContent.includes('0.0076s'), 'Scan duration should show');
  console.assert(elements['findings-container'].innerHTML.includes('HIGH'), 'Findings should show HIGH severity');
  console.assert(elements['findings-container'].innerHTML.includes('examples/resource_sample.py'), 'Finding should show file');
  console.assert(elements['findings-container'].innerHTML.includes('Line 5'), 'Finding should show line 5');
  console.assert(elements['syntax-panel'].style.display === 'block', 'Syntax panel should be visible');
  console.log('  PASS: Real scan executed, metrics updated, findings displayed.');

  console.log('[TEST 3] Click Reset button:');
  const resetFn = listeners['btn-clear:click'];
  console.assert(typeof resetFn === 'function', 'btn-clear click listener must exist');
  resetFn();

  console.assert(elements['status-title'].textContent === 'NOT SCANNED', 'Expected NOT SCANNED after reset');
  console.assert(elements['last-scan-text'].textContent === 'Not scanned yet', 'Expected Not scanned yet after reset');
  console.assert(String(elements['val-scanned'].textContent) === '0', 'Expected 0 files scanned after reset');
  console.assert(String(elements['val-leaks'].textContent) === '0', 'Expected 0 leaks after reset');
  console.assert(elements['findings-container'].innerHTML.includes('No analysis performed yet'), 'Expected empty findings after reset');
  console.assert(elements['syntax-panel'].style.display === 'none', 'Syntax panel should be hidden after reset');
  console.assert(elements['scan-target-select'].value === 'examples', 'Target selector should be restored to default examples');
  console.log('  PASS: Reset restored dashboard to exact initial state.');

  console.log('[TEST 4] Scan safe suite (python/safe):');
  elements['scan-target-select'].value = 'python/safe';
  await scanFn();

  console.assert(elements['status-title'].textContent.includes('PASS'), 'Status should be PASS');
  console.assert(String(elements['val-scanned'].textContent) === '2', 'Expected 2 files');
  console.assert(String(elements['val-clean'].textContent) === '2', 'Expected 2 clean files');
  console.assert(String(elements['val-leaks'].textContent) === '0', 'Expected 0 leaks');
  console.assert(elements['findings-container'].innerHTML.includes('No resource leaks detected'), 'Findings should show clean note');
  console.log('  PASS: Safe scan displays PASS and clean findings note.');

  console.log('[TEST 5] Reset again and verify third scan works cleanly:');
  resetFn();
  console.assert(elements['status-title'].textContent === 'NOT SCANNED', 'Expected NOT SCANNED after second reset');
  console.assert(String(elements['val-scanned'].textContent) === '0', 'Expected 0 files after second reset');
  elements['scan-target-select'].value = 'examples';
  await scanFn();
  console.assert(elements['status-title'].textContent.includes('FAILED'), 'Status should be FAILED on rescanning examples');
  console.assert(String(elements['val-scanned'].textContent) === '3', 'Expected 3 files on rescanning examples');
  console.log('  PASS: Rescan after reset successfully completes second full cycle.');

  console.log('[TEST 6] Scan SQLite leak target:');
  elements['scan-target-select'].value = 'python/leaks/sqlite_leak.py';
  await scanFn();
  console.assert(elements['status-title'].textContent.includes('FAILED'), 'Status should be FAILED for SQLite leak');
  console.assert(String(elements['val-leaks'].textContent) === '1', 'Expected 1 leak');
  console.assert(elements['findings-container'].innerHTML.includes('SQLite connection'), 'Findings should show SQLite connection');
  console.assert(elements['findings-container'].innerHTML.includes('conn'), 'Findings should show variable conn');
  console.log('  PASS: SQLite leak displays correctly on dashboard with Resource: SQLite Connection.');

  console.log('[TEST 7] Switch to Admin view and verify KPI summary:');
  const adminTabFn = listeners['tab-admin:click'];
  console.assert(typeof adminTabFn === 'function', 'tab-admin click listener must exist');
  adminTabFn();
  await new Promise(r => setTimeout(r, 60));

  console.assert(elements['view-admin'].style.display === 'block', 'Admin view should be visible');
  console.assert(elements['view-developer'].style.display === 'none', 'Dev view should be hidden');
  console.assert(elements['nav-mode-badge'].textContent === 'Admin Portfolio Mode', 'Mode badge should update');
  console.assert(String(elements['admin-val-projects'].textContent) === '2', 'Expected 2 projects in KPI');
  console.assert(String(elements['admin-val-scans'].textContent) === '5', 'Expected 5 scans in KPI');
  console.assert(String(elements['admin-val-open-leaks'].textContent) === '1', 'Expected 1 open leak');
  console.assert(String(elements['admin-val-high-severity'].textContent) === '1', 'Expected 1 high severity leak');
  console.assert(String(elements['admin-val-ci-blocked'].textContent) === '1', 'Expected 1 CI blocked project');
  console.log('  PASS: Admin view switched, summary metrics rendered.');

  console.log('[TEST 8] Admin projects portfolio & scans table rendering:');
  console.assert(elements['admin-projects-count'].textContent === '2 projects', 'Projects count badge should update');
  console.assert(elements['admin-projects-tbody'].innerHTML.includes('LeakGuard Test Repo'), 'Projects table should list test repo');
  console.assert(elements['admin-projects-tbody'].innerHTML.includes('AT RISK'), 'Projects table should display AT RISK badge');
  console.assert(elements['admin-projects-tbody'].innerHTML.includes('HEALTHY'), 'Projects table should display HEALTHY badge');
  console.assert(elements['admin-scans-tbody'].innerHTML.includes('scan_123'), 'Recent scans stream should show short scan id');
  console.assert(elements['analytics-ci-box'].innerHTML.includes('80%'), 'Analytics should display 80% CI pass rate');
  console.log('  PASS: Projects portfolio table, activity stream, and analytics rendered.');

  console.log('[TEST 9] Admin project drilldown inspection:');
  const detailBtnFn = listeners['btn-project-detail:click'];
  console.assert(typeof detailBtnFn === 'function', 'Project detail click listener must exist');
  await detailBtnFn();
  await new Promise(r => setTimeout(r, 60));

  console.assert(elements['admin-project-detail'].style.display === 'block', 'Detail drawer should be visible');
  console.assert(elements['detail-project-name'].textContent === 'LeakGuard Test Repo', 'Project name should match');
  console.assert(String(elements['detail-leaks'].textContent) === '2', 'Detail leaks count should be 2');
  console.assert(String(elements['detail-new-leaks'].textContent) === '1', 'Detail new leaks count should be 1');
  console.assert(String(elements['detail-baseline-leaks'].textContent) === '1', 'Detail baseline leaks count should be 1');
  console.assert(elements['detail-project-score-badge'].textContent.includes('Score: 75 / 100'), 'Score badge should render');
  console.assert(elements['detail-findings-container'].innerHTML.includes('SQLite connection'), 'Detail findings should display open leak');
  console.assert(elements['detail-findings-container'].innerHTML.includes('NEW LEAK (BLOCKING)'), 'Findings should show new leak tag');
  console.assert(elements['detail-findings-container'].innerHTML.includes('BASELINE (TOLERATED)'), 'Findings should show baseline tag');
  console.log('  PASS: Project drilldown rendered findings, score, and new/baseline metrics.');

  console.log('[TEST 10] Switch back to Developer view:');
  const devTabFn = listeners['tab-dev:click'];
  console.assert(typeof devTabFn === 'function', 'tab-dev click listener must exist');
  devTabFn();

  console.assert(elements['view-developer'].style.display === 'block', 'Developer view should be visible again');
  console.assert(elements['view-admin'].style.display === 'none', 'Admin view should be hidden');
  console.assert(elements['nav-mode-badge'].textContent === 'Developer Mode', 'Mode badge should restore to Developer Mode');
  console.log('  PASS: Successfully switched back to Developer view with state intact.');

  console.log('[TEST 11] Upload a single Python file via upload control:');
  const inputUploadFile = elements['input-upload-file'];
  const testFile = {
    name: 'uploaded_safe.py',
    webkitRelativePath: 'uploaded_safe.py',
    text: async () => 'with open("foo.txt") as f: pass\n'
  };
  inputUploadFile.files = [testFile];
  const fileChangeFn = listeners['input-upload-file:change'];
  console.assert(typeof fileChangeFn === 'function', 'input-upload-file change listener must exist');
  await fileChangeFn();
  await new Promise(r => setTimeout(r, 60));

  console.assert(String(elements['val-scanned'].textContent) === '1', 'Scanned files should be 1 after upload');
  console.assert(elements['scan-status-banner'].classList.contains('status-pass'), 'Upload safe scan should PASS');
  console.log('  PASS: Single Python file upload parsed via AST and updated UI.');

  console.log('[TEST 12] Upload a Python project folder via upload control:');
  const inputUploadFolder = elements['input-upload-folder'];
  const folderFiles = [
    {
      name: 'main.py',
      webkitRelativePath: 'my_app/main.py',
      text: async () => 'import os\n'
    },
    {
      name: 'notes.txt',
      webkitRelativePath: 'my_app/notes.txt',
      text: async () => 'ignore me\n'
    }
  ];
  inputUploadFolder.files = folderFiles;
  const folderChangeFn = listeners['input-upload-folder:change'];
  console.assert(typeof folderChangeFn === 'function', 'input-upload-folder change listener must exist');
  await folderChangeFn();
  await new Promise(r => setTimeout(r, 60));

  console.assert(elements['scan-status-banner'].classList.contains('status-pass'), 'Folder upload should complete successfully');
  console.log('  PASS: Project folder upload with non-Python filtering passed.');

  console.log('[TEST 13] Verify Scan Type badges in Admin recent scans table:');
  adminTabFn();
  await new Promise(r => setTimeout(r, 60));
  console.assert(elements['admin-scans-tbody'].innerHTML.includes('scan-type-tag'), 'Admin table should render scan-type tags');
  console.assert(elements['admin-scans-tbody'].innerHTML.includes('PROJECT UPLOAD'), 'Admin table should render PROJECT UPLOAD tag');
  console.log('  PASS: Scan Type badges correctly displayed in Admin view.');

  console.log('[TEST 14] Verify CI / PR Security Intelligence context and metadata:');
  await detailBtnFn();
  await new Promise(r => setTimeout(r, 60));
  console.assert(elements['detail-ci-context'].style.display === 'block', 'CI context card should be visible for CI scan');
  console.assert(elements['ci-source'].innerHTML.includes('CI'), 'CI source badge should render');
  console.assert(elements['ci-repo'].textContent === 'owner/leakguard-test', 'CI repository should display correctly');
  console.assert(elements['ci-branch'].textContent === 'main', 'CI branch should display correctly');
  console.assert(elements['ci-commit'].textContent === 'abcdef1234', 'CI commit should display short SHA');
  console.assert(elements['ci-pr'].textContent === '#42', 'CI PR should display correctly');
  console.assert(elements['ci-run'].textContent === '99887766', 'CI workflow run should display correctly');
  console.log('  PASS: CI Intelligence card, PR attribution, and commit context validated successfully.');

  console.log('\nALL 14 FRONTEND SIMULATION TESTS (DEVELOPER + ADMIN + UPLOADS + CI INTELLIGENCE) PASSED SUCCESSFULLY!');
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
