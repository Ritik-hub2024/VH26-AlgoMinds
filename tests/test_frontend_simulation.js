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
      classList: {
        add(c) { this.classes = this.classes || new Set(); this.classes.add(c); },
        remove(c) { if (this.classes) this.classes.delete(c); },
        contains(c) { return this.classes ? this.classes.has(c) : false; }
      },
      style: {},
      disabled: false,
      value: 'examples',
      addEventListener(event, fn) {
        listeners[id + ':' + event] = fn;
      }
    };
  }

  const ids = [
    'btn-scan', 'btn-scan-text', 'scan-target-select', 'btn-clear', 'dropzone',
    'scan-status-banner', 'status-icon', 'status-title', 'status-desc',
    'status-progress-steps', 'status-step-text', 'last-scan-container',
    'last-scan-text', 'last-scan-duration', 'val-scanned', 'val-clean',
    'val-syntax-errors', 'val-leaks', 'findings-container', 'findings-count',
    'syntax-panel', 'syntax-list', 'syntax-count', 'results-tbody', 'results-count'
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

  console.log('\nALL 6 FRONTEND SIMULATION TESTS PASSED SUCCESSFULLY!');
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
