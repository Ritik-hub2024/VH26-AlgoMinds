// Basic UI handler for LeakGuard dashboard
document.addEventListener('DOMContentLoaded', () => {
  const btnLoadSample = document.getElementById('btn-load-sample');
  const btnClear = document.getElementById('btn-clear');
  const tbody = document.getElementById('results-tbody');
  const countBadge = document.getElementById('results-count');

  const valScanned = document.getElementById('val-scanned');
  const valClean = document.getElementById('val-clean');
  const valSyntax = document.getElementById('val-syntax-errors');
  const valLeaks = document.getElementById('val-leaks');

  const sampleReport = {
    summary: {
      files_scanned: 3,
      clean_files: 2,
      syntax_errors_count: 1,
      issues_count: 1,
    },
    items: [
      {
        status: 'CLEAN',
        file: 'examples/valid_sample.py',
        finding: 'Clean AST parse - No syntax anomalies',
        location: 'L1-L36',
      },
      {
        status: 'ERROR',
        file: 'examples/invalid_syntax_sample.py',
        finding: 'SyntaxError: invalid syntax (unclosed parenthesis)',
        location: 'L6:19',
      },
      {
        status: 'CLEAN',
        file: 'examples/resource_sample.py',
        finding: 'Clean AST parse - 2 potential raw resources',
        location: 'L5, L14',
      },
    ]
  };

  function renderReport(data) {
    valScanned.textContent = data.summary.files_scanned;
    valClean.textContent = data.summary.clean_files;
    valSyntax.textContent = data.summary.syntax_errors_count;
    valLeaks.textContent = data.summary.issues_count;
    countBadge.textContent = `${data.items.length} items`;

    tbody.innerHTML = '';
    data.items.forEach(item => {
      const tr = document.createElement('tr');
      const badgeClass = item.status === 'CLEAN' ? 'badge-clean' : (item.status === 'LEAK' ? 'badge-leak' : 'badge-error');

      tr.innerHTML = `
        <td><span class="badge ${badgeClass}">${item.status}</span></td>
        <td><code>${item.file}</code></td>
        <td>${item.finding}</td>
        <td class="code-loc">${item.location}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function clearView() {
    valScanned.textContent = '0';
    valClean.textContent = '0';
    valSyntax.textContent = '0';
    valLeaks.textContent = '0';
    countBadge.textContent = '0 items';
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">No analysis report loaded. Click "Load Sample Report" above.</td>
      </tr>
    `;
  }

  function normalizeReport(raw) {
    if (raw.items) return raw;
    const items = [];
    if (raw.files) {
      raw.files.forEach(f => {
        const basename = f.file_path.split(/[\\/]/).pop();
        const fileIssues = (raw.issues || []).filter(i => i.location && i.location.file_path === f.file_path);
        if (f.syntax_error) {
          items.push({
            status: 'ERROR',
            file: basename,
            finding: `SyntaxError: ${f.syntax_error.message}`,
            location: `L${f.syntax_error.line}:${f.syntax_error.column}`
          });
        } else if (!f.success) {
          items.push({
            status: 'ERROR',
            file: basename,
            finding: f.read_error || 'Read/Parse error',
            location: '-'
          });
        } else if (fileIssues.length > 0) {
          fileIssues.forEach(issue => {
            items.push({
              status: 'LEAK',
              file: basename,
              finding: `[${issue.rule_id}] ${issue.message}`,
              location: `L${issue.location.line}:${issue.location.column}`
            });
          });
        } else {
          items.push({
            status: 'CLEAN',
            file: basename,
            finding: 'Clean AST parse - No resource leaks or syntax errors',
            location: 'Safe'
          });
        }
      });
    }
    return {
      summary: raw.summary || { files_scanned: 0, clean_files: 0, syntax_errors_count: 0, issues_count: 0 },
      items
    };
  }

  // Try auto-loading report.json if present
  fetch('./report.json')
    .then(res => res.ok ? res.json() : null)
    .then(data => {
      if (data) renderReport(normalizeReport(data));
    })
    .catch(() => { });

  btnLoadSample.addEventListener('click', () => {
    fetch('./report.json')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) {
          renderReport(normalizeReport(data));
        } else {
          renderReport(sampleReport);
        }
      })
      .catch(() => renderReport(sampleReport));
  });

  btnClear.addEventListener('click', clearView);
});
