/**
 * AegisGuard - Smart Contract Security Intelligence Frontend Logic
 * Vanilla JavaScript implementation for high performance & micro-interactions.
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const codeEditor = document.getElementById('codeEditor');
  const lineGutter = document.getElementById('lineGutter');
  const editorStats = document.getElementById('editorStats');
  const sampleSelect = document.getElementById('sampleSelect');
  const quickSamplePills = document.getElementById('quickSamplePills');
  const fileUploadInput = document.getElementById('fileUploadInput');
  const clearBtn = document.getElementById('clearBtn');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const analyzeBtnText = document.getElementById('analyzeBtnText');
  const editorContainer = document.getElementById('editorContainer');

  // States
  const idleState = document.getElementById('idleState');
  const scanningState = document.getElementById('scanningState');
  const resultsState = document.getElementById('resultsState');
  const scanProgressBar = document.getElementById('scanProgressBar');

  // Results components
  const verdictBanner = document.getElementById('verdictBanner');
  const verdictIconBox = document.getElementById('verdictIconBox');
  const verdictBadge = document.getElementById('verdictBadge');
  const latencyBadge = document.getElementById('latencyBadge');
  const verdictHeading = document.getElementById('verdictHeading');
  const verdictSummary = document.getElementById('verdictSummary');
  const circleProgress = document.getElementById('circleProgress');
  const riskScoreNumber = document.getElementById('riskScoreNumber');

  const kpiSvmPred = document.getElementById('kpiSvmPred');
  const kpiSvmConf = document.getElementById('kpiSvmConf');
  const kpiDecisionScore = document.getElementById('kpiDecisionScore');
  const kpiFindingCount = document.getElementById('kpiFindingCount');
  const kpiLoc = document.getElementById('kpiLoc');
  const kpiSloc = document.getElementById('kpiSloc');

  const findingsList = document.getElementById('findingsList');
  const categoriesList = document.getElementById('categoriesList');
  const remediationList = document.getElementById('remediationList');
  const findingsCountBadge = document.getElementById('findingsCountBadge');

  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  const copyMarkdownReportBtn = document.getElementById('copyMarkdownReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toastMsg');

  // Application State
  let lastAuditData = null;
  let sampleCache = {};

  // --- 1. Line Numbers & Editor Synchronization ---
  function updateLineNumbers() {
    const text = codeEditor.value;
    const lines = text.split('\n');
    const lineCount = lines.length || 1;
    
    // Generate line numbers string
    let numbersText = '';
    for (let i = 1; i <= lineCount; i++) {
      numbersText += i + '\n';
    }
    lineGutter.textContent = numbersText;

    // Update stats
    const charCount = text.length;
    editorStats.textContent = `${lineCount} line${lineCount === 1 ? '' : 's'} | ${charCount.toLocaleString()} chars`;
  }

  // Synchronize gutter scrolling with editor scrolling
  codeEditor.addEventListener('scroll', () => {
    lineGutter.scrollTop = codeEditor.scrollTop;
  });

  codeEditor.addEventListener('input', () => {
    updateLineNumbers();
  });

  // Tab key indent support
  codeEditor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = codeEditor.selectionStart;
      const end = codeEditor.selectionEnd;
      codeEditor.value = codeEditor.value.substring(0, start) + '    ' + codeEditor.value.substring(end);
      codeEditor.selectionStart = codeEditor.selectionEnd = start + 4;
      updateLineNumbers();
    }
    // Shortcut Ctrl+Enter or Cmd+Enter to run audit
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runSecurityAudit();
    }
  });

  // Drag and drop .sol files directly onto the editor
  editorContainer.addEventListener('dragover', (e) => {
    e.preventDefault();
    editorContainer.style.outline = '2px dashed var(--cyan-primary)';
  });

  editorContainer.addEventListener('dragleave', () => {
    editorContainer.style.outline = 'none';
  });

  editorContainer.addEventListener('drop', (e) => {
    e.preventDefault();
    editorContainer.style.outline = 'none';
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      readFileToEditor(file);
    }
  });

  // File Upload Input
  fileUploadInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      readFileToEditor(e.target.files[0]);
    }
  });

  function readFileToEditor(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      codeEditor.value = event.target.result;
      updateLineNumbers();
      showToast(`Loaded "${file.name}" into editor`, 'success');
    };
    reader.onerror = () => {
      showToast(`Failed to read file ${file.name}`, 'error');
    };
    reader.readAsText(file);
  }

  // Clear Editor
  clearBtn.addEventListener('click', () => {
    codeEditor.value = '';
    updateLineNumbers();
    sampleSelect.value = '';
    showToast('Editor cleared', 'info');
  });

  // --- 2. Load Sample Contracts from API ---
  async function loadSamplesList() {
    try {
      const response = await fetch('/api/samples');
      if (!response.ok) return;
      const samples = await response.json();

      samples.forEach(sample => {
        const option = document.createElement('option');
        option.value = sample.id;
        option.textContent = `${sample.title} (${sample.badge})`;
        sampleSelect.appendChild(option);
      });
    } catch (err) {
      console.warn('Could not fetch sample list:', err);
    }
  }

  async function fetchAndSetSample(filename) {
    if (sampleCache[filename]) {
      codeEditor.value = sampleCache[filename];
      updateLineNumbers();
      sampleSelect.value = filename;
      showToast(`Loaded sample: ${filename}`, 'info');
      return;
    }

    try {
      const res = await fetch(`/api/samples/${encodeURIComponent(filename)}`);
      if (!res.ok) throw new Error('Sample not found');
      const data = await res.json();
      sampleCache[filename] = data.code;
      codeEditor.value = data.code;
      updateLineNumbers();
      sampleSelect.value = filename;
      showToast(`Loaded sample: ${filename}`, 'info');
    } catch (err) {
      showToast(`Failed to load sample: ${err.message}`, 'error');
    }
  }

  sampleSelect.addEventListener('change', (e) => {
    if (e.target.value) {
      fetchAndSetSample(e.target.value);
    }
  });

  // Quick preset pills click handler
  if (quickSamplePills) {
    quickSamplePills.addEventListener('click', (e) => {
      const btn = e.target.closest('.sample-btn');
      if (!btn) return;
      const filename = btn.getAttribute('data-file');
      if (filename) {
        fetchAndSetSample(filename);
      }
    });
  }

  // --- 3. Tab Switching ---
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(btn.getAttribute('data-tab'));
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });

  // --- 4. Run Security Audit ---
  analyzeBtn.addEventListener('click', runSecurityAudit);

  async function runSecurityAudit() {
    const code = codeEditor.value.trim();
    if (!code) {
      showToast('Please enter or upload Solidity source code first.', 'warning');
      codeEditor.focus();
      return;
    }

    // Switch UI to scanning state
    analyzeBtn.disabled = true;
    analyzeBtnText.textContent = 'Auditing Contract...';
    idleState.classList.add('hidden');
    resultsState.classList.add('hidden');
    scanningState.classList.remove('hidden');

    // Reset and animate HUD progress
    animateScanSteps();

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned ${response.status}`);
      }

      const data = await response.json();
      lastAuditData = data;

      // Finish progress bar
      scanProgressBar.style.width = '100%';

      // Brief delay so user perceives the scan
      setTimeout(() => {
        renderAuditResults(data);
        scanningState.classList.add('hidden');
        resultsState.classList.remove('hidden');
        analyzeBtn.disabled = false;
        analyzeBtnText.textContent = 'Analyze Contract Security';
        showToast('Audit complete!', 'success');
      }, 400);

    } catch (err) {
      scanningState.classList.add('hidden');
      idleState.classList.remove('hidden');
      analyzeBtn.disabled = false;
      analyzeBtnText.textContent = 'Analyze Contract Security';
      showToast(`Audit failed: ${err.message}`, 'error');
    }
  }

  function animateScanSteps() {
    const steps = ['step1', 'step2', 'step3', 'step4', 'step5'];
    scanProgressBar.style.width = '15%';

    steps.forEach((stepId, idx) => {
      const el = document.getElementById(stepId);
      el.classList.remove('active', 'completed');
      setTimeout(() => {
        el.classList.add('active');
        scanProgressBar.style.width = `${Math.min(25 + idx * 18, 90)}%`;
        if (idx > 0) {
          const prev = document.getElementById(steps[idx - 1]);
          prev.classList.remove('active');
          prev.classList.add('completed');
        }
      }, idx * 120);
    });
  }

  // --- 5. Render Audit Results ---
  function renderAuditResults(data) {
    const isVulnerable = data.is_vulnerable;
    const mistakes = data.verified_mistakes || [];
    const riskScore = data.risk_score || 0;

    // Update Tab badge
    findingsCountBadge.textContent = mistakes.length;

    // Verdict Banner styling
    if (isVulnerable) {
      verdictBanner.className = 'verdict-banner';
      verdictBadge.textContent = 'CRITICAL RISK';
      verdictHeading.textContent = 'Potentially Vulnerable';
      verdictHeading.style.color = 'var(--rose-danger)';
      verdictSummary.textContent = data.mistake_summary || 'One or more security vulnerabilities were detected.';
      verdictIconBox.innerHTML = `
        <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      `;
    } else {
      verdictBanner.className = 'verdict-banner verdict-clean';
      verdictBadge.textContent = 'VERIFIED CLEAN';
      verdictHeading.textContent = 'No Vulnerability Detected';
      verdictHeading.style.color = 'var(--emerald)';
      verdictSummary.textContent = data.mistake_summary || 'Both machine learning and rule-based checks verified this contract.';
      verdictIconBox.innerHTML = `
        <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
      `;
    }

    latencyBadge.textContent = `${data.execution_time_ms}ms latency`;

    // Circular Risk Gauge
    circleProgress.setAttribute('stroke-dasharray', `${riskScore}, 100`);
    riskScoreNumber.textContent = riskScore;

    // KPI Mini Cards
    if (data.ml_is_vulnerable) {
      kpiSvmPred.textContent = 'Vulnerable (1)';
      kpiSvmPred.className = 'kpi-value text-danger';
    } else {
      kpiSvmPred.textContent = 'Clean (0)';
      kpiSvmPred.className = 'kpi-value text-success';
    }
    kpiSvmConf.textContent = `Confidence: ${data.svm_confidence_pct}%`;
    kpiDecisionScore.textContent = `${data.svm_decision_score > 0 ? '+' : ''}${data.svm_decision_score}`;
    kpiFindingCount.textContent = `${mistakes.length} Line${mistakes.length === 1 ? '' : 's'}`;
    kpiLoc.textContent = `${data.loc} Lines`;
    kpiSloc.textContent = `${data.sloc} SLOC`;

    // Render Tab 1: Findings List
    findingsList.innerHTML = '';
    if (mistakes.length === 0) {
      const emptyCard = document.createElement('div');
      emptyCard.className = 'rem-card';
      emptyCard.style.borderLeftColor = 'var(--emerald)';
      emptyCard.innerHTML = `
        <div class="rem-title" style="color: var(--emerald);">✓ Zero Static AST Weaknesses Found</div>
        <p class="rem-body">The rule-based analysis scanner detected no common vulnerabilities such as unverified state updates before external calls or unguarded withdraw calls.</p>
      `;
      findingsList.appendChild(emptyCard);
    } else {
      mistakes.forEach(item => {
        const card = document.createElement('div');
        card.className = 'finding-card';
        card.innerHTML = `
          <div class="finding-header">
            <div class="finding-tags">
              <span class="line-badge">Line ${item.line_number}</span>
              <span class="category-tag">${item.category_name}</span>
            </div>
            <span class="pattern-tag">${item.pattern_name}</span>
          </div>
          <div class="finding-code-snippet">${escapeHtml(item.line_content)}</div>
          <div class="finding-explanation">${escapeHtml(item.coding_mistake)}</div>
          <div class="finding-fix"><strong>Suggested Fix:</strong> ${escapeHtml(item.suggested_fix)}</div>
        `;
        // Clicking finding card jumps to line in editor!
        card.addEventListener('click', () => {
          highlightLineInEditor(item.line_number);
        });
        findingsList.appendChild(card);
      });
    }

    // Render Tab 2: Category Probabilities
    categoriesList.innerHTML = '';
    const probs = data.category_probabilities || {};
    const sortedCats = Object.entries(probs).sort((a, b) => b[1] - a[1]);

    sortedCats.forEach(([catName, probPct]) => {
      const item = document.createElement('div');
      item.className = 'cat-bar-item';
      
      let fillClass = '';
      if (probPct >= 50) fillClass = 'bar-high';
      else if (probPct >= 20) fillClass = 'bar-med';

      item.innerHTML = `
        <div class="cat-bar-header">
          <span class="cat-name">${catName}</span>
          <span class="cat-prob-text">${probPct}%</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill ${fillClass}" style="width: ${Math.max(probPct, 2)}%;"></div>
        </div>
      `;
      categoriesList.appendChild(item);
    });

    // Render Tab 3: Remediation List
    remediationList.innerHTML = '';
    const solutions = data.suggested_solutions || [];
    solutions.forEach(solText => {
      const card = document.createElement('div');
      card.className = 'rem-card';
      // Format markdown-like bold text
      const cleanHtml = solText.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
      card.innerHTML = `
        <div class="rem-body">${cleanHtml}</div>
      `;
      remediationList.appendChild(card);
    });
  }

  // Jump to line in textarea
  function highlightLineInEditor(targetLine) {
    const text = codeEditor.value;
    const lines = text.split('\n');
    if (targetLine < 1 || targetLine > lines.length) return;

    let charOffset = 0;
    for (let i = 0; i < targetLine - 1; i++) {
      charOffset += lines[i].length + 1; // +1 for newline
    }
    const lineLength = lines[targetLine - 1].length;

    codeEditor.focus();
    codeEditor.setSelectionRange(charOffset, charOffset + lineLength);

    // Approximate vertical scroll to that line
    const approxLineHeight = 25.6; // 1.6rem * 16px
    codeEditor.scrollTop = Math.max(0, (targetLine - 4) * approxLineHeight);
    lineGutter.scrollTop = codeEditor.scrollTop;

    showToast(`Focused on line ${targetLine}`, 'info');
  }

  // --- 6. Report Export Actions ---
  copyMarkdownReportBtn.addEventListener('click', () => {
    if (!lastAuditData) {
      showToast('No audit data to export. Run an audit first.', 'warning');
      return;
    }
    const md = generateMarkdownReport(lastAuditData);
    navigator.clipboard.writeText(md).then(() => {
      showToast('Markdown security audit report copied to clipboard!', 'success');
    }).catch(() => {
      showToast('Could not copy report to clipboard', 'error');
    });
  });

  downloadJsonBtn.addEventListener('click', () => {
    if (!lastAuditData) {
      showToast('No audit data to export. Run an audit first.', 'warning');
      return;
    }
    const blob = new Blob([JSON.stringify(lastAuditData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `smart_contract_audit_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('JSON report downloaded', 'success');
  });

  function generateMarkdownReport(data) {
    const findings = (data.verified_mistakes || []).map((m, i) => 
      `### Finding ${i + 1}: ${m.category_name} - ${m.pattern_name} (Line ${m.line_number})\n` +
      `- **Code:** \`${m.line_content}\`\n` +
      `- **Mistake:** ${m.coding_mistake}\n` +
      `- **Recommended Fix:** ${m.suggested_fix}\n`
    ).join('\n');

    return `# Smart Contract Security Audit Report
Generated by AegisGuard Security Intelligence
Timestamp: ${new Date().toUTCString()}

## Overall Verdict
- **Status:** ${data.status}
- **Risk Score:** ${data.risk_score} / 100
- **Linear SVM Prediction:** ${data.ml_binary_prediction} (Confidence: ${data.svm_confidence_pct}%)
- **Decision Score:** ${data.svm_decision_score}
- **Lines of Code (LOC):** ${data.loc} (${data.sloc} SLOC)
- **Execution Time:** ${data.execution_time_ms} ms

## Summary
${data.mistake_summary}

## Detailed Verified Findings
${findings || 'No verified code pattern issues detected.'}

## Category Probability Distribution
${Object.entries(data.category_probabilities || {}).map(([k, v]) => `- **${k}:** ${v}%`).join('\n')}

## Security Recommendations
${(data.suggested_solutions || []).map((s, i) => `${i + 1}. ${s.replace(/\*\*/g, '')}`).join('\n')}
`;
  }

  // --- 7. Toast Notification Helper ---
  let toastTimer = null;
  function showToast(message, type = 'info') {
    if (toastTimer) clearTimeout(toastTimer);
    toastMsg.textContent = message;
    toast.className = 'toast show';

    if (type === 'error') {
      toast.style.borderColor = 'var(--rose-danger)';
    } else if (type === 'success') {
      toast.style.borderColor = 'var(--emerald)';
    } else if (type === 'warning') {
      toast.style.borderColor = 'var(--amber-warning)';
    } else {
      toast.style.borderColor = 'var(--cyan-primary)';
    }

    toastTimer = setTimeout(() => {
      toast.className = 'toast';
    }, 3200);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial setup: populate samples and load initial sample
  loadSamplesList();
  fetchAndSetSample('2_reentrancy_vault.sol');
});
