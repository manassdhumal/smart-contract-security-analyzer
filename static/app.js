/**
 * AegisGuard - Smart Contract Security Intelligence Frontend Logic
 * High-performance Vanilla JavaScript implementation with Monaco IDE integration,
 * interactive remediation patch diff viewer, and instant AST fixes.
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
  const monacoHost = document.getElementById('monacoHost');

  // Patch Diff Modal Elements
  const patchModal = document.getElementById('patchModal');
  const closePatchModalBtn = document.getElementById('closePatchModalBtn');
  const patchModalTitle = document.getElementById('patchModalTitle');
  const patchModalSubtitle = document.getElementById('patchModalSubtitle');
  const patchLineNum = document.getElementById('patchLineNum');
  const patchOriginalCode = document.getElementById('patchOriginalCode');
  const patchFixedCode = document.getElementById('patchFixedCode');
  const patchDiffPreview = document.getElementById('patchDiffPreview');
  const patchExplanationText = document.getElementById('patchExplanationText');
  const copyPatchCodeBtn = document.getElementById('copyPatchCodeBtn');
  const applyPatchBtn = document.getElementById('applyPatchBtn');

  // Web3 / Blockchain Contract Import Elements
  const openWeb3ImportBtn = document.getElementById('openWeb3ImportBtn');
  const web3ImportModal = document.getElementById('web3ImportModal');
  const closeWeb3ModalBtn = document.getElementById('closeWeb3ModalBtn');
  const cancelWeb3ModalBtn = document.getElementById('cancelWeb3ModalBtn');
  const submitWeb3FetchBtn = document.getElementById('submitWeb3FetchBtn');
  const web3NetworkSelect = document.getElementById('web3NetworkSelect');
  const web3AddressInput = document.getElementById('web3AddressInput');
  const web3StatusBox = document.getElementById('web3StatusBox');
  const web3StatusText = document.getElementById('web3StatusText');
  const presetPillBtns = document.querySelectorAll('.preset-pill-btn');

  // Scanning & Result View States
  const idleState = document.getElementById('idleState');
  const scanningState = document.getElementById('scanningState');
  const resultsState = document.getElementById('resultsState');
  const scanProgressBar = document.getElementById('scanProgressBar');

  // Results HUD Components
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
  let activePatchFinding = null;
  let monacoEditorInstance = null;

  // --- 1. Editor Abstraction & Synchronization ---
  function getEditorCode() {
    if (monacoEditorInstance) {
      return monacoEditorInstance.getValue();
    }
    return codeEditor.value;
  }

  function setEditorCode(val) {
    codeEditor.value = val;
    if (monacoEditorInstance) {
      if (monacoEditorInstance.getValue() !== val) {
        monacoEditorInstance.setValue(val);
      }
    }
    updateLineNumbers();
  }

  function updateLineNumbers() {
    const text = codeEditor.value;
    const lines = text.split('\n');
    const lineCount = lines.length || 1;
    
    // Fallback line gutter
    let numbersText = '';
    for (let i = 1; i <= lineCount; i++) {
      numbersText += i + '\n';
    }
    lineGutter.textContent = numbersText;

    const charCount = text.length;
    editorStats.textContent = `${lineCount} line${lineCount === 1 ? '' : 's'} | ${charCount.toLocaleString()} chars`;
  }

  // Synchronize gutter scrolling with fallback textarea scrolling
  codeEditor.addEventListener('scroll', () => {
    lineGutter.scrollTop = codeEditor.scrollTop;
  });

  codeEditor.addEventListener('input', () => {
    updateLineNumbers();
  });

  // Tab key indent support for fallback textarea
  codeEditor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = codeEditor.selectionStart;
      const end = codeEditor.selectionEnd;
      codeEditor.value = codeEditor.value.substring(0, start) + '    ' + codeEditor.value.substring(end);
      codeEditor.selectionStart = codeEditor.selectionEnd = start + 4;
      updateLineNumbers();
    }
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
      readFileToEditor(e.dataTransfer.files[0]);
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
      setEditorCode(event.target.result);
      showToast(`Loaded "${file.name}" into editor`, 'success');
    };
    reader.onerror = () => {
      showToast(`Failed to read file ${file.name}`, 'error');
    };
    reader.readAsText(file);
  }

  // Clear Editor
  clearBtn.addEventListener('click', () => {
    setEditorCode('');
    sampleSelect.value = '';
    showToast('Editor cleared', 'info');
  });

  // --- 2. Monaco Editor Integration ---
  function initMonacoEditor() {
    if (typeof window.require !== 'undefined' && window.require.config) {
      window.require.config({
        paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs' }
      });

      window.require(['vs/editor/editor.main'], function () {
        try {
          if (!monaco.languages.getLanguages().some(lang => lang.id === 'solidity')) {
            monaco.languages.register({ id: 'solidity' });
            monaco.languages.setMonarchTokensProvider('solidity', {
              keywords: [
                'pragma', 'solidity', 'contract', 'library', 'interface', 'function', 'modifier',
                'event', 'error', 'struct', 'enum', 'mapping', 'address', 'uint', 'uint256',
                'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'int', 'int256', 'bytes',
                'bytes32', 'string', 'bool', 'public', 'private', 'internal', 'external',
                'pure', 'view', 'payable', 'memory', 'storage', 'calldata', 'returns', 'return',
                'if', 'else', 'for', 'while', 'do', 'break', 'continue', 'revert', 'require',
                'assert', 'emit', 'new', 'delete', 'this', 'super', 'override', 'virtual',
                'is', 'indexed', 'anonymous', 'constant', 'immutable', 'type', 'assembly'
              ],
              operators: [
                '=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=',
                '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%',
                '<<', '>>', '+=', '-=', '*=', '/='
              ],
              tokenizer: {
                root: [
                  [/\b(msg\.sender|msg\.value|msg\.data|tx\.origin|block\.timestamp|block\.number|block\.prevrandao|blockhash|gasleft|now)\b/, 'variable.predefined'],
                  [/[a-zA-Z_$][\w$]*/, {
                    cases: {
                      '@keywords': 'keyword',
                      '@default': 'identifier'
                    }
                  }],
                  [/\/\/.*/, 'comment'],
                  [/\/\*/, 'comment', '@comment'],
                  [/"([^"\\]|\\.)*"/, 'string'],
                  [/'([^'\\]|\\.)*'/, 'string'],
                  [/\d+/, 'number'],
                ],
                comment: [
                  [/[^\/*]+/, 'comment'],
                  [/\*\//, 'comment', '@pop'],
                  [/[\/*]/, 'comment']
                ]
              }
            });
          }

          monaco.editor.defineTheme('aegis-dark', {
            base: 'vs-dark',
            inherit: true,
            rules: [
              { token: 'keyword', foreground: '06b6d4', fontStyle: 'bold' },
              { token: 'variable.predefined', foreground: 'f43f5e', fontStyle: 'bold' },
              { token: 'comment', foreground: '64748b', fontStyle: 'italic' },
              { token: 'string', foreground: '10b981' },
              { token: 'number', foreground: 'f59e0b' },
              { token: 'identifier', foreground: 'e2e8f0' }
            ],
            colors: {
              'editor.background': '#080c16',
              'editor.foreground': '#f8fafc',
              'editorLineNumber.foreground': '#475569',
              'editorLineNumber.activeForeground': '#06b6d4',
              'editor.selectionBackground': '#0369a144',
              'editor.lineHighlightBackground': '#0c1322',
              'editorCursor.foreground': '#06b6d4'
            }
          });

          if (monacoHost) {
            monacoHost.classList.add('active');
            lineGutter.style.display = 'none';
            codeEditor.style.display = 'none';

            monacoEditorInstance = monaco.editor.create(monacoHost, {
              value: codeEditor.value,
              language: 'solidity',
              theme: 'aegis-dark',
              automaticLayout: true,
              fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
              fontSize: 13.5,
              lineHeight: 22,
              minimap: { enabled: true, renderCharacters: false, scale: 1 },
              scrollBeyondLastLine: false,
              padding: { top: 12, bottom: 12 },
              smoothScrolling: true,
              cursorBlinking: 'smooth',
              renderLineHighlight: 'all',
              tabSize: 4
            });

            monacoEditorInstance.onDidChangeModelContent(() => {
              const val = monacoEditorInstance.getValue();
              codeEditor.value = val;
              const lines = val.split('\n');
              editorStats.textContent = `${lines.length} line${lines.length === 1 ? '' : 's'} | ${val.length.toLocaleString()} chars`;
            });

            monacoEditorInstance.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
              runSecurityAudit();
            });
          }
        } catch (err) {
          console.warn('Monaco editor setup fallback to native textarea:', err);
        }
      });
    }
  }

  // --- 3. Sample Contracts Loading ---
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
      setEditorCode(sampleCache[filename]);
      sampleSelect.value = filename;
      showToast(`Loaded sample: ${filename}`, 'info');
      return;
    }

    try {
      const res = await fetch(`/api/samples/${encodeURIComponent(filename)}`);
      if (!res.ok) throw new Error('Sample not found');
      const data = await res.json();
      sampleCache[filename] = data.code;
      setEditorCode(data.code);
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

  // --- 4. Tab Navigation ---
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

  // --- 5. Run Security Audit ---
  analyzeBtn.addEventListener('click', runSecurityAudit);

  async function runSecurityAudit() {
    const code = getEditorCode().trim();
    if (!code) {
      showToast('Please enter or upload Solidity source code first.', 'warning');
      if (monacoEditorInstance) monacoEditorInstance.focus();
      else codeEditor.focus();
      return;
    }

    // Switch UI to scanning state
    analyzeBtn.disabled = true;
    analyzeBtnText.textContent = 'Auditing Contract...';
    idleState.classList.add('hidden');
    resultsState.classList.add('hidden');
    scanningState.classList.remove('hidden');

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

      scanProgressBar.style.width = '100%';

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
      if (el) {
        el.classList.remove('active', 'completed');
        setTimeout(() => {
          el.classList.add('active');
          scanProgressBar.style.width = `${Math.min(25 + idx * 18, 90)}%`;
          if (idx > 0) {
            const prev = document.getElementById(steps[idx - 1]);
            if (prev) {
              prev.classList.remove('active');
              prev.classList.add('completed');
            }
          }
        }, idx * 120);
      }
    });
  }

  // --- 6. Render Audit Results ---
  function renderAuditResults(data) {
    const isVulnerable = data.is_vulnerable;
    const mistakes = data.verified_mistakes || [];
    const riskScore = data.risk_score || 0;

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

    // KPI Metrics
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
              <span class="category-tag">${escapeHtml(item.category_name)}</span>
            </div>
            <span class="pattern-tag">${escapeHtml(item.pattern_name)}</span>
          </div>
          <div class="finding-code-snippet">${escapeHtml(item.line_content || item.code_line)}</div>
          <div class="finding-explanation">${escapeHtml(item.coding_mistake)}</div>
          <div class="finding-fix"><strong>Suggested Fix:</strong> ${escapeHtml(item.suggested_fix)}</div>
          <div class="finding-actions">
            <button type="button" class="btn-quick-patch">
              <span>⚡ Remediate & Diff</span>
            </button>
            <button type="button" class="btn-jump-line">
              <span>📍 Focus Line</span>
            </button>
          </div>
        `;

        const patchBtn = card.querySelector('.btn-quick-patch');
        patchBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          openPatchModal(item);
        });

        const jumpBtn = card.querySelector('.btn-jump-line');
        jumpBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          highlightLineInEditor(item.line_number);
        });

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
          <span class="cat-name">${escapeHtml(catName)}</span>
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
      const cleanHtml = escapeHtml(solText).replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
      card.innerHTML = `<div class="rem-body">${cleanHtml}</div>`;
      remediationList.appendChild(card);
    });
  }

  // --- 7. Editor Line Navigation ---
  function highlightLineInEditor(targetLine) {
    if (monacoEditorInstance) {
      const model = monacoEditorInstance.getModel();
      const lineCount = model ? model.getLineCount() : 1;
      const safeLine = Math.min(Math.max(1, targetLine), lineCount);
      monacoEditorInstance.revealLineInCenter(safeLine);
      monacoEditorInstance.setPosition({ lineNumber: safeLine, column: 1 });
      monacoEditorInstance.focus();
      showToast(`Focused on line ${safeLine}`, 'info');
      return;
    }

    // Fallback textarea navigation
    const text = codeEditor.value;
    const lines = text.split('\n');
    if (targetLine < 1 || targetLine > lines.length) return;

    let charOffset = 0;
    for (let i = 0; i < targetLine - 1; i++) {
      charOffset += lines[i].length + 1;
    }
    const lineLength = lines[targetLine - 1].length;

    codeEditor.focus();
    codeEditor.setSelectionRange(charOffset, charOffset + lineLength);

    const approxLineHeight = 25.6;
    codeEditor.scrollTop = Math.max(0, (targetLine - 4) * approxLineHeight);
    lineGutter.scrollTop = codeEditor.scrollTop;

    showToast(`Focused on line ${targetLine}`, 'info');
  }

  // --- 8. Patch Remediation Diff Modal Controller ---
  function openPatchModal(finding) {
    if (!finding) return;
    activePatchFinding = finding;

    patchModalTitle.textContent = `${finding.category_name} Remediation`;
    patchModalSubtitle.textContent = finding.pattern_name;
    patchLineNum.textContent = finding.line_number || '--';

    const patch = finding.patch_info || {};
    const originalText = patch.original || finding.line_content || finding.code_line || '// Original code';
    const fixedText = patch.fixed || '// Remediated secure code';

    patchOriginalCode.querySelector('code').textContent = originalText;
    patchFixedCode.querySelector('code').textContent = fixedText;

    // Render formatted unified diff with line decorations
    const diffRaw = patch.diff || `--- a/contract.sol\n+++ b/contract.sol\n- ${originalText}\n+ ${fixedText}`;
    const diffLines = diffRaw.split('\n').map(line => {
      if (line.startsWith('+')) {
        return `<span class="diff-line-added">${escapeHtml(line)}</span>`;
      } else if (line.startsWith('-')) {
        return `<span class="diff-line-removed">${escapeHtml(line)}</span>`;
      } else {
        return escapeHtml(line);
      }
    }).join('\n');
    patchDiffPreview.querySelector('code').innerHTML = diffLines;

    patchExplanationText.innerHTML = `<strong>Remediation Rationale:</strong> ${escapeHtml(patch.explanation || finding.suggested_fix || 'Enforce defensive security checks and safe execution patterns.')}`;

    patchModal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  function closePatchModal() {
    if (patchModal) {
      patchModal.classList.add('hidden');
      document.body.style.overflow = '';
    }
  }

  if (closePatchModalBtn) {
    closePatchModalBtn.addEventListener('click', closePatchModal);
  }

  if (patchModal) {
    patchModal.addEventListener('click', (e) => {
      if (e.target === patchModal) closePatchModal();
    });
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && patchModal && !patchModal.classList.contains('hidden')) {
      closePatchModal();
    }
  });

  if (copyPatchCodeBtn) {
    copyPatchCodeBtn.addEventListener('click', () => {
      if (!activePatchFinding || !activePatchFinding.patch_info) return;
      const codeToCopy = activePatchFinding.patch_info.fixed;
      navigator.clipboard.writeText(codeToCopy).then(() => {
        showToast('Remediated code copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Could not copy code to clipboard', 'error');
      });
    });
  }

  if (applyPatchBtn) {
    applyPatchBtn.addEventListener('click', () => {
      if (!activePatchFinding || !activePatchFinding.patch_info) return;
      const targetLine = activePatchFinding.line_number;
      const patch = activePatchFinding.patch_info;

      if (monacoEditorInstance) {
        const model = monacoEditorInstance.getModel();
        const lineCount = model ? model.getLineCount() : 1;
        if (targetLine >= 1 && targetLine <= lineCount) {
          const lineContent = model.getLineContent(targetLine);
          const range = new monaco.Range(targetLine, 1, targetLine, lineContent.length + 1);
          monacoEditorInstance.executeEdits('aegis-patch', [{
            range: range,
            text: patch.fixed,
            forceMoveMarkers: true
          }]);
          monacoEditorInstance.pushUndoStop();
          codeEditor.value = monacoEditorInstance.getValue();
          monacoEditorInstance.revealLineInCenter(targetLine);
          monacoEditorInstance.setPosition({ lineNumber: targetLine, column: 1 });
          monacoEditorInstance.focus();
        }
      } else {
        const lines = codeEditor.value.split('\n');
        if (targetLine >= 1 && targetLine <= lines.length) {
          lines[targetLine - 1] = patch.fixed;
          codeEditor.value = lines.join('\n');
          updateLineNumbers();
          highlightLineInEditor(targetLine);
        }
      }

      closePatchModal();
      showToast(`⚡ Security patch applied to Line ${targetLine}! Click 'Analyze' to re-audit.`, 'success');
    });
  }

  // --- 9. Web3 / Blockchain Contract Import Controller ---
  function openWeb3Modal() {
    if (!web3ImportModal) return;
    web3ImportModal.classList.remove('hidden');
    if (web3StatusBox) web3StatusBox.classList.add('hidden');
    if (web3AddressInput) {
      web3AddressInput.focus();
      web3AddressInput.select();
    }
    document.body.style.overflow = 'hidden';
  }

  function closeWeb3Modal() {
    if (!web3ImportModal) return;
    web3ImportModal.classList.add('hidden');
    if (web3StatusBox) web3StatusBox.classList.add('hidden');
    document.body.style.overflow = '';
  }

  if (openWeb3ImportBtn) {
    openWeb3ImportBtn.addEventListener('click', openWeb3Modal);
  }

  if (closeWeb3ModalBtn) {
    closeWeb3ModalBtn.addEventListener('click', closeWeb3Modal);
  }

  if (cancelWeb3ModalBtn) {
    cancelWeb3ModalBtn.addEventListener('click', closeWeb3Modal);
  }

  if (web3ImportModal) {
    web3ImportModal.addEventListener('click', (e) => {
      if (e.target === web3ImportModal) closeWeb3Modal();
    });
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && web3ImportModal && !web3ImportModal.classList.contains('hidden')) {
      closeWeb3Modal();
    }
  });

  presetPillBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const addr = btn.getAttribute('data-addr');
      const net = btn.getAttribute('data-net');
      if (addr && web3AddressInput) web3AddressInput.value = addr;
      if (net && web3NetworkSelect) web3NetworkSelect.value = net;
      fetchWeb3Contract();
    });
  });

  async function fetchWeb3Contract() {
    const address = (web3AddressInput ? web3AddressInput.value : '').trim();
    const network = web3NetworkSelect ? web3NetworkSelect.value : 'mainnet';

    const ethRegex = /^0x[a-fA-F0-9]{40}$/;
    if (!ethRegex.test(address)) {
      showWeb3Status('Invalid Ethereum address. Must be a 42-character hex address starting with 0x.', true);
      return;
    }

    if (submitWeb3FetchBtn) submitWeb3FetchBtn.disabled = true;
    showWeb3Status(`Connecting to ${network} explorer & retrieving verified Solidity source...`, false);

    try {
      const resp = await fetch(`/api/fetch-contract?address=${encodeURIComponent(address)}&network=${encodeURIComponent(network)}`);
      const data = await resp.json();

      if (!resp.ok) {
        throw new Error(data.detail || `Explorer returned status ${resp.status}`);
      }

      setEditorCode(data.code);
      closeWeb3Modal();
      sampleSelect.value = '';

      showToast(`Imported "${data.contract_name}" (${data.files_count} file${data.files_count > 1 ? 's' : ''}) from ${data.network}!`, 'success');

      // Auto-trigger security audit for the newly imported contract
      setTimeout(() => {
        runSecurityAudit();
      }, 400);

    } catch (err) {
      showWeb3Status(err.message, true);
    } finally {
      if (submitWeb3FetchBtn) submitWeb3FetchBtn.disabled = false;
    }
  }

  function showWeb3Status(msg, isError = false) {
    if (!web3StatusBox || !web3StatusText) return;
    web3StatusBox.classList.remove('hidden');
    web3StatusText.textContent = msg;
    if (isError) {
      web3StatusBox.classList.add('error');
    } else {
      web3StatusBox.classList.remove('error');
    }
  }

  if (submitWeb3FetchBtn) {
    submitWeb3FetchBtn.addEventListener('click', fetchWeb3Contract);
  }

  if (web3AddressInput) {
    web3AddressInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        fetchWeb3Contract();
      }
    });
  }

  // --- 10. Report Export Actions ---
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
      `- **Code:** \`${m.line_content || m.code_line}\`\n` +
      `- **Mistake:** ${m.coding_mistake}\n` +
      `- **Recommended Fix:** ${m.suggested_fix}\n` +
      (m.patch_info ? `- **Remediation Diff:**\n\`\`\`diff\n${m.patch_info.diff}\n\`\`\`\n` : '')
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

  // --- 10. Toast Notification Helper ---
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
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial setup: populate samples, load default, and initialize Monaco Editor
  initMonacoEditor();
  loadSamplesList();
  fetchAndSetSample('2_reentrancy_vault.sol');
});
