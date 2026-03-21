// SecretRadar - Popup Findings

import { debugLog, showNotification, displayStatus, escapeHtml, getConfidenceClass, setupFilters } from './ui.js';
import { isOriginDenied } from './denylist.js';

// Load findings for current tab
export async function loadCurrentTabFindings() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Handle cases where tab is not available
    if (!tab) {
      displayStatus('No active tab', 'warning');
      return;
    }

    // Handle cases where URL is not available or page is not loaded
    if (!tab.url || tab.url === 'about:blank' || tab.url === 'chrome://newtab/') {
      displayStatus('Page not loaded yet', 'scanning');
      return;
    }

    // Handle browser/system pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      displayStatus('Browser page - scanning disabled', 'safe');
      return;
    }

    // Handle invalid URLs
    let origin;
    try {
      origin = new URL(tab.url).origin;
    } catch (urlError) {
      displayStatus('Invalid URL', 'warning');
      return;
    }

    // Check if origin is denied
    const isDenied = await isOriginDenied(tab.url);
    await debugLog(`Origin ${origin} is denied: ${isDenied}`);

    const storage = await chrome.storage.local.get(['findings', 'confidenceThreshold']);
    const threshold = storage.confidenceThreshold ?? 0.3;

    // Collect all findings whose parentOrigin matches current tab origin
    // Filter by confidence threshold here (UI-side) — storage always has all findings
    let findings = [];
    if (storage.findings) {
      for (const keyFindings of Object.values(storage.findings)) {
        for (const finding of keyFindings) {
          if (finding.parentOrigin === origin && finding.confidence >= threshold) {
            findings.push(finding);
          }
        }
      }
    }

    await debugLog(`Found ${findings.length} findings for ${origin} (threshold: ${threshold})`);

    await displayFindings(findings, origin, isDenied);
  } catch (error) {
    await debugLog('Error loading findings:', error);
    displayStatus('Error loading data', 'error');
  }
}

// Display findings in the popup
export function displayFindings(findings, origin, isDenied = false) {
  const findingsContainer = document.getElementById('findingsList');
  const statusElement = document.getElementById('status');

  if (!findingsContainer || !statusElement) {
    debugLog('Required elements not found');
    return;
  }

  // Handle denied origins
  if (isDenied) {
    statusElement.textContent = 'Site is in deny list - scanning disabled';
    statusElement.className = 'status denied';
    findingsContainer.innerHTML = `
      <div class="denied-message">
        <p>🔒 This site has been added to the deny list.</p>
        <p>SecretRadar scanning is disabled for this domain.</p>
        <p>To re-enable scanning, remove this site from the deny list in settings.</p>
      </div>
    `;
    return;
  }

  if (findings.length === 0) {
    statusElement.textContent = 'No security issues found';
    statusElement.className = 'status safe';
    findingsContainer.innerHTML = '<p class="no-findings">No sensitive data detected on this page.</p>';
    return;
  }

  statusElement.textContent = `${findings.length} security issue(s) found`;
  statusElement.className = 'status warning';

  const filterHTML = `
    <div class="findings-filter">
      <input type="text" id="findingsFilter" placeholder="Filter findings..." class="filter-input">
      <select id="confidenceFilter" class="filter-select">
        <option value="">All confidence levels</option>
        <option value="high">High confidence (80%+)</option>
        <option value="medium">Medium confidence (50-79%)</option>
        <option value="low">Low confidence (30-49%)</option>
      </select>

    </div>
  `;

  const findingsHTML = findings.map(finding => `
    <div class="finding-item ${getConfidenceClass(finding.confidence)}"
         data-type="${finding.type}"
         data-confidence="${Math.round(finding.confidence * 100)}"
         data-source="${escapeHtml(finding.source)}">
      <div class="finding-header">
        <span class="finding-type">${escapeHtml(finding.type)}</span>
        <div class="finding-header-right">
          <span class="confidence-badge">${Math.round(finding.confidence * 100)}%</span>
          <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6,9 12,15 18,9"/></svg>
        </div>
      </div>
      <div class="finding-details">
        <div class="finding-match">
          <code class="copyable-secret" data-value="${escapeHtml(finding.match)}" title="Click to copy">${escapeHtml(finding.displayValue || finding.match.substring(0, 60))}${!finding.displayValue && finding.match.length > 60 ? '...' : ''}</code>
        </div>
        <div class="finding-source">Source: <a href="#" class="source-link" data-url="${escapeHtml(finding.source)}">${escapeHtml(finding.source)}</a></div>
        ${finding.context.surroundingText ? `<div class="finding-context">${escapeHtml(finding.context.surroundingText)}</div>` : ''}
        <div class="finding-time">${new Date(finding.timestamp).toLocaleString()}</div>
      </div>
    </div>
  `).join('');

  findingsContainer.innerHTML = filterHTML + findingsHTML;

  setupFilters();
  setupFindingInteractions(findingsContainer);
}

function setupFindingInteractions(container) {
  // Collapse/expand on header click
  container.querySelectorAll('.finding-header').forEach(header => {
    header.addEventListener('click', (e) => {
      if (e.target.closest('.source-link')) return;
      const item = header.closest('.finding-item');
      item.classList.toggle('expanded');
    });
  });

  // Copy secret on code click
  container.querySelectorAll('.copyable-secret').forEach(code => {
    code.addEventListener('click', async (e) => {
      e.stopPropagation();
      const value = code.dataset.value;
      try {
        await navigator.clipboard.writeText(value);
        code.classList.add('copied');
        setTimeout(() => code.classList.remove('copied'), 1500);
      } catch {
        // fallback for restricted contexts
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        code.classList.add('copied');
        setTimeout(() => code.classList.remove('copied'), 1500);
      }
    });
  });
}

// Clear findings for current tab
export async function clearCurrentTabFindings() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Handle cases where tab is not available
    if (!tab) {
      displayStatus('No active tab', 'warning');
      return;
    }

    // Handle cases where URL is not available or page is not loaded
    if (!tab.url || tab.url === 'about:blank' || tab.url === 'chrome://newtab/') {
      displayStatus('Page not loaded yet', 'scanning');
      return;
    }

    // Handle browser/system pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      displayStatus('No findings on browser pages', 'safe');
      return;
    }

    // Handle invalid URLs
    let origin;
    try {
      origin = new URL(tab.url).origin;
    } catch (urlError) {
      displayStatus('Invalid URL', 'warning');
      return;
    }

    const storage = await chrome.storage.local.get(['findings']);
    let cleared = false;

    if (storage.findings) {
      // Clear by exact URL
      if (storage.findings[tab.url]) {
        delete storage.findings[tab.url];
        cleared = true;
      }

      // Clear by origin
      if (storage.findings[origin]) {
        delete storage.findings[origin];
        cleared = true;
      }

      // Clear by any key containing origin
      for (const key of Object.keys(storage.findings)) {
        if (key.includes(origin)) {
          delete storage.findings[key];
          cleared = true;
        }
      }

      if (cleared) {
        await chrome.storage.local.set({ findings: storage.findings });

        // Allow future notifications for this origin now that findings are gone
        chrome.runtime.sendMessage({ action: 'findingsCleared', origin }).catch(() => {});

        // Update badge
        await chrome.action.setBadgeText({ text: '' });

        // Reload display
        await loadCurrentTabFindings();
      } else {
        displayStatus('No findings to clear', 'safe');
      }
    } else {
      displayStatus('No findings to clear', 'safe');
    }
  } catch (error) {
    await debugLog('Error clearing findings:', error);
    displayStatus('Failed to clear findings', 'error');
  }
}

// Clear all findings (settings and deny list are preserved)
export async function clearAllData() {
  try {
    await chrome.storage.local.remove(['findings']);
    // Allow future notifications for all origins
    chrome.runtime.sendMessage({ action: 'findingsCleared', origin: null }).catch(() => {});
    await chrome.action.setBadgeText({ text: '' });
    await loadCurrentTabFindings();
    showNotification('All findings cleared', 'success');
  } catch (error) {
    await debugLog('Error clearing all data:', error);
    showNotification('Failed to clear findings', 'error');
  }
}
