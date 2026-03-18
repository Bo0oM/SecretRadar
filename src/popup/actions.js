// SecretRadar - Popup Actions

import { debugLog, showNotification, displayStatus, displayError } from './ui.js';
import { loadCurrentTabFindings } from './findings.js';
import { isOriginDenied } from './denylist.js';

// Trigger manual scan
export async function triggerScan() {
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
      displayStatus('Cannot scan browser pages', 'warning');
      return;
    }

    // Try manual scan via background script (bypasses CSP)
    try {
      const response = await chrome.runtime.sendMessage({ action: 'manualScan' });

      if (response.success) {
        displayStatus('Scanning...', 'scanning');
        // Reload findings after a delay
        setTimeout(loadCurrentTabFindings, 2000);
      } else if (response.error === 'reload_required') {
        displayStatus('Refresh the page to enable scanning', 'warning');
      } else {
        displayStatus(response.error || 'Scan failed', 'error');
      }
    } catch (scriptError) {
      await debugLog('Manual scan failed:', scriptError.message);
      displayStatus('Scan failed - CSP restriction', 'warning');
    }

  } catch (error) {
    await debugLog('Error triggering scan:', error);
    displayStatus('Failed to trigger scan', 'error');
  }
}

// Force scan (bypass cache)
export async function forceScan() {
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
      displayStatus('Cannot scan browser pages', 'warning');
      return;
    }

    // Clear cache first
    await chrome.runtime.sendMessage({ action: 'clearCache' });

    // Try manual scan via background script (bypasses CSP)
    try {
      const response = await chrome.runtime.sendMessage({ action: 'manualScan' });

      if (response.success) {
        displayStatus('Force scanning...', 'scanning');
        // Reload findings after a delay
        setTimeout(loadCurrentTabFindings, 3000);
      } else if (response.error === 'reload_required') {
        displayStatus('Refresh the page to enable scanning', 'warning');
      } else {
        displayStatus(response.error || 'Force scan failed', 'error');
      }
    } catch (scriptError) {
      await debugLog('Force scan failed:', scriptError.message);
      displayStatus('Force scan failed - CSP restriction', 'warning');
    }

  } catch (error) {
    await debugLog('Error triggering force scan:', error);
    displayStatus('Failed to trigger force scan', 'error');
  }
}

// Clear cache
export async function clearCache() {
  try {
    // Send message to background script to clear cache
    await chrome.runtime.sendMessage({ action: 'clearCache' });
    showNotification('Cache cleared successfully', 'success');

    // Reload findings to show fresh data
    await loadCurrentTabFindings();
  } catch (error) {
    await debugLog('Error clearing cache:', error);
    showNotification('Failed to clear cache', 'error');
  }
}

// Safely escape a value for CSV (prevents formula injection)
function csvEscape(value) {
  const str = String(value ?? '').replace(/"/g, '""');
  // Prefix formula-starting characters to prevent spreadsheet injection
  return `"${/^[=+\-@\t\r]/.test(str) ? "'" + str : str}"`;
}

// Export findings to CSV
export async function exportFindings() {
  try {
    const storage = await chrome.storage.local.get(['findings']);
    const findings = storage.findings || {};

    let csvContent = 'Origin,Type,Source,Match,Confidence,Timestamp\n';

    for (const [origin, originFindings] of Object.entries(findings)) {
      for (const finding of originFindings) {
        csvContent += `${csvEscape(origin)},${csvEscape(finding.type)},${csvEscape(finding.source)},${csvEscape(finding.match)},${finding.confidence},${new Date(finding.timestamp).toISOString()}\n`;
      }
    }

    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secretradar-findings-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

  } catch (error) {
    await debugLog('Error exporting findings:', error);
    displayError('Failed to export findings');
  }
}

// Clear findings from denied domains
export async function clearDeniedDomainFindings() {
  try {
    const storage = await chrome.storage.local.get(['findings', 'denyList']);
    const findings = storage.findings || {};

    let clearedCount = 0;
    const cleanedFindings = {};

    for (const [origin, originFindings] of Object.entries(findings)) {
      // Check if origin is in deny list
      const isDenied = await isOriginDenied(origin);
      if (isDenied) {
        clearedCount += originFindings.length;
        continue; // Skip this origin
      }
      cleanedFindings[origin] = originFindings;
    }

    if (clearedCount > 0) {
      await chrome.storage.local.set({ findings: cleanedFindings });
      showNotification(`Cleared ${clearedCount} findings from denied domains`, 'success');
      await loadCurrentTabFindings(); // Refresh display
    } else {
      showNotification('No findings from denied domains to clear', 'info');
    }
  } catch (error) {
    await debugLog('Error clearing denied domain findings:', error);
    showNotification('Error clearing denied domain findings', 'error');
  }
}

// Open dashboard in new tab
export async function openDashboard() {
  try {
    const dashboardUrl = chrome.runtime.getURL('dashboard.html');
    await chrome.tabs.create({ url: dashboardUrl });
  } catch (error) {
    await debugLog('Error opening dashboard:', error);
    window.open(chrome.runtime.getURL('dashboard.html'), '_blank');
  }
}
