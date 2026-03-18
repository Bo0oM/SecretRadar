// SecretRadar - Popup Entry Point

import { initializeSettings, updateUI } from './src/popup/settings.js';
import { loadCurrentTabFindings } from './src/popup/findings.js';
import { removeFromDenyList, addToDenyList, clearDenyList } from './src/popup/denylist.js';
import { debugLog, showNotification } from './src/popup/ui.js';
import { triggerScan, forceScan, clearCache, exportFindings, clearDeniedDomainFindings, openDashboard } from './src/popup/actions.js';
import { clearCurrentTabFindings, clearAllData } from './src/popup/findings.js';
import { resetSettings, toggleAdvancedSettings } from './src/popup/settings.js';

// CRITICAL: expose removeFromDenyList globally for inline onclick handlers in loadDenyList
window.removeFromDenyList = removeFromDenyList;

document.addEventListener('DOMContentLoaded', async function() {
  // Notify background script that popup is opened
  await chrome.runtime.sendMessage({ action: 'popupOpened' });

  // Initialize settings
  await initializeSettings();

  // Load current tab findings
  await loadCurrentTabFindings();

  // Setup event listeners
  setupEventListeners();

  // Update UI
  await updateUI();
});

// Setup event listeners
function setupEventListeners() {
  // Settings toggles
  const toggles = ['enableNotifications', 'autoScan', 'scanExternalScripts', 'scanSourceMaps', 'scanSensitiveFiles', 'debugMode', 'verboseScanning'];

  toggles.forEach(toggleId => {
    const element = document.getElementById(toggleId);
    if (element) {
      element.addEventListener('change', async (e) => {
        await chrome.storage.local.set({ [toggleId]: e.target.checked });
        updateUI();
      });
    }
  });

  // Confidence threshold slider
  const confidenceSlider = document.getElementById('confidenceThreshold');
  if (confidenceSlider) {
    confidenceSlider.addEventListener('input', async (e) => {
      const value = parseFloat(e.target.value);
      await chrome.storage.local.set({ confidenceThreshold: value });
      document.getElementById('confidenceValue').textContent = `${Math.round(value * 100)}%`;
    });
  }

  // Data retention slider
  const retentionSlider = document.getElementById('dataRetentionDays');
  if (retentionSlider) {
    retentionSlider.addEventListener('input', async (e) => {
      const value = parseInt(e.target.value);
      await chrome.storage.local.set({ dataRetentionDays: value });
      document.getElementById('retentionValue').textContent = `${value} days`;
    });
  }

  // Deny list controls
  const addDomainButton = document.getElementById('addDomain');
  const newDomainInput = document.getElementById('newDomain');

  if (addDomainButton && newDomainInput) {
    addDomainButton.addEventListener('click', async () => {
      const domain = newDomainInput.value.trim();
      if (domain) {
        const success = await addToDenyList(domain);
        if (success) {
          newDomainInput.value = '';
        }
      }
    });

    // Allow Enter key to add domain
    newDomainInput.addEventListener('keypress', async (e) => {
      if (e.key === 'Enter') {
        const domain = newDomainInput.value.trim();
        if (domain) {
          const success = await addToDenyList(domain);
          if (success) {
            newDomainInput.value = '';
          }
        }
      }
    });
  }

  const clearDenyListButton = document.getElementById('clearDenyList');
  if (clearDenyListButton) {
    clearDenyListButton.addEventListener('click', async () => {
      if (confirm('Are you sure you want to clear all domains from the deny list?')) {
        await clearDenyList();
      }
    });
  }

  // Action buttons
  const scanButton = document.getElementById('scanNow');
  if (scanButton) {
    scanButton.addEventListener('click', async () => {
      await triggerScan();
    });
  }

  const forceScanButton = document.getElementById('forceScan');
  if (forceScanButton) {
    forceScanButton.addEventListener('click', async () => {
      await forceScan();
    });
  }

  const clearButton = document.getElementById('clearFindings');
  if (clearButton) {
    clearButton.addEventListener('click', async () => {
      await clearCurrentTabFindings();
    });
  }

  const exportButton = document.getElementById('exportFindings');
  if (exportButton) {
    exportButton.addEventListener('click', async () => {
      await exportFindings();
    });
  }

  const clearDeniedButton = document.getElementById('clearDeniedFindings');
  if (clearDeniedButton) {
    clearDeniedButton.addEventListener('click', async () => {
      await clearDeniedDomainFindings();
    });
  }

  const clearCacheButton = document.getElementById('clearCache');
  if (clearCacheButton) {
    clearCacheButton.addEventListener('click', async () => {
      await clearCache();
    });
  }

  const clearAllDataButton = document.getElementById('clearAllData');
  if (clearAllDataButton) {
    clearAllDataButton.addEventListener('click', async () => {
      if (confirm('Clear all findings? Settings and deny list will be preserved.')) {
        await clearAllData();
      }
    });
  }

  const resetSettingsButton = document.getElementById('resetSettings');
  if (resetSettingsButton) {
    resetSettingsButton.addEventListener('click', async () => {
      if (confirm('Reset all settings to defaults?')) {
        await resetSettings();
      }
    });
  }

  // Source link click handler (delegated event)
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('source-link')) {
      e.preventDefault();
      const url = e.target.getAttribute('data-url');
      if (url) {
        // Try to open URL in new tab
        try {
          // For file:// URLs, we need to handle them differently
          if (url.startsWith('file://')) {
            // For file URLs, we can't open them directly due to security restrictions
            // Instead, we can copy the path to clipboard or show a message
            navigator.clipboard.writeText(url).then(() => {
              showNotification('File path copied to clipboard', 'info');
            }).catch(() => {
              showNotification('File URL: ' + url, 'info');
            });
          } else {
            // For web URLs, open in new tab
            chrome.tabs.create({ url: url });
          }
        } catch (error) {
          debugLog('Error opening URL:', error);
          showNotification('Error opening URL', 'error');
        }
      }
    }
  });

  const advancedButton = document.getElementById('openSettings');
  if (advancedButton) {
    advancedButton.addEventListener('click', async () => {
      await toggleAdvancedSettings();
    });
  }

  const dashboardButton = document.getElementById('openDashboard');
  if (dashboardButton) {
    dashboardButton.addEventListener('click', async () => {
      await openDashboard();
    });
  }
}
