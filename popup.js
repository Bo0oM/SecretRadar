// SecretRadar - Popup Script
// Manifest V3 compatible with improved UI and functionality

// Debug logging helper function
async function debugLog(message, ...args) {
  try {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings.debugMode) {
      console.log('[SecretRadar Debug]', message, ...args);
    }
  } catch (error) {
  }
}

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
  updateUI();
});

// Initialize extension settings
async function initializeSettings() {
  const defaults = {
    enableNotifications: true,
    confidenceThreshold: 0.3,
    autoScan: true,
    scanExternalScripts: true,
    scanSourceMaps: true,
    scanSensitiveFiles: false,
    denyList: ['https://www.google.com', '*.google.com'],
    dataRetentionDays: 7, // Default 7 days
    showAdvancedSettings: false,
    debugMode: false,
    verboseScanning: false
  };

  const storage = await chrome.storage.local.get(Object.keys(defaults));
  
  // Set defaults for missing settings
  for (const [key, value] of Object.entries(defaults)) {
    if (storage[key] === undefined) {
      await chrome.storage.local.set({ [key]: value });
    }
  }
  
  // Load deny list
  await loadDenyList();
}

// Load and display deny list
async function loadDenyList() {
  try {
    const storage = await chrome.storage.local.get(['denyList']);
    const denyList = storage.denyList || ['https://www.google.com'];
    
    const denyListContainer = document.getElementById('denyListItems');
    if (!denyListContainer) return;
    
    if (denyList.length === 0) {
      denyListContainer.innerHTML = '<p class="no-items">No domains in deny list</p>';
      return;
    }
    
    const denyListHTML = denyList.map(domain => `
      <div class="deny-list-item">
        <div class="domain-info">
          <span class="domain-pattern">${escapeHtml(domain)}</span>
          <span class="domain-type">${domain.includes('*') ? 'Wildcard' : 'Exact'}</span>
        </div>
        <div class="domain-actions">
          <button class="btn-remove" onclick="removeFromDenyList('${escapeHtml(domain)}')" title="Remove from deny list">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
      </div>
    `).join('');
    
    denyListContainer.innerHTML = denyListHTML;
      } catch (error) {
      await debugLog('Error loading deny list:', error);
    }
}

// Add domain to deny list
async function addToDenyList(domain) {
  try {
    // Validate domain format
    if (!isValidDomain(domain)) {
      showNotification('Invalid domain format. Use: domain.com or *.domain.com', 'error');
      return false;
    }
    
    const storage = await chrome.storage.local.get(['denyList']);
    const denyList = storage.denyList || ['https://www.google.com'];
    
    // Check if domain already exists
    if (denyList.includes(domain)) {
      showNotification('Domain already in deny list', 'warning');
      return false;
    }
    
    // Add domain to list
    denyList.push(domain);
    await chrome.storage.local.set({ denyList: denyList });
    
    // Reload display
    await loadDenyList();
    
    showNotification(`Added ${domain} to deny list`, 'success');
    return true;
  } catch (error) {
    await debugLog('Error adding to deny list:', error);
    showNotification('Failed to add domain to deny list', 'error');
    return false;
  }
}

// Remove domain from deny list
async function removeFromDenyList(domain) {
  try {
    const storage = await chrome.storage.local.get(['denyList']);
    let denyList = storage.denyList || ['https://www.google.com'];
    
    // Remove domain from list
    denyList = denyList.filter(d => d !== domain);
    await chrome.storage.local.set({ denyList: denyList });
    
    // Reload display
    await loadDenyList();
    
    showNotification(`Removed ${domain} from deny list`, 'success');
  } catch (error) {
    await debugLog('Error removing from deny list:', error);
    showNotification('Failed to remove domain from deny list', 'error');
  }
}

// Clear all deny list
async function clearDenyList() {
  try {
    await chrome.storage.local.set({ denyList: [] });
    await loadDenyList();
    showNotification('Deny list cleared', 'success');
  } catch (error) {
    await debugLog('Error clearing deny list:', error);
    showNotification('Failed to clear deny list', 'error');
  }
}

// Validate domain format
function isValidDomain(domain) {
  // Remove protocol if present
  domain = domain.replace(/^https?:\/\//, '');
  
  // Check for wildcard pattern
  if (domain.includes('*')) {
    // Wildcard must be at the beginning and followed by a dot
    const wildcardPattern = /^\*\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return wildcardPattern.test(domain);
  }
  
  // Regular domain pattern
  const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainPattern.test(domain);
}

// Show notification
function showNotification(message, type = 'info') {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  
  // Add to page
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.parentNode.removeChild(notification);
    }
  }, 3000);
}

// Load findings for current tab
async function loadCurrentTabFindings() {
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
    
    const storage = await chrome.storage.local.get(['findings']);
    
    // Try to find findings by full URL first, then by origin
    let findings = [];
    if (storage.findings) {
      // First try exact URL match
      findings = storage.findings[tab.url] || [];
      
      // If no findings by URL, try by origin
      if (findings.length === 0) {
        findings = storage.findings[origin] || [];
      }
      
      // If still no findings, check all keys that contain the origin
      if (findings.length === 0) {
        for (const [key, keyFindings] of Object.entries(storage.findings)) {
          if (key.includes(origin) || key.startsWith('file://')) {
            findings = findings.concat(keyFindings);
          }
        }
      }
    }
    
    await debugLog(`Found ${findings.length} findings for ${origin}`);
    await debugLog(`Tab URL: ${tab.url}`);
    await debugLog(`Storage keys:`, Object.keys(storage.findings || {}));
    
    await displayFindings(findings, origin);
  } catch (error) {
    await debugLog('Error loading findings:', error);
    displayStatus('Error loading data', 'error');
  }
}

// Display findings in the popup
function displayFindings(findings, origin) {
  const findingsContainer = document.getElementById('findingsList');
  const statusElement = document.getElementById('status');
  
  if (!findingsContainer || !statusElement) {
    debugLog('Required elements not found');  
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
        <span class="confidence-badge">${Math.round(finding.confidence * 100)}%</span>
      </div>
      <div class="finding-details">
        <div class="finding-source">Source: <a href="#" class="source-link" data-url="${escapeHtml(finding.source)}">${escapeHtml(finding.source)}</a></div>
        <div class="finding-match">Match: <code>${escapeHtml(finding.displayValue || finding.match.substring(0, 50))}${!finding.displayValue && finding.match.length > 50 ? '...' : ''}</code></div>
        ${finding.context.surroundingText ? `<div class="finding-context">Context: ${escapeHtml(finding.context.surroundingText)}</div>` : ''}
        <div class="finding-time">Found: ${new Date(finding.timestamp).toLocaleString()}</div>
      </div>

    </div>
  `).join('');
  
  findingsContainer.innerHTML = filterHTML + findingsHTML;
  
  setupFilters();
}

// Get CSS class based on confidence level
function getConfidenceClass(confidence) {
  if (confidence >= 0.8) return 'high-confidence';
  if (confidence >= 0.5) return 'medium-confidence';
  return 'low-confidence';
}

// Display status message
function displayStatus(message, type = 'info') {
  const statusElement = document.getElementById('status');
  const findingsContainer = document.getElementById('findingsList');
  
  if (statusElement) {
    statusElement.textContent = message;
    statusElement.className = `status ${type}`;
  }
  
  if (findingsContainer) {
    findingsContainer.innerHTML = '';
  }
}

// Display error message (kept for backward compatibility)
function displayError(message) {
  displayStatus(message, 'error');
}

// Setup filters for findings
function setupFilters() {
  const textFilter = document.getElementById('findingsFilter');
  const confidenceFilter = document.getElementById('confidenceFilter');
  if (textFilter) {
    textFilter.addEventListener('input', applyFilters);
  }
  
  if (confidenceFilter) {
    confidenceFilter.addEventListener('change', applyFilters);
  }
}

// Apply filters to findings
function applyFilters() {
  const textFilter = document.getElementById('findingsFilter');
  const confidenceFilter = document.getElementById('confidenceFilter');
  
  const textValue = textFilter ? textFilter.value.toLowerCase() : '';
  const confidenceValue = confidenceFilter ? confidenceFilter.value : '';
  
  const findings = document.querySelectorAll('.finding-item');
  
  findings.forEach(finding => {
    let show = true;
    
    // Text filter
    if (textValue) {
      const text = finding.textContent.toLowerCase();
      if (!text.includes(textValue)) {
        show = false;
      }
    }
    
    // Confidence filter
    if (confidenceValue && show) {
      const confidence = parseInt(finding.dataset.confidence);
      switch (confidenceValue) {
        case 'high':
          show = confidence >= 80;
          break;
        case 'medium':
          show = confidence >= 50 && confidence < 80;
          break;
        case 'low':
          show = confidence >= 30 && confidence < 50;
          break;
      }
    }
    

    
    finding.style.display = show ? 'block' : 'none';
  });
  
  // Update status
  const visibleFindings = document.querySelectorAll('.finding-item[style*="block"], .finding-item:not([style*="none"])');
  const statusElement = document.getElementById('status');
  if (statusElement) {
    statusElement.textContent = `${visibleFindings.length} security issue(s) found`;
  }
}

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

// Toggle advanced settings
async function toggleAdvancedSettings() {
  try {
    const storage = await chrome.storage.local.get(['showAdvancedSettings']);
    const newState = !storage.showAdvancedSettings;
    
    await chrome.storage.local.set({ showAdvancedSettings: newState });
    
    // Show/hide advanced settings section
    const advancedSection = document.getElementById('advancedSettings');
    if (advancedSection) {
      advancedSection.style.display = newState ? 'block' : 'none';
    }
    
    // Update button text
    const button = document.getElementById('openSettings');
    if (button) {
      button.textContent = newState ? 'Hide Advanced' : 'Advanced';
    }
  } catch (error) {
    await debugLog('Error toggling advanced settings:', error);
  }
}

// Open dashboard in new tab
async function openDashboard() {
  try {
    const dashboardUrl = chrome.runtime.getURL('dashboard.html');
    await chrome.tabs.create({ url: dashboardUrl });
  } catch (error) {
    await debugLog('Error opening dashboard:', error);
    window.open(chrome.runtime.getURL('dashboard.html'), '_blank');
  }
}

// Update UI based on current settings
async function updateUI() {
  const storage = await chrome.storage.local.get([
    'enableNotifications', 'autoScan', 'scanExternalScripts', 
    'scanSourceMaps', 'scanSensitiveFiles', 'confidenceThreshold', 'dataRetentionDays',
    'showAdvancedSettings', 'debugMode', 'verboseScanning'
  ]);
  
  // Update toggles
  Object.entries(storage).forEach(([key, value]) => {
    const element = document.getElementById(key);
    if (element && typeof value === 'boolean') {
      element.checked = value;
    }
  });
  
  // Update confidence slider
  const confidenceSlider = document.getElementById('confidenceThreshold');
  const confidenceValue = document.getElementById('confidenceValue');
  if (confidenceSlider && confidenceValue) {
    confidenceSlider.value = storage.confidenceThreshold || 0.3;
    confidenceValue.textContent = `${Math.round((storage.confidenceThreshold || 0.3) * 100)}%`;
  }
  
  // Update retention slider
  const retentionSlider = document.getElementById('dataRetentionDays');
  const retentionValue = document.getElementById('retentionValue');
  if (retentionSlider && retentionValue) {
    retentionSlider.value = storage.dataRetentionDays || 7;
    retentionValue.textContent = `${storage.dataRetentionDays || 7} days`;
  }
  
  // Update advanced settings visibility
  const advancedSection = document.getElementById('advancedSettings');
  const advancedButton = document.getElementById('openSettings');
  if (advancedSection && advancedButton) {
    advancedSection.style.display = (storage.showAdvancedSettings ? 'block' : 'none');
    advancedButton.textContent = storage.showAdvancedSettings ? 'Hide Advanced' : 'Advanced';
  }
  
  // Test all settings functionality
  await testSettingsFunctionality();
}

// Test all settings functionality
async function testSettingsFunctionality() {
  try {
    await debugLog('Testing settings functionality...');
    
    // Test storage access
    const testData = { test: 'value', timestamp: Date.now() };
    await chrome.storage.local.set(testData);
    const retrieved = await chrome.storage.local.get(['test']);
    
    if (retrieved.test !== testData.test) {
      await debugLog('Storage test failed');
      showNotification('Storage test failed', 'error');
    } else {
      await debugLog('Storage test passed');
    }
    
    // Clean up test data
    await chrome.storage.local.remove(['test']);
    
    // Test current tab access
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      await debugLog('No active tab found - this is normal for new windows');
      return;
    }
    
    if (!tab.url || tab.url === 'about:blank' || tab.url === 'chrome://newtab/') {
      await debugLog('Tab not fully loaded yet - this is normal');
      return;
    }
    
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      await debugLog('Skipping tests for browser/system pages');
      return;
    }
    
    await debugLog('Tab access test passed');
    
    // Test scripting API (skip for restricted URLs)
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => 'test'
      });
      await debugLog('Scripting API test passed');
    } catch (error) {
      await debugLog('Scripting API test skipped - page not ready or restricted:', error.message);
    }
    
  } catch (error) {
    await debugLog('Settings functionality test failed:', error);
    showNotification('Settings test failed', 'error');
  }
}

// Force scan (bypass cache)
async function forceScan() {
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

// Trigger manual scan
async function triggerScan() {
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

// Clear findings for current tab
async function clearCurrentTabFindings() {
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
        if (key.includes(origin) || key.startsWith('file://')) {
          delete storage.findings[key];
          cleared = true;
        }
      }
      
      if (cleared) {
        await chrome.storage.local.set({ findings: storage.findings });
        
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

// Clear cache
async function clearCache() {
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

// Clear findings from denied domains
async function clearDeniedDomainFindings() {
  try {
    const storage = await chrome.storage.local.get(['findings', 'denyList']);
    const findings = storage.findings || {};
    const denyList = storage.denyList || ['*.google.com'];
    
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

// Helper function to check if origin is denied (copied from background.js)
async function isOriginDenied(url) {
  try {
    if (!url) return false;
    
    const storage = await chrome.storage.local.get(['denyList']);
    const denyList = storage.denyList || ['*.google.com'];
    
    // Extract domain from URL
    let domain;
    try {
      domain = new URL(url).hostname;
    } catch (error) {
      await debugLog('Invalid URL for deny list check:', url);
      return false;
    }
    
    // Check each deny list pattern
    for (const pattern of denyList) {
      if (matchesDenyPattern(domain, pattern)) {
        return true;
      }
    }
    
    return false;
  } catch (error) {
    await debugLog('Error checking origin deny list:', error);
    return false;
  }
}

// Helper function to match deny pattern (copied from background.js)
function matchesDenyPattern(domain, pattern) {
  // Remove protocol if present in pattern
  pattern = pattern.replace(/^https?:\/\//, '');
  
  // Handle wildcard patterns
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.substring(2); // Remove '*.'
    return domain === baseDomain || domain.endsWith('.' + baseDomain);
  }
  
  // Handle exact domain match
  return domain === pattern;
}

// Export findings to CSV
async function exportFindings() {
  try {
    const storage = await chrome.storage.local.get(['findings']);
    const findings = storage.findings || {};
    
    let csvContent = 'Origin,Type,Source,Match,Confidence,Timestamp\n';
    
    for (const [origin, originFindings] of Object.entries(findings)) {
      for (const finding of originFindings) {
        csvContent += `"${origin}","${finding.type}","${finding.source}","${finding.match}",${finding.confidence},${new Date(finding.timestamp).toISOString()}\n`;
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

// Utility functions
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}



// Global functions for inline event handlers
window.removeFromDenyList = removeFromDenyList;
