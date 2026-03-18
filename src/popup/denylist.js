// SecretRadar - Popup Denylist

import { debugLog, showNotification, isValidDomain, matchesDenyPattern, escapeHtml } from './ui.js';
import { loadCurrentTabFindings } from './findings.js';

// Load and display deny list
export async function loadDenyList() {
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
export async function addToDenyList(domain) {
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

    // Reload current tab findings to update UI
    await loadCurrentTabFindings();

    showNotification(`Added ${domain} to deny list`, 'success');
    return true;
  } catch (error) {
    await debugLog('Error adding to deny list:', error);
    showNotification('Failed to add domain to deny list', 'error');
    return false;
  }
}

// Remove domain from deny list
export async function removeFromDenyList(domain) {
  try {
    const storage = await chrome.storage.local.get(['denyList']);
    let denyList = storage.denyList || ['https://www.google.com'];

    // Remove domain from list
    denyList = denyList.filter(d => d !== domain);
    await chrome.storage.local.set({ denyList: denyList });

    // Reload display
    await loadDenyList();

    // Reload current tab findings to update UI
    await loadCurrentTabFindings();

    showNotification(`Removed ${domain} from deny list`, 'success');
  } catch (error) {
    await debugLog('Error removing from deny list:', error);
    showNotification('Failed to remove domain from deny list', 'error');
  }
}

// Clear all deny list
export async function clearDenyList() {
  try {
    await chrome.storage.local.set({ denyList: [] });
    await loadDenyList();

    // Reload current tab findings to update UI
    await loadCurrentTabFindings();

    showNotification('Deny list cleared', 'success');
  } catch (error) {
    await debugLog('Error clearing deny list:', error);
    showNotification('Failed to clear deny list', 'error');
  }
}

// Helper function to check if origin is denied (popup's copy)
export async function isOriginDenied(url) {
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
