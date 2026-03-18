// SecretRadar - Popup UI Utilities

// Debug logging helper function
export async function debugLog(message, ...args) {
  try {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings.debugMode) {
      console.log('[SecretRadar Debug]', message, ...args);
    }
  } catch (error) {
  }
}

// Show notification
export function showNotification(message, type = 'info') {
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

// Display status message
export function displayStatus(message, type = 'info') {
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
export function displayError(message) {
  displayStatus(message, 'error');
}

// Escape HTML to prevent XSS
export function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Get CSS class based on confidence level
export function getConfidenceClass(confidence) {
  if (confidence >= 0.8) return 'high-confidence';
  if (confidence >= 0.5) return 'medium-confidence';
  return 'low-confidence';
}

// Validate domain format
export function isValidDomain(domain) {
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

// Helper function to match deny pattern (copied from background.js)
export function matchesDenyPattern(domain, pattern) {
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

// Setup filters for findings
export function setupFilters() {
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
export function applyFilters() {
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
