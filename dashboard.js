// SecretRadar Dashboard - JavaScript

// Debug logging helper function
async function debugLog(message, ...args) {
  try {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings.debugMode) {
      console.log(message, ...args);
    }
  } catch (error) {
    
  }
}

document.addEventListener('DOMContentLoaded', async function() {
  // Initialize dashboard
  await initializeDashboard();
  
  // Setup event listeners
  setupEventListeners();
  
  // Load initial data
  await loadDashboardData();
});

// Dashboard state
let dashboardState = {
  findings: [],
  filteredFindings: [],
  currentPage: 1,
  itemsPerPage: 20,
  filters: {
    site: '',
    type: '',
    confidence: '',
    dateRange: ''
  },
  sortBy: 'timestamp',
  viewMode: 'compact'
};

// Initialize dashboard
async function initializeDashboard() {
  try {
    // Load settings
    const storage = await chrome.storage.local.get(['findings']);
    const allFindings = storage.findings || {};
    
    // Flatten findings from all origins
    dashboardState.findings = [];
    for (const [origin, originFindings] of Object.entries(allFindings)) {
      for (const finding of originFindings) {
        dashboardState.findings.push({
          ...finding,
          origin: origin
        });
      }
    }
    
    // Sort by timestamp (newest first)
    dashboardState.findings.sort((a, b) => b.timestamp - a.timestamp);
    
    // Apply initial filters
    applyFilters();
    
  } catch (error) {
    await debugLog('Error initializing dashboard:', error);
    showError('Failed to load dashboard data');
  }
}

// Setup event listeners
function setupEventListeners() {
  // Filter controls
  const filterSelects = ['siteFilter', 'confidenceFilter', 'dateFilter'];
  filterSelects.forEach(filterId => {
    const element = document.getElementById(filterId);
    if (element) {
      element.addEventListener('change', async (e) => {
        dashboardState.filters[filterId.replace('Filter', '')] = e.target.value;
        dashboardState.currentPage = 1;
        await applyFilters();
        updateFindingsDisplay();
      });
    }
  });
  
  // Sort control
  const sortSelect = document.getElementById('sortBy');
  if (sortSelect) {
    sortSelect.addEventListener('change', async (e) => {
      dashboardState.sortBy = e.target.value;
      await applyFilters();
      updateFindingsDisplay();
    });
  }
  
  // View mode controls
  const viewButtons = ['viewCompact', 'viewDetailed'];
  viewButtons.forEach(buttonId => {
    const button = document.getElementById(buttonId);
    if (button) {
      button.addEventListener('click', (e) => {
        // Update active state
        document.querySelectorAll('.view-controls .btn').forEach(btn => {
          btn.classList.remove('active');
        });
        e.target.classList.add('active');
        
        // Update view mode
        dashboardState.viewMode = buttonId.replace('view', '').toLowerCase();
        updateFindingsDisplay();
      });
    }
  });
  
  // Pagination controls
  const prevButton = document.getElementById('prevPage');
  const nextButton = document.getElementById('nextPage');
  
  if (prevButton) {
    prevButton.addEventListener('click', () => {
      if (dashboardState.currentPage > 1) {
        dashboardState.currentPage--;
        updateFindingsDisplay();
      }
    });
  }
  
  if (nextButton) {
    nextButton.addEventListener('click', () => {
      const totalPages = Math.ceil(dashboardState.filteredFindings.length / dashboardState.itemsPerPage);
      if (dashboardState.currentPage < totalPages) {
        dashboardState.currentPage++;
        updateFindingsDisplay();
      }
    });
  }
  
  // Action buttons
  const refreshButton = document.getElementById('refreshData');
  if (refreshButton) {
    refreshButton.addEventListener('click', async () => {
      await loadDashboardData();
    });
  }
  
  const exportButton = document.getElementById('exportAll');
  if (exportButton) {
    exportButton.addEventListener('click', async () => {
      await exportAllFindings();
    });
  }
  
  const clearButton = document.getElementById('clearAll');
  if (clearButton) {
    clearButton.addEventListener('click', async () => {
      if (confirm('Are you sure you want to clear all findings? This action cannot be undone.')) {
        await clearAllFindings();
      }
    });
  }
  
  const clearFiltersButton = document.getElementById('clearFilters');
  if (clearFiltersButton) {
    clearFiltersButton.addEventListener('click', async () => {
      clearFilters();
      await applyFilters();
      updateFindingsDisplay();
    });
  }
  
  // Source link click handler (delegated event)
  document.addEventListener('click', async (event) => {
    const target = event.target;
    if (target.classList.contains('source-link')) {
      event.preventDefault();
      const url = target.getAttribute('data-url');
      
      try {
        if (url.startsWith('file://')) {
          // For file URLs, try to show in notification
          chrome.tabs.create({ url: 'chrome://downloads/' }).then(() => {
            showNotification('File URL: ' + url, 'info');
          }).catch(() => {
            showNotification('File URL: ' + url, 'info');
          });
        } else {
          // For web URLs, open in new tab
          chrome.tabs.create({ url: url });
        }
      } catch (error) {
        await debugLog('Error opening URL:', error);
        showNotification('Error opening URL', 'error');
      }
    }
  });
}

// Load dashboard data
async function loadDashboardData() {
  try {
    await initializeDashboard();
    updateStats();
    updateFilters();
    updateFindingsDisplay();
    updateCharts();
  } catch (error) {
    await debugLog('Error loading dashboard data:', error);
    showError('Failed to load dashboard data');
  }
}

// Apply filters to findings
function applyFilters() {
  let filtered = [...dashboardState.findings];
  
  // Apply site filter
  if (dashboardState.filters.site) {
    filtered = filtered.filter(finding => 
      finding.origin.includes(dashboardState.filters.site)
    );
  }
  


  // Apply confidence filter
  if (dashboardState.filters.confidence) {
    filtered = filtered.filter(finding => {
      const confidence = finding.confidence;
      switch (dashboardState.filters.confidence) {
        case 'high':
          return confidence >= 0.8;
        case 'medium':
          return confidence >= 0.5 && confidence < 0.8;
        case 'low':
          return confidence < 0.5;
        default:
          return true;
      }
    });
  }
  
  // Apply date filter
  if (dashboardState.filters.dateRange) {
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    const oneWeek = 7 * oneDay;
    const oneMonth = 30 * oneDay;
    
    filtered = filtered.filter(finding => {
      const findingDate = finding.timestamp;
      switch (dashboardState.filters.dateRange) {
        case 'today':
          return (now - findingDate) <= oneDay;
        case 'week':
          return (now - findingDate) <= oneWeek;
        case 'month':
          return (now - findingDate) <= oneMonth;
        default:
          return true;
      }
    });
  }
  
  // Apply sorting
  filtered.sort((a, b) => {
    switch (dashboardState.sortBy) {
      case 'timestamp':
        return b.timestamp - a.timestamp;
      case 'timestamp-asc':
        return a.timestamp - b.timestamp;
      case 'confidence':
        return b.confidence - a.confidence;
      case 'confidence-asc':
        return a.confidence - b.confidence;
      case 'origin':
        return a.origin.localeCompare(b.origin);
      default:
        return b.timestamp - a.timestamp;
    }
  });
  
  dashboardState.filteredFindings = filtered;
}

// Update statistics
function updateStats() {
  const totalFindings = dashboardState.findings.length;
  const totalSites = new Set(dashboardState.findings.map(f => f.origin)).size;
  const highConfidence = dashboardState.findings.filter(f => f.confidence >= 0.8).length;
  
  // Calculate recent findings (last 24 hours)
  const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
  const recentFindings = dashboardState.findings.filter(f => f.timestamp >= oneDayAgo).length;
  
  // Update stats display
  document.getElementById('totalFindings').textContent = totalFindings;
  document.getElementById('totalSites').textContent = totalSites;
  document.getElementById('highConfidence').textContent = highConfidence;
  document.getElementById('recentFindings').textContent = recentFindings;
}

// Update filters dropdowns
function updateFilters() {
  // Get unique sites
  const sites = [...new Set(dashboardState.findings.map(f => f.origin))].sort();
  const siteFilter = document.getElementById('siteFilter');
  if (siteFilter) {
    siteFilter.innerHTML = '<option value="">All Sites</option>' +
      sites.map(site => `<option value="${escapeHtml(site)}">${escapeHtml(site)}</option>`).join('');
  }
  

}

// Update findings display
function updateFindingsDisplay() {
  const findingsList = document.getElementById('findingsList');
  if (!findingsList) return;
  
  const startIndex = (dashboardState.currentPage - 1) * dashboardState.itemsPerPage;
  const endIndex = startIndex + dashboardState.itemsPerPage;
  const pageFindings = dashboardState.filteredFindings.slice(startIndex, endIndex);
  
  // Update counts
  document.getElementById('showingCount').textContent = pageFindings.length;
  document.getElementById('totalCount').textContent = dashboardState.filteredFindings.length;
  
  // Update pagination
  const totalPages = Math.ceil(dashboardState.filteredFindings.length / dashboardState.itemsPerPage);
  document.getElementById('currentPage').textContent = dashboardState.currentPage;
  document.getElementById('totalPages').textContent = totalPages;
  
  document.getElementById('prevPage').disabled = dashboardState.currentPage <= 1;
  document.getElementById('nextPage').disabled = dashboardState.currentPage >= totalPages;
  
  // Display findings
  if (pageFindings.length === 0) {
    findingsList.innerHTML = '<p class="no-findings">No findings match the current filters</p>';
    return;
  }
  
  const findingsHTML = pageFindings.map(finding => 
    dashboardState.viewMode === 'detailed' ? 
      createDetailedFindingHTML(finding) : 
      createCompactFindingHTML(finding)
  ).join('');
  
  findingsList.innerHTML = findingsHTML;
}

// Create compact finding HTML
function createCompactFindingHTML(finding) {
  const confidenceClass = getConfidenceClass(finding.confidence);
  const confidencePercent = Math.round(finding.confidence * 100);
  
  return `
    <div class="finding-item ${confidenceClass}">
      <div class="finding-header">
        <span class="finding-type">${escapeHtml(finding.type)}</span>
        <span class="confidence-badge">${confidencePercent}%</span>
      </div>
      <div class="finding-details">
        <div class="finding-source">${escapeHtml(finding.origin)} • <a href="#" class="source-link" data-url="${escapeHtml(finding.source)}">${escapeHtml(finding.source)}</a></div>
        <div class="finding-match">${escapeHtml(finding.match.substring(0, 100))}${finding.match.length > 100 ? '...' : ''}</div>
        <div class="finding-time">${new Date(finding.timestamp).toLocaleString()}</div>
      </div>
    </div>
  `;
}

// Create detailed finding HTML
function createDetailedFindingHTML(finding) {
  const confidenceClass = getConfidenceClass(finding.confidence);
  const confidencePercent = Math.round(finding.confidence * 100);
  
  return `
    <div class="finding-item ${confidenceClass}">
      <div class="finding-header">
        <span class="finding-type">${escapeHtml(finding.type)}</span>
        <span class="confidence-badge">${confidencePercent}%</span>
      </div>
      <div class="finding-details">
        <div class="finding-source">Site: <a href="#" class="source-link" data-url="${escapeHtml(finding.origin)}">${escapeHtml(finding.origin)}</a></div>
        <div class="finding-source">Source: <a href="#" class="source-link" data-url="${escapeHtml(finding.source)}">${escapeHtml(finding.source)}</a></div>
        <div class="finding-match">Match: <code>${escapeHtml(finding.match)}</code></div>
        ${finding.context.surroundingText ? `<div class="finding-context">Context: ${escapeHtml(finding.context.surroundingText)}</div>` : ''}
        <div class="finding-time">Found: ${new Date(finding.timestamp).toLocaleString()}</div>
      </div>

    </div>
  `;
}

// Get confidence class
function getConfidenceClass(confidence) {
  if (confidence >= 0.8) return 'high-confidence';
  if (confidence >= 0.5) return 'medium-confidence';
  return 'low-confidence';
}

// Clear filters
function clearFilters() {
  dashboardState.filters = {
    site: '',
    type: '',
    confidence: '',
    dateRange: ''
  };
  
  // Reset filter dropdowns
  const filterSelects = ['siteFilter', 'confidenceFilter', 'dateFilter'];
  filterSelects.forEach(filterId => {
    const element = document.getElementById(filterId);
    if (element) {
      element.value = '';
    }
  });
}

// Update charts
async function updateCharts() {
  // Charts removed due to CSP restrictions
  await debugLog('Charts disabled due to Content Security Policy');
}

// Export all findings
async function exportAllFindings() {
  try {
    let csvContent = 'Origin,Type,Source,Match,Confidence,Timestamp,Context\n';
    
    for (const finding of dashboardState.findings) {
      const context = finding.context.surroundingText || '';
      csvContent += `"${finding.origin}","${finding.type}","${finding.source}","${finding.match}",${finding.confidence},${new Date(finding.timestamp).toISOString()},"${context}"\n`;
    }
    
    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secretradar-all-findings-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    
    showNotification('Export completed successfully', 'success');
  } catch (error) {
    await debugLog('Error exporting findings:', error);
    showNotification('Export failed', 'error');
  }
}

// Clear all findings
async function clearAllFindings() {
  try {
    await chrome.storage.local.set({ findings: {} });
    await loadDashboardData();
    showNotification('All findings cleared', 'success');
  } catch (error) {
    await debugLog('Error clearing findings:', error);
    showNotification('Failed to clear findings', 'error');
  }
}

// Utility functions
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}


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

function showError(message) {
  showNotification(message, 'error');
}


