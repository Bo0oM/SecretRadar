// SecretRadar - Background Service Worker (Entry Point)

import { processedUrls, newFindings, CACHE_DURATION } from './src/background/state.js';
import { cleanupOldFindings, clearCache, clearNewFindingsForOrigin } from './src/background/storage.js';
import { clearNotificationQueue, notifiedOrigins, updateBadge, notificationOrigins } from './src/background/notifications.js';
import { handleMessage, scanSourceMap } from './src/background/scanner.js';
import { debugLog } from './src/background/utils.js';
import { isOriginDenied } from './src/background/denylist.js';

// Clear old cache entries on startup
const now = Date.now();
for (const [key, timestamp] of processedUrls.entries()) {
  if (now - timestamp > CACHE_DURATION) {
    processedUrls.delete(key);
  }
}

// Cleanup on extension unload
chrome.runtime.onSuspend.addListener(() => {
  clearNotificationQueue();
});

// Reset notification tracking on extension startup
chrome.runtime.onStartup.addListener(() => {
  notifiedOrigins.clear();
});

// Handle notification click — focus the tab where secrets were found
chrome.notifications.onClicked.addListener(async (notificationId) => {
  try {
    chrome.notifications.clear(notificationId);
    const origin = notificationOrigins.get(notificationId);
    notificationOrigins.delete(notificationId);
    if (!origin) return;

    // Find a tab with this origin and activate it
    const tabs = await chrome.tabs.query({});
    const target = tabs.find(t => {
      try { return new URL(t.url).origin === origin; } catch { return false; }
    });
    if (target) {
      await chrome.tabs.update(target.id, { active: true });
      await chrome.windows.update(target.windowId, { focused: true });
    }
  } catch (error) {
    await debugLog('Error handling notification click:', error);
  }
});

// Handle extension icon click to clear new findings for current tab
chrome.action.onClicked.addListener(async (tab) => {
  try {
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      return;
    }

    const origin = new URL(tab.url).origin;
    clearNewFindingsForOrigin(origin);
    await updateBadge(origin);

    await debugLog(`Cleared new findings for ${origin} on icon click`);
  } catch (error) {
    await debugLog('Error handling icon click:', error);
  }
});

// Message handler for content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Handle popup opened - clear new findings and reset notification throttle
  if (request.action === 'popupOpened') {
    newFindings.clear();
    notifiedOrigins.clear();
    sendResponse({ success: true, message: 'New findings cleared' });
    return true;
  }

  // Handle source map scan request
  if (request.action === 'scanSourceMap') {
    (async () => {
      try {
        await scanSourceMap(request.sourceMapUrl, request.parentUrl, request.parentOrigin);
        sendResponse({ success: true, message: 'Source map scanned' });
      } catch (error) {
        await debugLog('Source map scan error:', error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true;
  }

  // Handle manual scan request from popup
  if (request.action === 'manualScan') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
          sendResponse({ success: false, error: 'No active tab found' });
          return;
        }
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
          sendResponse({ success: false, error: 'Cannot scan browser pages' });
          return;
        }

        // Clear cache for current origin — ensures external scripts are re-fetched
        // (processedUrls keys are scriptUrls and page origins, filter by current origin)
        let origin;
        try {
          origin = new URL(tab.url).origin;
          notifiedOrigins.delete(origin);
        } catch (e) { /* ignore invalid URLs */ }
        for (const key of processedUrls.keys()) {
          if (key === tab.url || (origin && key.includes(origin))) {
            processedUrls.delete(key);
          }
        }

        // Send message to already-loaded content script
        try {
          await chrome.tabs.sendMessage(tab.id, { action: 'manualScan' });
          sendResponse({ success: true, message: 'Manual scan triggered' });
        } catch (msgError) {
          // Content script not reachable (page opened before extension loaded)
          sendResponse({ success: false, error: 'reload_required' });
        }
      } catch (error) {
        await debugLog('Manual scan error:', error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true; // Keep message channel open for async response
  }

  // Handle clear cache request from popup
  if (request.action === 'clearCache') {

    try {
      clearCache();
      sendResponse({ success: true, message: 'Cache cleared' });
    } catch (error) {
      sendResponse({ success: false, error: error.message });
    }

    return true;
  }

  // Handle content script messages
  if (request.scriptUrl || request.pageBody) {
    // Handle message asynchronously
    handleMessage(request, sender).then(result => {
      sendResponse(result);
    }).catch(error => {
      debugLog('handleMessage failed with error:', error);
      sendResponse({ success: false, error: error.message });
    });

    return true; // Keep message channel open for async response
  }

  sendResponse({ success: false, error: 'Unknown message type' });
  return true;
});

// Tab activation handler
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);

    await debugLog(`Tab activated: ${tab?.url || 'no URL'}`);

    // Handle cases where tab is not available
    if (!tab) {
      // Clear badge for unavailable tabs
      await chrome.action.setBadgeText({ text: '' });
      return;
    }

    // Handle cases where URL is not available or page is not loaded
    if (!tab.url || tab.url === 'about:blank' || tab.url === 'chrome://newtab/') {
      // Clear badge for empty pages
      await chrome.action.setBadgeText({ text: '' });
      return;
    }

    // Handle browser/system pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      // Clear badge for browser pages
      await chrome.action.setBadgeText({ text: '' });
      return;
    }

    // Handle file:// URLs
    if (tab.url.startsWith('file://')) {
      try {
        const origin = new URL(tab.url).origin;
        await updateBadge(origin);
      } catch (urlError) {
        await debugLog('Invalid file URL in tab activation:', tab.url);
        await chrome.action.setBadgeText({ text: '' });
      }
      return;
    }

    // Handle invalid URLs
    try {
      const origin = new URL(tab.url).origin;

      // Check if origin is denied
      const isDenied = await isOriginDenied(tab.url);
      if (isDenied) {
        // Clear badge for denied origins
        await chrome.action.setBadgeText({ text: '' });
        await chrome.action.setBadgeBackgroundColor({ color: '#6c757d' });
        return;
      }

      // Clear new findings for this origin when switching tabs
      clearNewFindingsForOrigin(origin);

      await updateBadge(origin);
    } catch (urlError) {
      await debugLog('Invalid URL in tab activation:', tab.url);
      // Clear badge for invalid URLs
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch (error) {
    await debugLog('Error updating badge on tab activation (normal for loading pages):', error.message);
    // Clear badge on error
    await chrome.action.setBadgeText({ text: '' });
  }
});

// Function to scan page content (injected via scripting API to bypass CSP)
async function scanPageContent() {
  try {
    // Schedule the heavy scanning task when browser is idle
    scheduleScan(async () => {
      // Get page content
      const pageContent = document.documentElement.innerHTML;
      const origin = window.location.origin;
      const parentUrl = window.location.href;
      const parentOrigin = window.location.origin;

      // For file:// URLs, use a special origin
      const effectiveOrigin = origin === 'null' ? 'file://' : origin;

      await debugLog('scanPageContent: Page content length:', pageContent.length);
      await debugLog('scanPageContent: Origin:', origin);
      await debugLog('scanPageContent: Effective origin:', effectiveOrigin);
      await debugLog('scanPageContent: Parent URL:', parentUrl);

      // Send message to background script
      chrome.runtime.sendMessage({
        pageBody: pageContent,
        origin: effectiveOrigin,
        parentUrl: parentUrl,
        parentOrigin: parentOrigin,
        source: 'scripting-injection'
      });

      await debugLog('Page scanned via scripting injection (CSP bypass)');
    });
  } catch (error) {
    await debugLog('Error in page scan via injection:', error.message);
  }
}

// Schedule heavy tasks when browser is idle
function scheduleScan(func) {
  if ('requestIdleCallback' in self) {
    requestIdleCallback(func);
  } else {
    setTimeout(func, 200); // Fallback for older browsers
  }
}

// Tab update handler for CSP bypass
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  try {
    // Only process when page is fully loaded
    if (changeInfo.status !== 'complete') return;

    // Skip browser/system pages
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      return;
    }

    // Skip empty pages
    if (tab.url === 'about:blank' || tab.url === 'chrome://newtab/') {
      return;
    }

    // Special handling for file:// URLs
    if (tab.url.startsWith('file://')) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tabId },
          function: scanPageContent
        });
        await debugLog('File URL scanned via scripting injection');
      } catch (scriptError) {
        await debugLog('File URL script injection failed:', scriptError.message);
      }
      return;
    }

    // Inject script to bypass CSP for web URLs
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        function: scanPageContent
      });

      // Update badge after page scan
      try {
        const origin = new URL(tab.url).origin;

        // Check if origin is denied
        const isDenied = await isOriginDenied(tab.url);
        if (isDenied) {
          // Clear badge for denied origins
          await chrome.action.setBadgeText({ text: '' });
          await chrome.action.setBadgeBackgroundColor({ color: '#6c757d' });
        } else {
          await updateBadge(origin);
        }
      } catch (urlError) {
        await debugLog('Error updating badge after page scan:', urlError.message);
      }
    } catch (scriptError) {
      await debugLog('Script injection failed (CSP restriction):', scriptError.message);
    }
  } catch (error) {
    await debugLog('Error in tab update handler:', error.message);
  }
});

// Initialize extension with cleanup
chrome.runtime.onInstalled.addListener(async () => {
  const defaults = {
    enableNotifications: true,
    confidenceThreshold: 0.3,
    autoScan: true,
    scanExternalScripts: true,
    scanSensitiveFiles: false,
    denyList: ['*.google.com'],
    dataRetentionDays: 7,
    showAdvancedSettings: false,
    debugMode: false,
    verboseScanning: false
  };

  await chrome.storage.local.set(defaults);

  // Initial cleanup
  await cleanupOldFindings();

  // Set up periodic cleanup via alarms (survives SW suspension)
  chrome.alarms.create('cleanupOldFindings', { periodInMinutes: 1440 });

  await debugLog('SecretRadar initialized');
});

// Periodic cleanup via alarms (replaces setInterval — survives SW suspension)
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'cleanupOldFindings') {
    await cleanupOldFindings();
  }
});

// Listen for storage changes to clean up findings when denyList is updated
chrome.storage.onChanged.addListener(async (changes, namespace) => {
  if (namespace === 'local' && changes.denyList) {
    await debugLog('Deny list updated, cleaning up findings from denied domains...');
    await cleanupOldFindings();
  }
});
