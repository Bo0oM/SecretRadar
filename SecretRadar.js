// SecretRadar - Content Script

(function() {
  'use strict';

  // Debug logging helper function
  async function debugLog(message, ...args) {
    try {
      const currentSettings = await chrome.storage.local.get(['debugMode']);
      if (currentSettings.debugMode) {
        console.log('[SecretRadar Debug]', message, ...args);
      }
      } catch (error) {
  }
  }

  // Performance optimization: Debounce function
  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  // Manual scan function (without debounce)
  async function manualScan() {
    let settings = {};
    try {
      settings = await chrome.storage.local.get(['debugMode']);

      if (settings.debugMode) {
        await debugLog('Manual scan triggered');
      }
      
      const pageContent = document.documentElement.innerHTML;
      const origin = window.location.origin;
      const parentUrl = window.location.href;
      const parentOrigin = window.location.origin;

      if (settings.debugMode) {
        await debugLog('Starting manual scan for:', origin);
      }

      // Send page content for analysis
      try {
        const pageResult = await chrome.runtime.sendMessage({
          pageBody: pageContent,
          origin: origin,
          parentUrl: parentUrl,
          parentOrigin: parentOrigin
        });

        if (settings.debugMode) {
          await debugLog('Manual scan result:', pageResult);
        }
      } catch (error) {
        await debugLog('Error sending page content:', error);
        throw error;
      }

      // Scan external scripts
      await scanExternalScripts();
      
      // Scan for source maps
      await scanSourceMaps();
      
      // Scan for common sensitive files
      await scanSensitiveFiles();

    } catch (error) {
      if (settings.debugMode) {
        await debugLog('Error in manual scan:', error);
      }
    }
  }

  // Enhanced page scanning with performance optimizations
  const scanPage = debounce(async function() {
    try {
      if (window.self !== window.top) return; // skip in iframes — pageBody handled by top frame
      const settings = await chrome.storage.local.get(['autoScan', 'debugMode']);
      
      if (settings.debugMode) {
        await debugLog('Content script settings:', settings);
      }
      
      if (settings.autoScan === false) {
        if (settings.debugMode) {
          await debugLog('Auto Scan disabled in content script, skipping scan');
        }
        return;
      }
      
      const pageContent = document.documentElement.innerHTML;
      const origin = window.location.origin;
      const parentUrl = window.location.href;
      const parentOrigin = window.location.origin;

      if (settings.debugMode) {
        await debugLog('Starting page scan for:', origin);
      }

      // Send page content for analysis
      try {
        const pageResult = await chrome.runtime.sendMessage({
          pageBody: pageContent,
          origin: origin,
          parentUrl: parentUrl,
          parentOrigin: parentOrigin
        });

        if (settings.debugMode) {
          await debugLog('Page scan result:', pageResult);
        }
      } catch (error) {
        await debugLog('Error sending page content:', error);
        throw error;
      }

      // Scan external scripts with improved performance
      await scanExternalScripts();
      
      // Scan for source maps
      await scanSourceMaps();
      
      // Scan for common sensitive files
      await scanSensitiveFiles();

    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        await debugLog('Extension context invalidated, stopping page scan');
        return;
      }
      
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
        await debugLog('Error scanning page:', error);
        }
      } catch (settingsError) {
        await debugLog('Error scanning page:', error);
      }
    }
  }, 1000); // Debounce for 1 second

  // Send one script URL to SW — used inside batched scanner
  async function sendScriptMessage(scriptSrc) {
    try {
      return await chrome.runtime.sendMessage({
        scriptUrl: scriptSrc,
        parentUrl: window.location.href,
        parentOrigin: window.location.origin
      });
    } catch (error) {
      if (error.message && error.message.includes('Extension context invalidated')) {
        throw error; // propagate to abort the batch loop
      }
      return null;
    }
  }

  // Scan external scripts — batched (5 parallel) to avoid sequential latency
  async function scanExternalScripts() {
    try {
      if (window.self !== window.top) return; // skip in iframes
      const settings = await chrome.storage.local.get(['scanExternalScripts', 'debugMode']);
      if (settings.scanExternalScripts === false) return;

      const scripts = document.querySelectorAll('script[src]');
      const seen = new Set();
      const urls = [];

      for (const script of scripts) {
        let src = script.src;
        if (src.startsWith('//')) src = location.protocol + src;
        if (!seen.has(src)) {
          seen.add(src);
          urls.push(src);
        }
      }

      if (settings.debugMode) {
        await debugLog(`Scanning ${urls.length} external scripts (batched)`);
      }

      // Process in batches of 5 — avoids sequential latency without WAF-triggering burst
      for (let i = 0; i < urls.length; i += 5) {
        const batch = urls.slice(i, i + 5);
        await Promise.allSettled(batch.map(src => sendScriptMessage(src)));
      }
    } catch (error) {
      if (error.message && error.message.includes('Extension context invalidated')) return;
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) await debugLog('Error in scanExternalScripts:', error);
      } catch (_) {}
    }
  }

  // Scan for source maps
  async function scanSourceMaps() {
    try {
      if (window.self !== window.top) return; // skip in iframes
      const settings = await chrome.storage.local.get(['scanSourceMaps', 'debugMode']);
      if (settings.scanSourceMaps === false) {
        if (settings.debugMode) {
          await debugLog('Source map scanning disabled');
        }
        return;
      }

      if (settings.debugMode) {
        await debugLog('Starting source map scan...');
      }

      // Find all script tags
      const scripts = document.querySelectorAll('script[src]');
      const sourceMapUrls = new Set();

      for (const script of scripts) {
        const scriptUrl = script.src;
        
        // Check if script has source map comment
        try {
          const response = await fetch(scriptUrl);
          const scriptContent = await response.text();
          
          // Look for source map comment
          const sourceMapMatch = scriptContent.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
          if (sourceMapMatch) {
            const sourceMapUrl = new URL(sourceMapMatch[1], scriptUrl).href;
            sourceMapUrls.add(sourceMapUrl);
            if (settings.debugMode) {
              await debugLog('Found source map:', sourceMapUrl);
            }
          }
        } catch (error) {
          if (settings.debugMode) {
            await debugLog('Error checking script for source map:', error);
          }
        }
      }

      // Note: probing common map paths with wildcard URLs is not feasible via fetch;
      // source maps are discovered only via sourceMappingURL comments in script content above.

      // Send source map URLs to background script
      if (sourceMapUrls.size > 0) {
        for (const mapUrl of sourceMapUrls) {
          try {
            await chrome.runtime.sendMessage({
              action: 'scanSourceMap',
              sourceMapUrl: mapUrl,
              parentUrl: window.location.href,
              parentOrigin: window.location.origin
            });
          } catch (error) {
            if (settings.debugMode) {
              await debugLog('Error sending source map URL:', error);
            }
          }
        }
      }

    } catch (error) {
      if (settings.debugMode) {
        await debugLog('Error in scanSourceMaps:', error);
      }
    }
  }

  // Scan for sensitive files with improved patterns
  async function scanSensitiveFiles() {
    try {
      if (window.self !== window.top) return; // skip in iframes
      const settings = await chrome.storage.local.get(['scanSensitiveFiles', 'debugMode']);
      if (settings.scanSensitiveFiles === false) {
        if (settings.debugMode) {
          await debugLog('Sensitive files scanning disabled');
        }
        return;
      }
      
      const baseUrl = window.location.origin + window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/'));
      const sensitiveFiles = [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/.env.test',
        '/config.json',
        '/config.js',
        '/secrets.json',
        '/credentials.json',
        '/.git/config',
        '/.gitignore',
        '/package.json',
        '/composer.json',
        '/requirements.txt',
        '/Gemfile',
        '/Cargo.toml',
        '/go.mod',
        '/pom.xml',
        '/build.gradle',
        '/docker-compose.yml',
        '/Dockerfile',
        '/.dockerignore'
      ];

      if (settings.debugMode) {
        await debugLog(`Scanning ${sensitiveFiles.length} sensitive files (batched)`);
      }

      const fileUrls = sensitiveFiles.map(f => baseUrl + f);

      // Process in batches of 5 — ~5x faster than sequential on typical latency
      for (let i = 0; i < fileUrls.length; i += 5) {
        const batch = fileUrls.slice(i, i + 5);
        await Promise.allSettled(batch.map(fileUrl =>
          chrome.runtime.sendMessage({
            envFile: fileUrl,
            parentUrl: window.location.href,
            parentOrigin: window.location.origin
          }).catch(() => null)
        ));
      }
    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        await debugLog('Extension context invalidated, stopping sensitive files scan');
        return;
      }
      
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
          await debugLog('Error in scanSensitiveFiles:', error);
        }
      } catch (settingsError) {
        await debugLog('Error in scanSensitiveFiles:', error);
      }
    }
  }

  // Enhanced DOM monitoring for dynamic content
  function setupDOMMonitoring() {
    // Monitor for new script tags
    const scriptObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.tagName === 'SCRIPT' && node.src) {
            // Debounce script scanning
            setTimeout(() => scanExternalScripts(), 500);
          }
        }
      }
    });

    scriptObserver.observe(document.head, {
      childList: true,
      subtree: true
    });

    // Monitor for AJAX content changes
    let lastContentLength = document.documentElement.innerHTML.length;
    const contentObserver = new MutationObserver(() => {
      const currentLength = document.documentElement.innerHTML.length;
      if (Math.abs(currentLength - lastContentLength) > 1000) {
        lastContentLength = currentLength;
        scanPage();
      }
    });

    contentObserver.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // Initialize scanning
  async function initialize() {
    try {
      // Wait for DOM to be ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          setTimeout(scanPage, 1000); // Delay initial scan
          setupDOMMonitoring();
        });
      } else {
        setTimeout(scanPage, 1000); // Delay initial scan
        setupDOMMonitoring();
      }

      // Re-scan on navigation (for SPA)
      let lastUrl = location.href;
      new MutationObserver(() => {
        const url = location.href;
        if (url !== lastUrl) {
          lastUrl = url;
          setTimeout(scanPage, 1000);
        }
      }).observe(document, { subtree: true, childList: true });
    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        await debugLog('Extension context invalidated during initialization');
        return;
      }
      
      await debugLog('Error initializing SecretRadar:', error);
    }
  }

  // Start the scanner
  initialize().catch(error => {
    console.error('Failed to initialize SecretRadar:', error);
  });

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'manualScan') {
      manualScan().then(() => {
        sendResponse({ success: true });
      }).catch(error => {
        sendResponse({ success: false, error: error.message });
      });
      return true; // Keep message channel open
    }
  });

})();
