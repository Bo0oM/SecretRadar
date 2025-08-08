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
      // Silent fallback if storage is not available
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

  // Enhanced page scanning with performance optimizations
  const scanPage = debounce(async function() {
    try {
      const settings = await chrome.storage.local.get(['autoScan', 'debugMode']);
      
      if (settings.debugMode) {
        await debugLog('Content script settings:', settings);
      }
      
      if (settings.autoScan === false) {
        if (settings.debugMode) {
          debugLog('Auto Scan disabled in content script, skipping scan');
        }
        return;
      }
      
      const pageContent = document.documentElement.innerHTML;
      const origin = window.location.origin;
      const parentUrl = window.location.href;
      const parentOrigin = window.location.origin;

      if (settings.debugMode) {
        debugLog('Starting page scan for:', origin);
      }

      // Send page content for analysis
      const pageResult = await chrome.runtime.sendMessage({
        pageBody: pageContent,
        origin: origin,
        parentUrl: parentUrl,
        parentOrigin: parentOrigin
      });
      
      if (settings.debugMode) {
        debugLog('Page scan result:', pageResult);
      }

      // Scan external scripts with improved performance
      await scanExternalScripts();
      
      // Scan for common sensitive files
      await scanSensitiveFiles();

    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        debugLog('Extension context invalidated, stopping page scan');
        return;
      }
      
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
          debugLog('Error scanning page:', error);
        }
      } catch (settingsError) {
        debugLog('Error scanning page:', error);
      }
    }
  }, 1000); // Debounce for 1 second

  // Scan external scripts with caching
  async function scanExternalScripts() {
    try {
      // Проверяем настройку scanExternalScripts
      const settings = await chrome.storage.local.get(['scanExternalScripts', 'debugMode']);
      if (settings.scanExternalScripts === false) {
        if (settings.debugMode) {
          debugLog('External scripts scanning disabled');
        }
        return;
      }
      
      const scripts = document.querySelectorAll('script[src]');
      const processedScripts = new Set();
      
      if (settings.debugMode) {
        debugLog(`Found ${scripts.length} external scripts to scan`);
      }
      
      for (const script of scripts) {
        let scriptSrc = script.src;
        
        // Normalize script URL
        if (scriptSrc.startsWith('//')) {
          scriptSrc = location.protocol + scriptSrc;
        }
        
        // Skip if already processed in this session
        if (processedScripts.has(scriptSrc)) {
          if (settings.debugMode) {
            debugLog(`Skipping already processed script: ${scriptSrc}`);
          }
          continue;
        }
        
        processedScripts.add(scriptSrc);
        
        try {
          const result = await chrome.runtime.sendMessage({
            scriptUrl: scriptSrc,
            parentUrl: window.location.href,
            parentOrigin: window.location.origin
          });
          
          if (settings.debugMode) {
            if (result && result.reason === 'csp_error') {
              debugLog(`CSP error for script: ${scriptSrc}`);
            } else if (result && result.reason === 'disabled') {
              debugLog(`Script scanning disabled for: ${scriptSrc}`);
            } else if (result && result.reason === 'cached') {
              debugLog(`Script already cached: ${scriptSrc}`);
            }
          }
        } catch (error) {
          // Handle extension context invalidated error
          if (error.message && error.message.includes('Extension context invalidated')) {
            if (settings.debugMode) {
              debugLog('Extension context invalidated, stopping script scan');
            }
            return; // Stop scanning scripts
          }
          
          if (settings.debugMode) {
            debugLog('Error scanning script:', scriptSrc, error);
          }
        }
      }
    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        debugLog('Extension context invalidated, stopping external scripts scan');
        return;
      }
      
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
          debugLog('Error in scanExternalScripts:', error);
        }
      } catch (settingsError) {
        debugLog('Error in scanExternalScripts:', error);
      }
    }
  }

  // Scan for sensitive files with improved patterns
  async function scanSensitiveFiles() {
    try {
      const settings = await chrome.storage.local.get(['scanSensitiveFiles', 'debugMode']);
      if (settings.scanSensitiveFiles === false) {
        if (settings.debugMode) {
          debugLog('Sensitive files scanning disabled');
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
        debugLog(`Scanning ${sensitiveFiles.length} sensitive files`);
      }

      for (const file of sensitiveFiles) {
        const fileUrl = baseUrl + file;
        
        try {
          const result = await chrome.runtime.sendMessage({
            envFile: fileUrl,
            parentUrl: window.location.href,
            parentOrigin: window.location.origin
          });
          
          if (settings.debugMode) {
            if (result && result.reason === 'csp_error') {
              debugLog(`CSP error for file: ${fileUrl}`);
            } else if (result && result.reason === 'disabled') {
              debugLog(`File scanning disabled for: ${fileUrl}`);
            }
          }
        } catch (error) {
          // Silently ignore 404 errors for missing files
          if (!error.message.includes('404')) {
            if (settings.debugMode) {
              debugLog('Error scanning file:', fileUrl, error);
            }
          }
        }
      }
    } catch (error) {
      // Handle extension context invalidated error
      if (error.message && error.message.includes('Extension context invalidated')) {
        debugLog('Extension context invalidated, stopping sensitive files scan');
        return;
      }
      
      try {
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
          debugLog('Error in scanSensitiveFiles:', error);
        }
      } catch (settingsError) {
        debugLog('Error in scanSensitiveFiles:', error);
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
      subtree: true,
      characterData: true
    });
  }

  // Initialize scanning
  function initialize() {
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
        debugLog('Extension context invalidated during initialization');
        return;
      }
      
      debugLog('Error initializing SecretRadar:', error);
    }
  }

  // Start the scanner
  initialize();

  // Export functions for potential external use
  window.secretRadar = {
    scanPage,
    scanExternalScripts,
    scanSensitiveFiles
  };

})();
