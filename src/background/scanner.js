// SecretRadar - Scanner (Background)

import { debugLog } from './utils.js';
import { isOriginDenied } from './denylist.js';
import { detectSecrets } from './detector.js';
import { processedUrls, CACHE_DURATION, storeFindings } from './storage.js';
import { updateBadge, queueNotification } from './notifications.js';

// Optimized data checking with caching
export async function checkData(data, src, parentUrl, parentOrigin) {

  try {
    const settings = await chrome.storage.local.get(['autoScan', 'confidenceThreshold', 'debugMode']);

    if (settings.debugMode) {
      await debugLog('Current settings:', settings);
    }

    if (settings.autoScan === false) {
      if (settings.debugMode) {
        await debugLog('Auto Scan disabled, skipping scan');
      }
      return;
    }

    // Skip if already processed (with cache expiration)
    // Use different cache keys for scripts vs page content
    const isScript = src.startsWith('http');
    const cacheKey = isScript ? src : `${src}-${parentOrigin}`;
    const now = Date.now();
    const cachedTime = processedUrls.get(cacheKey);

    // Allow force rescan for file:// URLs (local files)
    const isLocalFile = src.startsWith('file://');
    const shouldSkipCache = isLocalFile && settings.debugMode;

    if (cachedTime && (now - cachedTime) < CACHE_DURATION && !shouldSkipCache) {
      if (settings.debugMode) {
        await debugLog('Already processed (cached):', cacheKey);
      }
      return;
    }

    // Clean up old cache entries periodically
    if (processedUrls.size > 100) { // Only cleanup when cache gets large
      let cleanedCount = 0;
      for (const [key, timestamp] of processedUrls.entries()) {
        if (now - timestamp > CACHE_DURATION) {
          processedUrls.delete(key);
          cleanedCount++;
        }
      }
      if (settings.debugMode && cleanedCount > 0) {
        await debugLog(`Cache cleanup completed, removed: ${cleanedCount} entries`);
      }
    }

    processedUrls.set(cacheKey, now);

    const findings = await detectSecrets(data, src, parentUrl, parentOrigin);

    // Store all findings — threshold filtering happens in popup UI, not here
    // This ensures lowering sensitivity later reveals previously-scanned data
    if (settings.debugMode) {
      await debugLog(`Found ${findings.length} potential secrets`);
    }

    if (findings.length > 0) {
      await storeFindings(findings, parentOrigin);
      await updateBadge(parentOrigin);

      // Notify for high-confidence findings
      const highConfidence = findings.filter(f => f.confidence >= 0.7);
      if (highConfidence.length > 0) {
        await queueNotification(highConfidence[0]);
      }
    }
  } catch (error) {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings.debugMode) {
      console.error('Error in checkData:', error);
    }
  }
}

// Parse and analyze source map
export async function scanSourceMap(sourceMapUrl, parentUrl, parentOrigin) {
  try {
    const settings = await chrome.storage.local.get(['debugMode']);

    if (settings.debugMode) {
      await debugLog('Fetching source map:', sourceMapUrl);
    }

    // Fetch source map
    const response = await fetch(sourceMapUrl, {
      credentials: 'include',
      cache: 'force-cache'
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch source map: ${response.status}`);
    }

    const sourceMapData = await response.json();

    if (settings.debugMode) {
      await debugLog('Source map fetched, parsing...');
    }

    // Extract source files from source map
    const sourceFiles = sourceMapData.sources || [];
    const sourceContents = sourceMapData.sourcesContent || [];

    if (settings.debugMode) {
      await debugLog(`Found ${sourceFiles.length} source files in source map`);
    }

    // Analyze each source file
    for (let i = 0; i < sourceFiles.length; i++) {
      const sourceFile = sourceFiles[i];
      const sourceContent = sourceContents[i];

      if (!sourceContent) {
        if (settings.debugMode) {
          await debugLog('Skipping source file without content:', sourceFile);
        }
        continue;
      }

      if (settings.debugMode) {
        await debugLog(`Analyzing source file: ${sourceFile} (${sourceContent.length} chars)`);
      }

      // Detect secrets in source content
      const findings = await detectSecrets(
        sourceContent,
        `source-map:${sourceFile}`,
        parentUrl,
        parentOrigin
      );

      if (findings.length > 0) {
        if (settings.debugMode) {
          await debugLog(`Found ${findings.length} secrets in source file: ${sourceFile}`);
        }

        // Store findings
        await storeFindings(findings, parentOrigin);

        // Update badge
        await updateBadge(parentOrigin);
      }
    }

    if (settings.debugMode) {
      await debugLog('Source map analysis completed');
    }

  } catch (error) {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings && settings.debugMode) {
      await debugLog('Error scanning source map:', error);
    }
    throw error;
  }
}

export async function handleMessage(request, sender) {
  try {
    const url = request.origin || request.scriptUrl;
    const isDenied = await isOriginDenied(url);
    if (isDenied) {
      return { success: false, reason: 'denied' };
    }

    if (request.pageBody) {
      // Handle scripting injection messages
      const source = request.source || 'content-script';
      await debugLog('handleMessage: Received pageBody from', source);
      await debugLog('handleMessage: Origin:', request.origin);
      await debugLog('handleMessage: Page body length:', request.pageBody.length);

      await checkData(
        request.pageBody,
        request.origin,
        request.parentUrl,
        request.parentOrigin
      );
      return { success: true };
    } else if (request.scriptUrl) {
      // Check scanExternalScripts setting
      const settings = await chrome.storage.local.get(['scanExternalScripts', 'debugMode']);
      if (settings.scanExternalScripts === false) {
        await debugLog('External scripts scanning disabled');
        return { success: false, reason: 'disabled' };
      }

      // Fetch and check external scripts
      try {
        // Check cache before fetching to avoid duplicate requests
        const scriptCacheKey = request.scriptUrl;
        const now = Date.now();

        // Check both new and old cache keys for backward compatibility
        const scriptCachedTime = processedUrls.get(scriptCacheKey) || processedUrls.get(`${scriptCacheKey}-${request.parentOrigin}`);

        if (scriptCachedTime && (now - scriptCachedTime) < CACHE_DURATION) {
          return { success: true, reason: 'already_processed' };
        }

        // Skip URLs with embedded credentials — fetch() throws a TypeError for these
        // (e.g. Sentry DSNs: https://key@sentry.io/project)
        try {
          const parsedUrl = new URL(request.scriptUrl);
          if (parsedUrl.username || parsedUrl.password) {
            await debugLog(`Skipping credential URL: ${request.scriptUrl}`);
            return { success: false, reason: 'credential_url' };
          }
        } catch (_) {
          return { success: false, reason: 'invalid_url' };
        }

        const response = await fetch(request.scriptUrl, {
          credentials: 'include',
          cache: 'force-cache' // Use cache for performance
        });

        // Check if response is successful
        if (!response.ok) {
          await debugLog(`Skipping ${request.scriptUrl} - HTTP ${response.status}`);
          return { success: false, reason: 'http_error', status: response.status };
        }

        await debugLog(`Fetching script: ${request.scriptUrl}`);

        const data = await response.text();
        await debugLog(`Successfully fetched script: ${request.scriptUrl} (${data.length} chars)`);

        // Cache the script URL immediately to prevent duplicate fetches
        processedUrls.set(request.scriptUrl, now);

        await checkData(
          data,
          request.scriptUrl,
          request.parentUrl,
          request.parentOrigin
        );

        return { success: true };
      } catch (fetchError) {
        // Enhanced error handling for CSP and network errors
        if (fetchError.message.includes('Content Security Policy') ||
            fetchError.message.includes('CSP') ||
            fetchError.message.includes('Failed to fetch') ||
            fetchError.message.includes('credentials')) {
          await debugLog(`Skipping ${request.scriptUrl}: ${fetchError.message}`);
          return { success: false, reason: 'csp_error', error: fetchError.message };
        }

        console.error('Error fetching script:', request.scriptUrl, fetchError);
        return { success: false, reason: 'fetch_error', error: fetchError.message };
      }
    } else if (request.envFile) {
      // Check scanSensitiveFiles setting
      const settings = await chrome.storage.local.get(['scanSensitiveFiles', 'debugMode']);
      if (settings.scanSensitiveFiles === false) {
        if (settings.debugMode) {
          await debugLog('Sensitive files scanning disabled');
        }
        return { success: false, reason: 'disabled' };
      }

      // Check cache for sensitive files
      const cacheKey = `sensitive-${request.envFile}`;
      const now = Date.now();
      const cachedTime = processedUrls.get(cacheKey);

      if (cachedTime && (now - cachedTime) < CACHE_DURATION) {
        if (settings.debugMode) {
          await debugLog('Sensitive file already processed (cached):', request.envFile);
        }
        return { success: false, reason: 'cached' };
      }

      // Check .env files
      try {
        const response = await fetch(request.envFile, {
          credentials: 'include',
          cache: 'force-cache'
        });

        // Check if response is successful
        if (!response.ok) {
          if (settings.debugMode) {
            await debugLog(`Skipping ${request.envFile} - HTTP ${response.status}`);
          }
          return { success: false, reason: 'http_error', status: response.status };
        }

        const data = await response.text();
        await checkData(
          data,
          `.env file at ${request.envFile}`,
          request.parentUrl,
          request.parentOrigin
        );

        // Cache the processed file
        processedUrls.set(cacheKey, now);

        return { success: true };

      } catch (fetchError) {
        if (fetchError.message.includes('Content Security Policy') ||
            fetchError.message.includes('CSP') ||
            fetchError.message.includes('Failed to fetch')) {
          if (settings.debugMode) {
            await debugLog(`CSP/Network error for ${request.envFile}:`, fetchError.message);
          }
          return { success: false, reason: 'csp_error', error: fetchError.message };
        }

        if (settings.debugMode) {
          console.error('Error fetching env file:', request.envFile, fetchError);
        }
        return { success: false, reason: 'fetch_error', error: fetchError.message };
      }
    }

    return { success: true };
  } catch (error) {
    console.error('Error handling message:', error);
    return { success: false, error: error.message };
  }
}
