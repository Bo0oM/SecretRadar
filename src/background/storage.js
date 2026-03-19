// SecretRadar - Storage (Background)

import { debugLog } from './utils.js';
import { updateBadge, queueNotification, notifiedOrigins } from './notifications.js';
import { isOriginDenied } from './denylist.js';
import { processedUrls, newFindings, CACHE_DURATION } from './state.js';

export { processedUrls, newFindings, CACHE_DURATION };

// Store findings with improved data structure
export async function storeFindings(findings, origin) {
  try {
    const storage = await chrome.storage.local.get(['findings']);
    const existingFindings = storage.findings || {};

    // Use parentOrigin as key — consistent with badge counting and popup display
    const key = origin;

    if (!existingFindings[key]) {
      existingFindings[key] = [];
    }

    // Deduplicate findings - consider only unique secrets, not sources
    for (const finding of findings) {
      const isDuplicate = existingFindings[key].some(existing =>
        existing.match === finding.match &&
        existing.type === finding.type
      );

      if (!isDuplicate) {
        existingFindings[key].push(finding);

        // Mark as new finding for notification
        const findingId = `${finding.type}-${finding.match}-${finding.source}`;
        newFindings.add(findingId);

        // Queue notification for high-confidence findings (grouped by origin)
        if (finding.confidence >= 0.7) {
          await queueNotification(finding);
        }
      } else {
        // Log duplicate detection for debugging
        const settings = await chrome.storage.local.get(['debugMode']);
        if (settings.debugMode) {
          await debugLog('Duplicate secret detected and skipped:', {
            type: finding.type,
            match: finding.match.substring(0, 20) + '...',
            source: finding.source,
            existingSources: existingFindings[key]
              .filter(existing => existing.match === finding.match && existing.type === finding.type)
              .map(existing => existing.source)
          });
        }
      }
    }

    await chrome.storage.local.set({ findings: existingFindings });

    // Update badge after storing findings only if there are findings
    if (findings.length > 0 && findings[0].parentOrigin) {
      await updateBadge(findings[0].parentOrigin);
    } else {
      // Clear badge if no findings for this origin
      await chrome.action.setBadgeText({ text: '' });
      await chrome.action.setBadgeBackgroundColor({ color: '#6c757d' });
    }
  } catch (error) {
    console.error('Error storing findings:', error);
  }
}

// Clean up old findings, remove duplicates, and remove findings from denied domains
export async function cleanupOldFindings() {
  try {
    const storage = await chrome.storage.local.get(['findings', 'dataRetentionDays', 'denyList']);
    const findings = storage.findings || {};
    const retentionDays = storage.dataRetentionDays || 7;
    const retentionMs = retentionDays * 24 * 60 * 60 * 1000;
    const cutoffTime = Date.now() - retentionMs;

    let cleanedCount = 0;
    let duplicateCount = 0;
    let deniedCount = 0;
    const cleanedFindings = {};

    for (const [origin, originFindings] of Object.entries(findings)) {
      // Check if origin is in deny list
      const isDenied = await isOriginDenied(origin);
      if (isDenied) {
        deniedCount += originFindings.length;
        continue; // Skip this origin entirely
      }

      // Remove old findings
      const recentFindings = originFindings.filter(finding => finding.timestamp >= cutoffTime);

      // Remove duplicates (keep only the first occurrence of each unique secret)
      const uniqueFindings = [];
      const seenSecrets = new Set();

      for (const finding of recentFindings) {
        const secretKey = `${finding.type}:${finding.match}`;
        if (!seenSecrets.has(secretKey)) {
          seenSecrets.add(secretKey);
          uniqueFindings.push(finding);
        } else {
          duplicateCount++;
        }
      }

      if (uniqueFindings.length > 0) {
        cleanedFindings[origin] = uniqueFindings;
      }
      cleanedCount += originFindings.length - uniqueFindings.length;
    }

    if (cleanedCount > 0 || duplicateCount > 0 || deniedCount > 0) {
      await chrome.storage.local.set({ findings: cleanedFindings });
      await debugLog(`Cleaned up ${cleanedCount} old findings, removed ${duplicateCount} duplicates, and removed ${deniedCount} findings from denied domains`);
    }

  } catch (error) {
    console.error('Error cleaning up old findings:', error);
  }
}

// Function to clear cache manually
export function clearCache() {
  processedUrls.clear();
}

// Function to clear new findings for specific origin
export function clearNewFindingsForOrigin(origin) {
  // newFindings is in-memory session state not used for display decisions —
  // clear entirely on tab switch (harmless over-clear)
  newFindings.clear();

  // Reset notification throttle so future findings on this origin notify again
  notifiedOrigins.delete(origin);
}
