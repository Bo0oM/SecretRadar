// SecretRadar - Notifications (Background)

import { debugLog } from './utils.js';
import { newFindings } from './state.js';

export const notificationQueue = new Map(); // origin -> { count: number, timer: timeout }
export const notifiedOrigins = new Set(); // Track origins that have been notified
export const NOTIFICATION_DEBOUNCE = 2000; // 2 seconds debounce for notifications
export const MAX_NOTIFICATIONS_PER_ORIGIN = 5; // Maximum notifications per origin per session

// Queue notification for grouping by origin
export async function queueNotification(finding) {
  try {
    const origin = finding.parentOrigin;

    // Check if we've already notified this origin too many times
    if (notifiedOrigins.has(origin)) {
      await debugLog(`Skipping notification for ${origin} - already notified in this session`);
      return;
    }

    // Get existing queue entry or create new one
    let queueEntry = notificationQueue.get(origin);
    if (!queueEntry) {
      queueEntry = { count: 0, timer: null };
      notificationQueue.set(origin, queueEntry);
    }

    // Increment count
    queueEntry.count++;

    // Clear existing timer
    if (queueEntry.timer) {
      clearTimeout(queueEntry.timer);
    }

    // Set new timer to show grouped notification
    queueEntry.timer = setTimeout(async () => {
      await showGroupedNotification(origin, queueEntry.count);
      notificationQueue.delete(origin);
      // Mark this origin as notified to prevent spam
      notifiedOrigins.add(origin);
    }, NOTIFICATION_DEBOUNCE);

    await debugLog(`Queued notification for ${origin}, count: ${queueEntry.count}`);
  } catch (error) {
    console.error('Error queuing notification:', error);
  }
}

// Show grouped notification for origin
export async function showGroupedNotification(origin, count) {
  try {
    const settings = await chrome.storage.local.get(['enableNotifications', 'debugMode']);

    await debugLog(`Showing grouped notification for ${origin} with ${count} findings`);

    // Show browser notification if enabled
    if (settings.enableNotifications) {
      const notificationId = await chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icon48.png'),
        title: 'SecretRadar Security Alert',
        message: `${count} high-confidence secrets detected on ${origin}`
      });
      await debugLog('Grouped notification created with ID:', notificationId);
    } else {
      await debugLog('Notifications are disabled in settings');
    }

    // Update badge
    await updateBadge(origin);
  } catch (error) {
    console.error('[SecretRadar] Error showing grouped notification:', error);
  }
}

// Show notification for high-confidence findings (legacy - now replaced by queueNotification)
export async function showNotification(finding) {
  try {
    const settings = await chrome.storage.local.get(['enableNotifications', 'debugMode']);

    // Check if this is a new finding
    const findingId = `${finding.type}-${finding.match}-${finding.source}`;
    if (!newFindings.has(findingId)) {
      await debugLog('Skipping notification - not a new finding');
      return;
    }

    await debugLog(`Notification check - enableNotifications: ${settings.enableNotifications}, debugMode: ${settings.debugMode}`);
    await debugLog(`Security Alert: High-confidence ${finding.type} detected on ${finding.parentOrigin}`);

    // Show browser notification if enabled
    if (settings.enableNotifications) {
      await debugLog('Creating browser notification...');
      const notificationId = await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'SecretRadar Security Alert',
        message: `High-confidence ${finding.type} detected on ${finding.parentOrigin}`
      });
      await debugLog('Notification created with ID:', notificationId);
    } else {
      await debugLog('Notifications are disabled in settings');
    }

    // Update badge
    await updateBadge(finding.parentOrigin);
  } catch (error) {
    // Get settings again in case of error
    try {
      const errorSettings = await chrome.storage.local.get(['debugMode']);
      if (errorSettings.debugMode) {
        await debugLog('Error showing notification:', error);
      }
    } catch (settingsError) {
      await debugLog('Error showing notification:', error);
    }
  }
}

// Update badge with finding count for specific origin
export async function updateBadge(origin) {
  try {
    await debugLog(`Updating badge for origin: ${origin}`);

    const storage = await chrome.storage.local.get(['findings']);

    // Count findings for the specific origin
    let originCount = 0;
    let totalCount = 0;

    if (storage.findings) {
      for (const key in storage.findings) {
        const findings = storage.findings[key];
        totalCount += findings.length;

        // Count findings for this specific origin
        const originFindings = findings.filter(finding => finding.parentOrigin === origin);
        originCount += originFindings.length;
      }
    }

    // Count new findings for this origin
    let newCountForOrigin = 0;
    for (const findingId of newFindings) {
      // Extract origin from findingId (format: "type-match-source")
      const parts = findingId.split('-');
      if (parts.length >= 3) {
        const source = parts.slice(2).join('-'); // Reconstruct source
        try {
          const sourceOrigin = new URL(source).origin;
          if (sourceOrigin === origin) {
            newCountForOrigin++;
          }
        } catch (urlError) {
          // If source is not a URL, check if it contains the origin
          if (source.includes(origin)) {
            newCountForOrigin++;
          }
        }
      }
    }

    // Show only origin-specific count, no fallback to total count
    const badgeText = newCountForOrigin > 0 ? `!${newCountForOrigin}` :
                     (originCount > 0 ? originCount.toString() : '');

    await debugLog(`Badge text: ${badgeText} (origin: ${originCount}, new: ${newCountForOrigin}, total: ${totalCount})`);

    await chrome.action.setBadgeText({
      text: badgeText
    });

    await chrome.action.setBadgeBackgroundColor({
      color: newCountForOrigin > 0 ? '#ff6600' :
             (originCount > 0 ? '#ff0000' : '#6c757d')
    });
  } catch (error) {
    console.error('Error updating badge:', error);
  }
}

// Function to clear notification queue
export function clearNotificationQueue() {
  // Clear all timers
  for (const [origin, entry] of notificationQueue.entries()) {
    if (entry.timer) {
      clearTimeout(entry.timer);
    }
  }
  notificationQueue.clear();
  notifiedOrigins.clear();
  console.log('[SecretRadar] Notification queue and tracking cleared');
}
