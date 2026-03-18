// SecretRadar - Notifications (Background)

import { debugLog } from './utils.js';

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

// Update badge with finding count for specific origin
export async function updateBadge(origin) {
  try {
    await debugLog(`Updating badge for origin: ${origin}`);

    const storage = await chrome.storage.local.get(['findings', 'confidenceThreshold']);
    const threshold = storage.confidenceThreshold ?? 0.3;

    // Count findings for the specific origin above confidence threshold
    let originCount = 0;

    if (storage.findings) {
      for (const findings of Object.values(storage.findings)) {
        for (const finding of findings) {
          if (finding.parentOrigin === origin && finding.confidence >= threshold) {
            originCount++;
          }
        }
      }
    }

    const badgeText = originCount > 0 ? originCount.toString() : '';

    await debugLog(`Badge text: ${badgeText} (origin: ${originCount}, threshold: ${threshold})`);

    await chrome.action.setBadgeText({ text: badgeText });
    await chrome.action.setBadgeBackgroundColor({
      color: originCount > 0 ? '#ff0000' : '#6c757d'
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
