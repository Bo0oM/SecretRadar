// SecretRadar - Notifications (Background)

import { debugLog } from './utils.js';

export const notificationQueue = new Map(); // origin -> { count: number, timer: timeout }
export const notifiedOrigins = new Set(); // Track origins that have been notified (session-persisted)
export const notificationOrigins = new Map(); // notificationId -> origin (for click handling)
export const NOTIFICATION_DEBOUNCE = 2000; // 2 seconds debounce for notifications
export const MAX_NOTIFICATIONS_PER_ORIGIN = 5; // Maximum notifications per origin per session

// Load notifiedOrigins from session storage — survives SW restarts within same browser session
chrome.storage.session.get(['notifiedOrigins']).then(data => {
  if (Array.isArray(data.notifiedOrigins)) {
    for (const origin of data.notifiedOrigins) notifiedOrigins.add(origin);
  }
}).catch(() => {});

async function persistNotifiedOrigins() {
  await chrome.storage.session.set({ notifiedOrigins: [...notifiedOrigins] }).catch(() => {});
}

// Clear notification tracking for a specific origin (call when user explicitly clears findings)
export async function clearNotifiedOrigin(origin) {
  if (origin) {
    notifiedOrigins.delete(origin);
  } else {
    notifiedOrigins.clear(); // clear all (browser restart / manual reset)
  }
  await persistNotifiedOrigins();
}

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
      queueEntry = { count: 0, maxConfidence: 0, timer: null };
      notificationQueue.set(origin, queueEntry);
    }

    // Increment count and track highest confidence seen
    queueEntry.count++;
    if ((finding.confidence || 0) > queueEntry.maxConfidence) {
      queueEntry.maxConfidence = finding.confidence || 0;
    }

    // Clear existing timer
    if (queueEntry.timer) {
      clearTimeout(queueEntry.timer);
    }

    // Set new timer to show grouped notification
    queueEntry.timer = setTimeout(async () => {
      await showGroupedNotification(origin, queueEntry.count, queueEntry.maxConfidence);
      notificationQueue.delete(origin);
      // Mark this origin as notified — persist so SW restart doesn't reset dedup
      notifiedOrigins.add(origin);
      await persistNotifiedOrigins();
    }, NOTIFICATION_DEBOUNCE);

    await debugLog(`Queued notification for ${origin}, count: ${queueEntry.count}, maxConf: ${queueEntry.maxConfidence}`);
  } catch (error) {
    console.error('Error queuing notification:', error);
  }
}

function confidenceLevel(conf) {
  if (conf >= 0.8) return 'high';
  if (conf >= 0.5) return 'medium';
  return 'low';
}

const LEVEL_BADGE_COLOR = {
  high:   '#dc3545',
  medium: '#fd7e14',
  low:    '#6c757d',
};

const LEVEL_TITLE = {
  high:   'SecretRadar — High Risk',
  medium: 'SecretRadar — Warning',
  low:    'SecretRadar — Notice',
};

const LEVEL_MESSAGE = {
  high:   (count, origin) => `${count} high-risk secret${count > 1 ? 's' : ''} detected on ${origin}`,
  medium: (count, origin) => `${count} medium-confidence secret${count > 1 ? 's' : ''} detected on ${origin}`,
  low:    (count, origin) => `${count} low-confidence finding${count > 1 ? 's' : ''} on ${origin}`,
};

// Show grouped notification for origin
export async function showGroupedNotification(origin, count, maxConfidence = 0) {
  try {
    const settings = await chrome.storage.local.get(['enableNotifications', 'debugMode']);
    const level = confidenceLevel(maxConfidence);

    await debugLog(`Showing grouped notification for ${origin} with ${count} findings, level: ${level}`);

    // Show browser notification if enabled
    if (settings.enableNotifications) {
      const notificationId = await chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icon48.png'),
        title: LEVEL_TITLE[level],
        message: LEVEL_MESSAGE[level](count, origin)
      });
      notificationOrigins.set(notificationId, origin);
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

    const storage = await chrome.storage.local.get(['findings']);

    let originCount = 0;
    let maxConf = 0;

    if (storage.findings) {
      for (const findings of Object.values(storage.findings)) {
        for (const finding of findings) {
          if (finding.parentOrigin === origin) {
            originCount++;
            if ((finding.confidence || 0) > maxConf) maxConf = finding.confidence || 0;
          }
        }
      }
    }

    const badgeText = originCount > 0 ? originCount.toString() : '';
    const badgeColor = originCount > 0 ? LEVEL_BADGE_COLOR[confidenceLevel(maxConf)] : '#6c757d';

    await debugLog(`Badge: ${badgeText} color: ${badgeColor} (${originCount} findings, maxConf: ${maxConf})`);

    await chrome.action.setBadgeText({ text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor });
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
}
