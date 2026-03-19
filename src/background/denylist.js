// SecretRadar - Denylist (Background)

import { debugLog } from './utils.js';
import { matchesDenyPattern } from '../shared/denylist-utils.js';

// Check if origin is in deny list
export async function isOriginDenied(url) {
  try {
    if (!url) return false;

    const storage = await chrome.storage.local.get(['denyList']);
    const denyList = storage.denyList || ['https://www.google.com'];

    // Extract domain from URL
    let domain;
    try {
      domain = new URL(url).hostname;
    } catch (error) {
      console.error('Invalid URL for deny list check:', url);
      return false;
    }

    // Check each deny list pattern
    for (const pattern of denyList) {
      if (matchesDenyPattern(domain, pattern)) {
        return true;
      }
    }

    return false;
  } catch (error) {
    console.error('Error checking origin deny list:', error);
    return false;
  }
}

export { matchesDenyPattern };
