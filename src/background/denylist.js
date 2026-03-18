// SecretRadar - Denylist (Background)

import { debugLog } from './utils.js';

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

// Check if domain matches deny pattern (supports wildcards)
export function matchesDenyPattern(domain, pattern) {
  // Remove protocol if present in pattern
  pattern = pattern.replace(/^https?:\/\//, '');

  // Handle wildcard patterns
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.substring(2); // Remove '*.'
    return domain === baseDomain || domain.endsWith('.' + baseDomain);
  }

  // Handle exact domain match
  return domain === pattern;
}
