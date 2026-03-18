// SecretRadar - Shared mutable state (no imports — used by both storage and notifications)

export const processedUrls = new Map(); // URL -> timestamp
export const newFindings = new Set();   // Track new findings for notifications
export const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
