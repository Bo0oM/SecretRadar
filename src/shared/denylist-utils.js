// SecretRadar - Shared denylist utilities (used by both background and popup)

// Check if domain matches a deny pattern (supports wildcards like *.example.com)
export function matchesDenyPattern(domain, pattern) {
  pattern = pattern.replace(/^https?:\/\//, '');
  if (pattern.startsWith('*.')) {
    const base = pattern.substring(2);
    return domain === base || domain.endsWith('.' + base);
  }
  return domain === pattern;
}
