// SecretRadar - Secret Detector

import { SECRET_PATTERNS, FALSE_POSITIVE_PATTERNS } from './patterns.js';
import { debugLog, decodeJWT, calculateShannonEntropy } from './utils.js';

// Enhanced secret detection with context analysis
export async function detectSecrets(content, source, parentUrl, parentOrigin) {
  const findings = [];

  // Check debug mode once — never read storage inside the match loop
  const settings = await chrome.storage.local.get(['debugMode', 'confidenceThreshold']);
  const isDebugMode = settings.debugMode || false;

  if (isDebugMode) {
    await debugLog(`Scanning content from ${source} (${content.length} chars)`);
    await debugLog(`Content preview: ${content.substring(0, 200)}...`);
    await debugLog(`Settings:`, settings);
  }

  for (const [secretType, config] of Object.entries(SECRET_PATTERNS)) {
    try {
      // Prefilter: skip expensive regex if required marker string is absent
      if (config.prefilter && !content.includes(config.prefilter)) continue;

      const matches = content.matchAll(config.pattern);
      let matchCount = 0;

      for (const match of matches) {
        matchCount++;

        const matchedValue = match[0];
        const matchIndex = match.index;

        // Skip if it's a known false positive
        if (FALSE_POSITIVE_PATTERNS.some(fp => fp.test(matchedValue))) {
          continue;
        }

        // Context analysis — uses match.index directly, no indexOf scan
        const context = analyzeContext(content, matchedValue, matchIndex, source);

        // Run validation function if it exists (normalise sync/async via Promise.resolve)
        if (config.validation && !(await Promise.resolve(config.validation(matchedValue, context)))) {
          if (isDebugMode) {
            await debugLog(`Validation failed for ${secretType}:`, matchedValue.substring(0, 40));
          }
          continue;
        }

        const confidence = calculateConfidence(config, context, matchedValue, secretType);

        if (isDebugMode) {
          await debugLog(`${secretType} confidence=${confidence.toFixed(2)} value=${matchedValue.substring(0, 30)}`);
        }

        if (confidence > 0.3) { // Minimum confidence threshold
          let displayValue = matchedValue;

          // Special handling for JWT tokens - decode and show payload info
          if (secretType.startsWith("JWT Token") && matchedValue.length > 100) {
            const decoded = decodeJWT(matchedValue);
            if (decoded && decoded.payload) {
              const payloadInfo = [];
              if (decoded.payload.sub) payloadInfo.push(`sub: ${decoded.payload.sub}`);
              if (decoded.payload.iss) payloadInfo.push(`iss: ${decoded.payload.iss}`);
              if (decoded.payload.aud) payloadInfo.push(`aud: ${decoded.payload.aud}`);
              if (decoded.payload.email) payloadInfo.push(`email: ${decoded.payload.email}`);

              // Add lifetime information
              if (decoded.analysis) {
                if (decoded.analysis.isExpired) {
                  payloadInfo.push(`EXPIRED`);
                } else if (decoded.analysis.expiresIn !== null) {
                  const hours = Math.floor(decoded.analysis.expiresIn / 3600);
                  const days = Math.floor(hours / 24);
                  if (days > 0) {
                    payloadInfo.push(`expires in ${days}d ${hours % 24}h`);
                  } else {
                    payloadInfo.push(`expires in ${hours}h`);
                  }
                }

                if (decoded.analysis.isLongLived) {
                  payloadInfo.push(`LONG-LIVED`);
                }
              }

              displayValue = `${matchedValue.substring(0, 50)}... (${payloadInfo.join(', ')})`;
            } else {
              displayValue = `${matchedValue.substring(0, 50)}...`;
            }
          }

          findings.push({
            type: secretType,
            match: matchedValue,
            displayValue: displayValue,
            source: parentUrl || source || 'Unknown source',
            confidence: confidence,
            context: context,
            parentUrl: parentUrl || 'Unknown URL',
            parentOrigin: parentOrigin || 'Unknown origin',
            timestamp: Date.now()
          });
        }
      }

      if (isDebugMode && matchCount > 0) {
        await debugLog(`${secretType}: ${matchCount} matches`);
      }
    } catch (error) {
      console.error(`Error processing ${secretType}:`, error);
    }
  }

  if (isDebugMode) {
    await debugLog(`Total findings: ${findings.length}`);
  }

  return findings;
}

// Analyze context around the match to reduce false positives
// matchIndex is match.index from matchAll — free, no indexOf scan needed
export function analyzeContext(content, match, matchIndex, source = '') {
  const context = {
    surroundingText: '',
    keywords: [],
    confidence: 0,
    source  // URL/origin of the scanned content — available to validation functions
  };

  try {
    if (matchIndex === undefined || matchIndex === -1) return context;

    // Get surrounding text (200 characters before and after)
    const start = Math.max(0, matchIndex - 200);
    const end = Math.min(content.length, matchIndex + match.length + 200);
    let surroundingText = content.substring(start, end);

    // Clean up the surrounding text
    surroundingText = surroundingText.replace(/\s+/g, ' ').trim();

    // Truncate if too long (max 300 characters)
    if (surroundingText.length > 300) {
      const matchPos = surroundingText.indexOf(match);
      if (matchPos !== -1) {
        const beforeMatch = surroundingText.substring(0, matchPos);
        const afterMatch = surroundingText.substring(matchPos + match.length);

        // Keep 100 chars before and 100 chars after, or less if available
        const beforeLength = Math.min(100, beforeMatch.length);
        const afterLength = Math.min(100, afterMatch.length);

        surroundingText = beforeMatch.substring(beforeMatch.length - beforeLength) +
                         match +
                         afterMatch.substring(0, afterLength);

        // Add ellipsis if truncated
        if (beforeMatch.length > beforeLength) surroundingText = '...' + surroundingText;
        if (afterMatch.length > afterLength) surroundingText = surroundingText + '...';
      } else {
        surroundingText = surroundingText.substring(0, 300) + '...';
      }
    }

    context.surroundingText = surroundingText;

    // Extract keywords from surrounding text
    const keywords = [
      'api', 'key', 'token', 'secret', 'password', 'auth', 'authentication',
      'credential', 'access', 'private', 'public', 'config', 'environment',
      'env', 'variable', 'setting', 'credential', 'authorization',
      'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
      'ci', 'cd', 'registry', 'docker', 'gitlab', 'github', 'npm'
    ];

    const textLower = surroundingText.toLowerCase();
    context.keywords = keywords.filter(keyword => textLower.includes(keyword));

    // Calculate confidence based on keyword presence
    context.confidence = Math.min(1.0, context.keywords.length * 0.2);

  } catch (error) {
    console.error('Error analyzing context:', error);
  }

  return context;
}

// Calculate confidence score based on pattern and context
export function calculateConfidence(config, context, match, secretType = '') {
  // Base is determined by pattern confidence — this is the primary signal
  let confidence;
  switch (config.confidence) {
    case 'high':   confidence = 0.75; break;
    case 'medium': confidence = 0.55; break;
    case 'low':    confidence = 0.35; break;
    default:       confidence = 0.35;
  }

  const contextText = context.surroundingText.toLowerCase();

  // Context keyword bonus: pattern's own context[] keywords found nearby
  if (config.context.some(ctx => contextText.includes(ctx))) {
    confidence += 0.1;
  }

  // Negative keywords penalty — clear false-positive signals
  const negativeKeywords = [
    'example', 'test', 'demo', 'fake', 'mock', 'dummy', 'placeholder',
    'documentation', 'tutorial', 'sample', 'template'
  ];
  const negativeCount = negativeKeywords.filter(kw => contextText.includes(kw)).length;
  if (negativeCount > 0) {
    confidence -= Math.min(negativeCount * 0.15, 0.3);
  }

  // Value itself contains placeholder signals
  const lowerMatch = match.toLowerCase();
  if (lowerMatch.includes('example') || lowerMatch.includes('test') || lowerMatch.includes('demo')) {
    confidence -= 0.15;
  }

  // Generic pattern entropy check — high-entropy values are more likely real secrets
  if (secretType && secretType.includes('Generic')) {
    const entropy = calculateShannonEntropy(match);
    if (entropy >= 4.0) {
      confidence += (entropy - 4.0) * 0.1;
    } else if (entropy < 3.0) {
      confidence -= 0.2;
    }
  }

  // JWT: override base, adjust by token properties
  if (secretType.startsWith('JWT Token')) {
    confidence = 0.4;
    const decoded = decodeJWT(match);
    if (decoded && decoded.payload) {
      if (decoded.analysis) {
        if (decoded.analysis.isLongLived) confidence += 0.15;
        // Active short-lived token (< 10 min) — operational/infra token, not a leaked secret
        if (decoded.analysis.lifetime !== null && decoded.analysis.lifetime <= 600) {
          confidence = 0.1;
        } else if (decoded.analysis.isExpired) {
          // Expired token: penalise more if it was originally short-lived (< 1h)
          if (decoded.analysis.originalLifetime !== null && decoded.analysis.originalLifetime <= 3600) {
            confidence = 0.1;
          } else {
            confidence -= 0.2;
          }
        } else if (decoded.analysis.expiresIn !== null && decoded.analysis.expiresIn < 3600) {
          confidence -= 0.1;
        }
      }
      // jwt.io canonical example token
      if (decoded.payload.sub === '1234567890' && decoded.payload.name === 'John Doe') {
        confidence = 0.1;
      } else if (decoded.payload.sub === '1234567890' || decoded.payload.sub === 'test') {
        confidence -= 0.15;
      }
    } else {
      confidence -= 0.15;
    }
  }

  // Generic Password Variable: penalise UI text / i18n strings
  if (secretType === 'Generic Password Variable') {
    if (/\s/.test(match) || /[а-яёА-ЯЁ]/.test(match) ||
        /^[A-Z][a-z]+(\s[A-Z][a-z]+)*$/.test(match) ||
        /^(reset|login|sign|continue|verify|password|pass|pwd)$/i.test(match)) {
      confidence = 0.1; // hard kill — natural language is never a password
    }
  }

  // Google API Keys used for Maps embeds are intentionally public — lower priority
  if (secretType === 'Google API Key' || secretType === 'Google API Key (standalone)') {
    if (/maps\.google|googleapis\.com\/maps|google\.maps|maps_api|initmap/i
        .test(context.surroundingText)) {
      confidence -= 0.2;
    }
  }

  return Math.min(Math.max(confidence, 0.1), 1.0);
}
