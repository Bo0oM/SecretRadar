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
        const context = analyzeContext(content, matchedValue, matchIndex);

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
          if (secretType === "JWT Token" && matchedValue.length > 100) {
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
export function analyzeContext(content, match, matchIndex) {
  const context = {
    surroundingText: '',
    keywords: [],
    confidence: 0
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
  let confidence = 0.15; // Slightly higher base confidence

  // Positive keywords (increase confidence)
  const positiveKeywords = [
    'key', 'token', 'secret', 'password', 'auth', 'api', 'credential',
    'access', 'private', 'secure', 'encrypt', 'signature', 'hash',
    'aws', 'amazon', 'google', 'github', 'stripe', 'slack', 'firebase',
    'database', 'connection', 'endpoint', 'webhook', 'oauth', 'jwt'
  ];

  // Negative keywords (decrease confidence)
  const negativeKeywords = [
    'example', 'test', 'demo', 'fake', 'mock', 'dummy', 'placeholder',
    'documentation', 'tutorial', 'sample', 'template', 'default',
    'not_a_real', 'also_not_real', 'fake_token', 'test_key',
    'example_secret', 'demo_password', 'sample_api', 'template_key',
    'placeholder_token', 'dummy_secret', 'mock_key', 'fake_credential'
  ];

  // Check positive keywords
  const contextText = context.surroundingText.toLowerCase();
  const positiveMatches = positiveKeywords.filter(keyword =>
    contextText.includes(keyword)
  );

  if (positiveMatches.length > 0) {
    confidence += Math.min(positiveMatches.length * 0.1, 0.3); // Maximum +0.3
  }

  // Check negative keywords
  const negativeMatches = negativeKeywords.filter(keyword =>
    contextText.includes(keyword)
  );

  if (negativeMatches.length > 0) {
    confidence -= Math.min(negativeMatches.length * 0.15, 0.4); // Maximum -0.4
  }

  // Pattern confidence (balanced)
  switch (config.confidence) {
    case 'high': confidence += 0.3; break;
    case 'medium': confidence += 0.2; break;
    case 'low': confidence += 0.1; break;
  }

  // Context confidence (balanced)
  if (config.context.some(ctx =>
    context.surroundingText.toLowerCase().includes(ctx)
  )) {
    confidence += 0.15; // Balanced context weight
  }

  // Keyword confidence (balanced)
  if (context.keywords.length > 0) {
    confidence += Math.min(context.keywords.length * 0.08, 0.2); // Balanced keyword weight
  }

  // Length and format confidence
  if (match.length > 20 && /[a-zA-Z0-9]/.test(match)) {
    confidence += 0.08;
  }

  // AWS bonus
  if (config.context.includes('aws') || config.context.includes('amazon')) {
    const awsContextKeywords = ['aws', 'amazon', 'secret', 'key', 'access', 'credential', 'configure', 'cli'];
    const awsContextCount = awsContextKeywords.filter(keyword =>
      context.surroundingText.toLowerCase().includes(keyword)
    ).length;

    if (awsContextCount >= 2) {
      confidence += 0.15; // Balanced AWS bonus
    }
  }

  // Enhanced confidence for generic patterns with entropy analysis
  if (secretType && secretType.includes('Generic')) {
    // Calculate entropy for the matched value
    const entropy = calculateShannonEntropy(match);

    // If entropy is high, increase confidence
    if (entropy >= 4.0) {
      confidence += (entropy - 4.0) * 0.15; // Bonus for high entropy
    } else if (entropy < 3.0) {
      confidence -= 0.2; // Penalty for low entropy
    }
  }

  // Special handling for JWT tokens with enhanced time analysis
  if (secretType === 'JWT Token') {
    confidence = 0.4; // Higher base for JWT

    // Check if it's a real JWT (has proper structure)
    const decoded = decodeJWT(match);
    if (decoded && decoded.payload) {
      // Analyze token lifetime
      if (decoded.analysis) {
        // If token is expired, reduce confidence
        if (decoded.analysis.isExpired) {
          confidence -= 0.2;
        }

        // If token is long-lived, increase confidence
        if (decoded.analysis.isLongLived) {
          confidence += 0.15;
        }

        // If token is short-lived (less than 1 hour), reduce confidence
        if (decoded.analysis.expiresIn !== null && decoded.analysis.expiresIn < 3600) {
          confidence -= 0.1;
        }
      }

      // Check if it's a common auth token
      if (decoded.payload.iss && (decoded.payload.iss.includes('auth') || decoded.payload.iss.includes('login'))) {
        confidence -= 0.1;
      }

      // Check if it's a test/example token
      if (decoded.payload.sub === '1234567890' || decoded.payload.sub === 'test' || decoded.payload.sub === 'example') {
        confidence -= 0.15;
      }
    } else {
      confidence -= 0.15; // Not a proper JWT structure
    }

    // Additional penalty for auth context
    const authKeywords = ['authorization', 'bearer', 'auth', 'login', 'session', 'cookie', 'token'];
    const hasAuthContext = authKeywords.some(keyword =>
      context.surroundingText.toLowerCase().includes(keyword)
    );

    if (hasAuthContext) {
      confidence -= 0.15;
    }
  }

  // Special handling for Generic Password
  if (secretType === 'Generic Password') {
    const passwordLikePatterns = [
      /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/,
      /^[A-Za-z0-9]{8,}$/,
      /^[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
    ];

    const isPasswordLike = passwordLikePatterns.some(pattern => pattern.test(match));
    if (!isPasswordLike) {
      confidence -= 0.2; // Reduced penalty
    }

    const uiTextPatterns = [
      /\s/,
      /^[A-Z][a-z]+(\s[A-Z][a-z]+)*$/,
      /^(reset|login|sign|continue|verify|password|pass|pwd)$/i,
      /[а-яё]/i
    ];

    const isUIText = uiTextPatterns.some(pattern => pattern.test(match));
    if (isUIText) {
      confidence -= 0.3; // Reduced penalty
    }
  }

  // Additional penalties for common false positives
  if (match.includes('example') || match.includes('test') || match.includes('demo')) {
    confidence -= 0.15;
  }

  if (match.includes('123456') || match.includes('password') || match.includes('secret')) {
    confidence -= 0.08;
  }

  return Math.min(Math.max(confidence, 0.1), 1.0);
}
