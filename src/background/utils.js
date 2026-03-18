// SecretRadar - Background Utilities

// Debug logging helper function
export async function debugLog(message, ...args) {
  try {
    const settings = await chrome.storage.local.get(['debugMode']);
    if (settings.debugMode) {
      console.log('[SecretRadar Debug]', message, ...args);
    }
  } catch (error) {
  }
}

export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      return func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// JWT Decoder function with enhanced time analysis
export function decodeJWT(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;

    // Decode header and payload
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    // Token lifetime analysis
    const now = Math.floor(Date.now() / 1000);
    let tokenAnalysis = {
      isExpired: false,
      isLongLived: false,
      expiresIn: null,
      age: null,
      lifetime: null
    };

    // Check expiration time (exp)
    if (payload.exp) {
      const expiresAt = payload.exp;
      const expiresIn = expiresAt - now;

      tokenAnalysis.isExpired = expiresIn < 0;
      tokenAnalysis.expiresIn = expiresIn;

      // If token is not expired, calculate lifetime
      if (!tokenAnalysis.isExpired) {
        tokenAnalysis.lifetime = expiresIn;

        // Token is considered long-lived if > 24 hours
        tokenAnalysis.isLongLived = expiresIn > 86400; // 24 hours in seconds
      }
    }

    // Check issued at time (iat)
    if (payload.iat) {
      const issuedAt = payload.iat;
      const age = now - issuedAt;
      tokenAnalysis.age = age;

      // If no exp but iat exists, we can estimate lifetime
      if (!payload.exp && age > 86400) {
        tokenAnalysis.isLongLived = true;
      }
    }

    return {
      header,
      payload,
      signature: parts[2],
      analysis: tokenAnalysis
    };
  } catch (error) {
    return null;
  }
}

// Shannon entropy calculation
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const charCount = {};
  for (const char of str) {
    charCount[char] = (charCount[char] || 0) + 1;
  }

  const length = str.length;
  let entropy = 0;

  for (const char in charCount) {
    const probability = charCount[char] / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}
