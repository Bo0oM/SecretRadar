// SecretRadar - Secret Patterns

import { debugLog } from './utils.js';

export const SECRET_PATTERNS = {
  // API Keys with improved validation
  "AWS Access Key": {
    pattern: /[\w.-]{0,50}?(?:aws|AWS)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(AKIA[0-9A-Z]{16})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["aws", "amazon", "cloud"],
    prefilter: "AKIA"
  },
  // Standalone: AKIA prefix is AWS-specific and unambiguous
  "AWS Access Key (standalone)": {
    pattern: /AKIA[0-9A-Z]{16}/g,
    confidence: "high",
    context: ["aws", "amazon", "key"],
    prefilter: "AKIA"
  },
  "AWS Secret Key": {
    pattern: /[\w.-]{0,50}?(?:aws|AWS)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([A-Za-z0-9\/+=]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["aws", "amazon", "secret", "key"]
  },
  "GitHub Personal Access Token": {
    pattern: /[\w.-]{0,50}?(?:github|GITHUB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(ghp_[a-zA-Z0-9]{36})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["github", "personal", "access"],
    prefilter: "ghp_"
  },
  // Standalone: ghp_ prefix is unambiguous, no context required
  "GitHub PAT (standalone)": {
    pattern: /ghp_[a-zA-Z0-9]{36,40}/g,
    confidence: "high",
    context: ["github", "token", "access"],
    prefilter: "ghp_"
  },
  // GitHub OAuth token
  "GitHub OAuth Token": {
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    confidence: "high",
    context: ["github", "oauth", "token"],
    prefilter: "gho_"
  },
  // GitHub Actions server-to-server token
  "GitHub Server Token": {
    pattern: /ghs_[a-zA-Z0-9]{36}/g,
    confidence: "high",
    context: ["github", "actions", "token"],
    prefilter: "ghs_"
  },
  // GitHub fine-grained personal access token (new format since 2022)
  "GitHub Fine-Grained PAT": {
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    confidence: "high",
    context: ["github", "token", "access"],
    prefilter: "github_pat_"
  },
  "Slack Token": {
    pattern: /[\w.-]{0,50}?(?:slack|SLACK)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{24,36})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["slack", "token"],
    validation: (match, context) => {
      // Check if it's a real Slack token (not just a pattern match)
      const slackKeywords = ['slack', 'token', 'bot', 'webhook', 'xox'];
      const hasSlackContext = slackKeywords.some(keyword =>
        context.surroundingText.toLowerCase().includes(keyword)
      );

      return hasSlackContext;
    }
  },
  "Stripe API Key": {
    pattern: /[\w.-]{0,50}?(?:stripe|STRIPE)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(sk_(live|test)_[a-zA-Z0-9]{24})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["stripe", "payment", "api"]
  },
  // Standalone: sk_live_ / sk_test_ prefix is unambiguous
  "Stripe Secret Key (standalone)": {
    pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/g,
    confidence: "high",
    context: ["stripe", "payment", "api"]
  },
  // Stripe publishable key — public by design but signals Stripe usage; medium severity
  "Stripe Publishable Key": {
    pattern: /pk_(live|test)_[a-zA-Z0-9]{24,}/g,
    confidence: "medium",
    context: ["stripe", "publishable", "public"]
  },
  "JWT Token": {
    pattern: /[\w.-]{0,50}?(?:jwt|JWT)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "low",
    context: ["jwt", "token", "bearer"],
    prefilter: "eyJ"
  },
  // Standalone JWT: eyJ header is unambiguous base64-encoded JSON start
  "JWT Token (standalone)": {
    pattern: /eyJ[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}\.?[A-Za-z0-9-_.+/=]*/g,
    confidence: "low",
    context: ["jwt", "token", "bearer"],
    prefilter: "eyJ"
  },
  "Private Key (RSA)": {
    pattern: /-----BEGIN RSA PRIVATE KEY-----(?:.|\n)*?-----END RSA PRIVATE KEY-----/g,
    confidence: "high",
    context: ["private", "key", "rsa", "ssh"],
    prefilter: "-----BEGIN"
  },
  "Private Key (DSA)": {
    pattern: /-----BEGIN DSA PRIVATE KEY-----(?:.|\n)*?-----END DSA PRIVATE KEY-----/g,
    confidence: "high",
    context: ["private", "key", "dsa", "ssh"],
    prefilter: "-----BEGIN"
  },
  "Private Key (EC)": {
    pattern: /-----BEGIN EC PRIVATE KEY-----(?:.|\n)*?-----END EC PRIVATE KEY-----/g,
    confidence: "high",
    context: ["private", "key", "ec", "elliptic"],
    prefilter: "-----BEGIN"
  },
  "PGP Private Key": {
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----(?:.|\n)*?-----END PGP PRIVATE KEY BLOCK-----/g,
    confidence: "high",
    context: ["pgp", "gpg", "private"],
    prefilter: "-----BEGIN"
  },
  "Heroku API Key": {
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    confidence: "medium",
    context: ["heroku"],
    validation: (match, context) => {
      const text = context.surroundingText.toLowerCase();

      // Exclude common UUID field names that are never API keys
      const fpFields = [
        'clientid', 'client_id', 'deviceid', 'device_id',
        'sessionid', 'session_id', 'userid', 'user_id',
        'requestid', 'request_id', 'traceid', 'trace_id',
        'spanid', 'span_id', 'correlationid', 'messagingid',
        'connectionclass', 'bootloader', 'mqttwebdevice',
        'data-analytics', 'button--', 'actionlist',
        '"id":', "'id':", 'transaction_id', 'event_id',
        'installation_id', 'workspace_id', 'organization_id',
      ];
      if (fpFields.some(fp => text.includes(fp))) return false;

      // Require explicit Heroku mention nearby
      return text.includes('heroku');
    }
  },
  "Mailgun API Key": {
    pattern: /key-[0-9a-zA-Z]{32}/g,
    confidence: "high",
    context: ["mailgun", "email", "api"]
  },
  "Twilio API Key": {
    pattern: /SK[0-9a-fA-F]{32}/g,
    confidence: "high",
    context: ["twilio", "sms", "api"]
  },
  "Google API Key": {
    pattern: /[\w.-]{0,50}?(?:google|GOOGLE)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(AIza[0-9A-Za-z\-_]{35})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["google", "api", "key", "maps", "analytics"]
  },
  // Standalone: AIzaSy prefix is Google-specific — medium because third-party sites often
  // embed their own Maps/Analytics keys intentionally; severity depends on API restrictions
  "Google API Key (standalone)": {
    pattern: /AIzaSy[0-9A-Za-z\-_]{33}/g,
    confidence: "medium",
    context: ["google", "api", "key"],
    prefilter: "AIzaSy",
    validation: (match, context) => {
      const ctx = context.surroundingText;
      const src = context.source || '';

      // YouTube/Google own pages — ALL AIzaSy keys are their own infrastructure keys
      if (src.includes('youtube.com') || src.includes('youtu.be') ||
          src.includes('google.com') || src.includes('googleapis.com')) return false;

      // Skip by context markers (catches embedded YouTube config in other pages)
      const googleInternalMarkers = [
        'INNERTUBE_API_KEY', 'INNERTUBE_', 'ytcfg', 'ytInitialData',
        'LIVE_CHAT_BASE_TANGO_CONFIG', 'VOZ_API_KEY', 'LINK_API_KEY',
        'obfuscatedData_', 'WEB_PLAYER_CONTEXT_CONFIGS',
        // Google Analytics — always public by design
        'analyticsKey', 'analytics_key', 'ga_key', 'GA_MEASUREMENT_ID',
        'googleAnalytics', 'google_analytics'
      ];
      if (googleInternalMarkers.some(marker => ctx.includes(marker))) return false;
      // gapi_key / gapi_client = app config key, referrer-restricted
      if (ctx.includes('gapi_key') || ctx.includes('gapi_client')) return false;
      return true;
    }
  },
  "Giphy API Key Variable": {
    pattern: /["']?[gG][iI][pP][hH][yY][_][aA][pP][iI][_][kK][eE][yY]["']?\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/g,
    confidence: "high",
    context: ["giphy", "api", "key", "gif"]
  },
  "Railway API Key Variable": {
    pattern: /["']?[rR][aA][iI][lL][wW][aA][yY][_][aA][pP][iI][_][kK][eE][yY]["']?\s*[:=]\s*["']([a-zA-Z0-9]{8,})["']/g,
    confidence: "high",
    context: ["railway", "api", "key"]
  },
  "Amadeus API Key Variable": {
    pattern: /["']?[aA][mM][aA][dD][eE][uU][sS][_][aA][pP][iI][_][kK][eE][yY]["']?\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/g,
    confidence: "high",
    context: ["amadeus", "api", "key"]
  },

  // Database credentials
  // JSON "password" field inside a connection/config object (e.g. leaked error responses, debug logs)
  // Generic Password pattern filters this out because matchedValue contains the key word "password"
  "JSON Connection Password": {
    pattern: /"password"\s*:\s*"([^"]{6,120})"/g,
    confidence: "high",
    context: ["host", "port", "user", "schema", "database", "db", "connection", "oracle", "mysql", "postgres", "mongo", "redis", "service_name", "service", "dsn"],
    prefilter: '"password"',
    validation: (match, context) => {
      const m = match.match(/"password"\s*:\s*"([^"]+)"/i);
      const value = m ? m[1] : '';
      if (!value || value.length < 6) return false;
      if (/\s/.test(value)) return false; // passwords don't have spaces
      if (/^(password|pass|pwd|secret|key|token|reset|login|enter|type|your|here)$/i.test(value)) return false;
      if (/(.)\1{4,}/.test(value)) return false; // repeating chars
      // Only flag when connection context is present (avoids login form FPs)
      const ctx = context.surroundingText.toLowerCase();
      const connFields = ['host', 'port', 'user', 'schema', 'database', 'service', 'connection',
        'oracle', 'mysql', 'postgres', 'mongo', 'redis', 'dsn', 'pooling', 'driver', 'provider'];
      return connFields.some(kw => ctx.includes(kw));
    }
  },
  "Database Password": {
    pattern: /["']?[dD][bB][_][pP][aA][sS][sS][wW][oO][rR][dD]["']?\s*[:=]\s*["']([^"']{8,})["']/g,
    confidence: "high",
    context: ["db", "database", "password", "mysql", "postgres"]
  },
  // Database connection strings
  "PostgreSQL URL": {
    pattern: /postgresql:\/\/[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_-]+/g,
    confidence: "high",
    context: ["postgresql", "postgres", "database", "connection", "url"],
    validation: async (match, context) => {
      const settings = await chrome.storage.local.get(['debugMode']);
      const isDebugMode = settings.debugMode || false;

      if (isDebugMode) {
        await debugLog('PostgreSQL URL validation:', { match, context: context.surroundingText });
      }

      if (!match.startsWith('postgresql://')) {
        if (isDebugMode) {
          await debugLog('PostgreSQL URL validation failed - not a PostgreSQL URL:', match);
        }
        return false;
      }

      return true;
    },
    prefilter: "postgresql://"
  },
  "MySQL URL": {
    pattern: /mysql:\/\/[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_-]+/g,
    confidence: "high",
    context: ["mysql", "database", "connection", "url"],
    prefilter: "mysql://"
  },
  "MongoDB URL": {
    pattern: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_-]+/g,
    confidence: "high",
    context: ["mongodb", "database", "connection", "url"],
    prefilter: "mongodb"
  },
  "Redis URL": {
    pattern: /redis:\/\/[^@]*@[a-zA-Z0-9.-]+:\d+/g,
    confidence: "high",
    context: ["redis", "database", "connection", "url"],
    prefilter: "redis://"
  },

  // Generic credential URL: scheme://user:pass@host — catches smtp, amqp, ftp, ldap, sftp, etc.
  // Specific schemes (postgresql, mysql, mongodb, redis, cloudinary) have their own higher-confidence patterns.
  "URL Credentials": {
    pattern: /[a-zA-Z][a-zA-Z0-9+.-]{1,15}:\/\/[a-zA-Z0-9._%-]{1,64}:([a-zA-Z0-9._~!$%^&*()\[\]+,;:-]{6,})@[a-zA-Z0-9][a-zA-Z0-9.-]+/g,
    confidence: "medium",
    context: ["url", "uri", "dsn", "connection", "connect", "config", "database", "db", "smtp", "amqp", "ftp", "ldap", "sftp", "git", "api", "auth", "credential", "secret", "password", "pass", "host", "server"],
    prefilter: "://",
    validation: (match) => {
      // Exclude schemes with dedicated higher-confidence patterns to avoid duplicates
      if (/^(?:postgresql|postgres|mysql|mongodb|redis|cloudinary):\/\//i.test(match)) return false;
      return true;
    }
  },

  // CI/CD and Registry credentials
  "CI Registry Password": {
    pattern: /["']?CI_REGISTRY_PASSWORD["']?\s*[:=]\s*["']([^"']{8,})["']/g,
    confidence: "high",
    context: ["ci", "registry", "password", "gitlab", "docker"]
  },
  "CI Registry Host": {
    pattern: /["']?CI_TEMPLATE_REGISTRY_HOST["']?\s*[:=]\s*["']([^"']{3,})["']/g,
    confidence: "medium",
    context: ["ci", "registry", "host", "gitlab", "docker"]
  },
  "CI Dependency Proxy Password": {
    pattern: /["']?CI_DEPENDENCY_PROXY_PASSWORD["']?\s*[:=]\s*["']([^"']{8,})["']/g,
    confidence: "high",
    context: ["ci", "proxy", "password", "gitlab"]
  },
  "CI Dependency Proxy Server": {
    pattern: /["']?CI_DEPENDENCY_PROXY_SERVER["']?\s*[:=]\s*["']([^"']{3,})["']/g,
    confidence: "medium",
    context: ["ci", "proxy", "server", "gitlab"]
  },
  "NPM Registry Auth": {
    pattern: /["']?NPM_REGISTRY__AUTH["']?\s*[:=]\s*["']([^"']{8,})["']/g,
    confidence: "high",
    context: ["npm", "registry", "auth", "token"]
  },
  "CI Package Registry User": {
    pattern: /["']?CI_PACKAGE_REGISTRY_USER["']?\s*[:=]\s*["']([^"']{3,})["']/g,
    confidence: "medium",
    context: ["ci", "package", "registry", "user", "gitlab"]
  },

  // Generic patterns for any service secrets
  "Generic Password": {
    pattern: /["']?[pP][aA][sS][sS][wW][oO][rR][dD]["']?\s*[:=]\s*["']([^"']{8,60})["']/g,
    confidence: "low",
    context: ["password", "pass", "pwd"],
    validation: (match, context) => {
      if (match.includes(' ')) {
        return false;
      }

      if (/(.)\1{3,}/.test(match)) {
        return false;
      }

      const commonWords = ['password', 'pass', 'pwd', 'secret', 'key', 'token', 'reset', 'login', 'sign', 'continue', 'verify'];
      if (commonWords.some(word => match.toLowerCase().includes(word))) {
        return false;
      }

      const uiKeywords = ['button', 'text', 'label', 'title', 'message', 'error', 'success', 'continue', 'reset', 'login', 'sign'];
      const hasUIContext = uiKeywords.some(keyword =>
        context.surroundingText.toLowerCase().includes(keyword)
      );
      if (hasUIContext) {
        return false;
      }

      return true;
    }
  },

  "Environment Variable API Key": {
    pattern: /export\s+[A-Z_]+_API_KEY\s*=\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["export", "api", "key", "environment"]
  },
  "Environment Variable Key": {
    pattern: /export\s+[A-Z_]+_KEY\s*=\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["export", "key", "environment"]
  },

  "Shell Variable API Key": {
    pattern: /[a-zA-Z_]+_api_key\s*=\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["api", "key", "shell", "variable"]
  },

  "Generic Password Variable": {
    pattern: /["']?[a-zA-Z_]+_PASSWORD["']?\s*[:=]\s*["']([^"']{8,})["']/g,
    confidence: "high",
    context: ["password", "secret", "credential"]
  },
  "PHP API Key Variable": {
    pattern: /\$api_key\s*=\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
    confidence: "high",
    context: ["api", "key", "secret", "token", "php"]
  },

  // OpenAI API keys — extremely common in frontend bundles
  // Old format: T3BlbkFJ is base64 marker present in all legacy keys
  "OpenAI API Key": {
    pattern: /sk-[a-zA-Z0-9_-]{20}T3BlbkFJ[a-zA-Z0-9_-]{20}/g,
    confidence: "high",
    context: ["openai", "gpt", "api", "chatgpt"],
    prefilter: "T3BlbkFJ"
  },
  // New project-scoped keys (since 2024)
  "OpenAI Project Key": {
    pattern: /sk-proj-[a-zA-Z0-9_-]{48,}/g,
    confidence: "high",
    context: ["openai", "gpt", "api", "key"],
    prefilter: "sk-proj-"
  },
  // Anthropic / Claude API keys
  "Anthropic API Key": {
    pattern: /sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{93,}/g,
    confidence: "high",
    context: ["anthropic", "claude", "api", "key"],
    prefilter: "sk-ant-"
  },
  // HuggingFace access tokens — common in ML frontend apps
  "HuggingFace Token": {
    pattern: /hf_[a-zA-Z0-9]{37}/g,
    confidence: "high",
    context: ["huggingface", "hf", "token", "transformers"],
    prefilter: "hf_"
  },
  // npm access token (new format since 2021)
  "npm Access Token": {
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    confidence: "high",
    context: ["npm", "registry", "token"],
    prefilter: "npm_"
  },
  // Shopify storefront and admin tokens
  "Shopify Access Token": {
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    confidence: "high",
    context: ["shopify", "store", "api", "token"],
    prefilter: "shpat_"
  },
  "Shopify Shared Secret": {
    pattern: /shpss_[a-fA-F0-9]{32}/g,
    confidence: "high",
    context: ["shopify", "webhook", "secret"],
    prefilter: "shpss_"
  },
  // Mapbox tokens — common in mapping frontend apps
  // pk.eyJ = public token, sk.eyJ = secret token (both are JWT-based)
  "Mapbox Token": {
    pattern: /[ps]k\.eyJ[a-zA-Z0-9_-]{60,}/g,
    confidence: "high",
    context: ["mapbox", "map", "token"],
    prefilter: ".eyJ"
  },
  // Airtable personal access token (new format since 2023)
  "Airtable PAT": {
    pattern: /pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}/g,
    confidence: "high",
    context: ["airtable", "api", "token"],
    prefilter: "pat"
  },
  // PlanetScale database tokens
  "PlanetScale Token": {
    pattern: /pscale_tkn_[a-zA-Z0-9_]{43}/g,
    confidence: "high",
    context: ["planetscale", "database", "token"],
    prefilter: "pscale_tkn_"
  },
  // Google OAuth client secret (service account or OAuth2 app)
  "Google OAuth Client Secret": {
    pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/g,
    confidence: "high",
    context: ["google", "oauth", "client", "secret"]
  },
  // Mailchimp API key — unique suffix format
  "Mailchimp API Key": {
    pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    confidence: "high",
    context: ["mailchimp", "email", "api", "marketing"]
  },

  // Firebase full config block — apiKey alone is public by design (like Sentry DSN),
  // but the full initializeApp config with projectId/authDomain/databaseURL enables
  // unauthorized signups and data access if Firebase Rules are misconfigured.
  "Firebase Config": {
    pattern: /(?:firebase\.initializeApp|initializeApp)\s*\(\s*\{[^}]{0,800}apiKey\s*:\s*["']([^"']{10,})["'][^}]{0,800}\}/g,
    confidence: "high",
    context: ["firebase", "initializeApp"],
    validation: (match, context) => {
      // Only flag when identifying fields are present alongside apiKey.
      // Without these, apiKey is just a public project identifier — not actionable.
      return /projectId\s*:/.test(match) ||
             /databaseURL\s*:/.test(match) ||
             /authDomain\s*:/.test(match);
    },
    prefilter: "initializeApp"
  },
  "Slack Webhook URL": {
    pattern: /(?:https?:\/\/)?hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+\/]{43,56}/g,
    confidence: "high",
    context: ["slack", "webhook", "url"],
    prefilter: "hooks.slack.com"
  },

  "SendGrid API Key": {
    pattern: /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}/g,
    confidence: "high",
    context: ["sendgrid", "email", "api"],
    prefilter: "SG."
  },

  "Algolia API Key": {
    pattern: /(?:algolia|ALGOLIA)[^"']*["']([a-zA-Z0-9]{32})["']/g,
    confidence: "high",
    context: ["algolia", "search", "api"]
  },

  "Cloudinary URL": {
    pattern: /cloudinary:\/\/[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/g,
    confidence: "high",
    context: ["cloudinary", "image", "upload"],
    prefilter: "cloudinary://"
  },

  "Elasticsearch URL": {
    pattern: /(?:elasticsearch|ELASTICSEARCH)\s*[:=]["'\s]{0,5}https?:\/\/[a-zA-Z0-9.-]+:\d+(?:\/[a-zA-Z0-9_-]+)?/g,
    confidence: "high",
    context: ["elasticsearch", "elastic", "search"],
    prefilter: "elasticsearch"
  },

  "OAuth Client Secret": {
    pattern: /client_secret["']?\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["oauth", "client", "secret", "auth"]
  },

  "Session Secret": {
    pattern: /["']?session_secret["']?\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["session", "secret", "cookie"]
  },

  "Encryption Key": {
    pattern: /["']?encryption_key["']?\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/g,
    confidence: "high",
    context: ["encryption", "key", "crypto"]
  },

  // New patterns based on gitleaks
  "Discord Bot Token": {
    pattern: /[\w.-]{0,50}?(?:discord|DISCORD)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["discord", "bot", "token"]
  },

  "Telegram Bot Token": {
    pattern: /[\w.-]{0,50}?(?:telegram|TELEGRAM)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9]{6,12}:[A-Za-z0-9_-]{32,38})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["telegram", "bot", "token"]
  },
  // Standalone: digits:AA prefix is Telegram-specific
  "Telegram Bot Token (standalone)": {
    pattern: /(?<![0-9])[0-9]{6,12}:AA[A-Za-z0-9_-]{30,36}(?![A-Za-z0-9_-])/g,
    confidence: "high",
    context: ["telegram", "bot", "token"],
    prefilter: ":AA"
  },

  "Slack Bot Token": {
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{24,36}/g,
    confidence: "high",
    context: ["slack", "bot", "token"],
    prefilter: "xoxb-"
  },

  "GitLab Personal Access Token": {
    pattern: /[\w.-]{0,50}?(?:gitlab|GITLAB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(glpat-[A-Za-z0-9_-]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["gitlab", "personal", "access", "token"],
    prefilter: "glpat-"
  },
  // Standalone: glpat- prefix is GitLab-specific
  "GitLab PAT (standalone)": {
    pattern: /glpat-[A-Za-z0-9_-]{20}/g,
    confidence: "high",
    context: ["gitlab", "token", "access"],
    prefilter: "glpat-"
  },

  "GitLab Pipeline Trigger Token": {
    pattern: /[\w.-]{0,50}?(?:gitlab|GITLAB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(glptt-[A-Za-z0-9_-]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["gitlab", "pipeline", "trigger", "token"],
    prefilter: "glptt-"
  },
  "GitLab Pipeline Trigger Token (standalone)": {
    pattern: /glptt-[A-Za-z0-9_-]{20}/g,
    confidence: "high",
    context: ["gitlab", "pipeline", "trigger"],
    prefilter: "glptt-"
  },

  "GitLab Deploy Token": {
    pattern: /[\w.-]{0,50}?(?:gitlab|GITLAB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(gldt-[A-Za-z0-9_-]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["gitlab", "deploy", "token"],
    prefilter: "gldt-"
  },
  "GitLab Deploy Token (standalone)": {
    pattern: /gldt-[A-Za-z0-9_-]{20}/g,
    confidence: "high",
    context: ["gitlab", "deploy", "token"],
    prefilter: "gldt-"
  },

  "GitLab Runner Token": {
    pattern: /[\w.-]{0,50}?(?:gitlab|GITLAB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(glrt-[A-Za-z0-9_-]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["gitlab", "runner", "token"],
    prefilter: "glrt-"
  },
  "GitLab Runner Token (standalone)": {
    pattern: /glrt-[A-Za-z0-9_-]{20}/g,
    confidence: "high",
    context: ["gitlab", "runner", "token"],
    prefilter: "glrt-"
  },

  "GitLab Deploy Key": {
    pattern: /[\w.-]{0,50}?(?:gitlab|GITLAB)(?:[ \t\w.-]{0,20})[\s'"`]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(ssh-rsa [A-Za-z0-9+/=]+)(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "high",
    context: ["gitlab", "deploy", "key", "ssh"]
  },

  // Discord: MN prefix + specific structure — standalone, no context required
  "Discord Bot Token (standalone)": {
    pattern: /[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}/g,
    confidence: "high",
    context: ["discord", "bot", "token"]
  },

  // Generic patterns - placed at the end to avoid false positives
  "Generic API Key": {
    pattern: /(?<![a-zA-Z0-9])[aA][pP][iI][-_]?[kK][eE][yY][-_]?[a-zA-Z0-9]*\s*[:=]\s*['"`]([a-zA-Z0-9_-]{32,45})['"`]/g,
    confidence: "medium",
    context: ["key", "api", "secret", "token"],
    validation: (match, context) => {
      // match is the full matched string e.g. 'api_key="abc123..."'
      const lower = match.toLowerCase();
      if (lower.includes('test') || lower.includes('example') || lower.includes('demo')) {
        return false;
      }
      // Extract value between quotes
      const m = match.match(/['"`]([a-zA-Z0-9_-]{32,45})['"`]/);
      if (!m) return false;
      return true;
    }
  },
  "Generic Secret": {
    pattern: /(?<![a-zA-Z0-9])[sS][eE][cC][rR][eE][tT][-_]?[a-zA-Z0-9]*\s*[:=]\s*['"`]([a-zA-Z0-9_-]{32,45})['"`]/g,
    confidence: "medium",
    context: ["secret", "key", "api", "token"],
    validation: (match, context) => {
      const lower = match.toLowerCase();
      if (lower.includes('test') || lower.includes('example') || lower.includes('demo')) {
        return false;
      }
      const m = match.match(/['"`]([a-zA-Z0-9_-]{32,45})['"`]/);
      if (!m) return false;
      return true;
    }
  },
  "Generic Token": {
    pattern: /(?<![a-zA-Z0-9])[tT][oO][kK][eE][nN][-_]?[a-zA-Z0-9]*\s*[:=]\s*['"`]([a-zA-Z0-9_-]{32,45})['"`]/g,
    confidence: "medium",
    context: ["token", "api", "secret", "key"],
    validation: (match, context) => {
      const lower = match.toLowerCase();
      if (lower.includes('test') || lower.includes('example') || lower.includes('demo')) {
        return false;
      }
      const m = match.match(/['"`]([a-zA-Z0-9_-]{32,45})['"`]/);
      if (!m) return false;
      return true;
    }
  }
};


// False positive patterns to exclude
export const FALSE_POSITIVE_PATTERNS = [
  // Test/Example/Demo patterns
  /AIDAAAAAAAAAAAAAAAAA/, // AWS test key
  /AKIAIOSFODNN7EXAMPLE/, // AWS example key
  /wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/, // AWS example secret (from AWS docs)
  /ghp_000000000000000000000000000000000000/, // GitHub test token
  /xoxb-000000000000-000000000000-000000000000000000000000000000000000/, // Slack test token
  /sk_test_000000000000000000000000/, // Stripe test key
  /pk_test_000000000000000000000000/, // Stripe test publishable key
  /3f4beddd-2061-49b0-ae80-6f1f2ed65b37/, // Heroku example key
  /7cd4636c-0d25-47d2-9b31-0be7ae5347ed/, // Heroku example key
  /84593b65-0ef6-4a72-891c-d351ddd50aab/, // Heroku example key
  /d38548a411a38fc85ffd3f0f5ccc57f76c0c9385/, // Example hash

  // UI text patterns that should not be detected as passwords
  /password:"Reset Password"/, // Common UI text
  /password:"Continue with Password"/, // Common UI text
  /password:"Sign In with Passkey"/, // Common UI text
  /password:"Verify Email"/, // Common UI text
  /password:"Login to Account"/, // Common UI text
  /password:"Create New Password"/, // Common UI text
  /password:"Confirm Password"/, // Common UI text
  /password:"Forgot Password"/, // Common UI text
  /password:"Change Password"/, // Common UI text
  /password:"Enter Password"/, // Common UI text
  /password:"New Password"/, // Common UI text
  /password:"Old Password"/, // Common UI text
  /password:"Current Password"/, // Common UI text
  /password:"Repeat Password"/, // Common UI text
  /password:"Password Confirmation"/, // Common UI text

  // Additional false positive patterns for comprehensive testing
  /test_key_1234567890/, // Test key pattern
  /example_secret_1234567890/, // Example secret pattern
  /demo_token_1234567890/, // Demo token pattern
  /short123/, // Too short keys
  /secret123/, // Too short secrets
  /token123/, // Too short tokens
  /mini123/, // Too short keys
  /tiny123/, // Too short secrets

  // Common UI text variations
  /"Reset Password"/, // UI text
  /"Enter Password"/, // UI text
  /"Type your password"/, // UI text
  /"Continue with Password"/, // UI text
  /"Forgot Password"/, // UI text

  // Common variable names that are not secrets
  /APP_NAME/, // Application name
  /APP_VERSION/, // Version
  /DEBUG_MODE/, // Debug flag
  /LOG_LEVEL/, // Log level
  /PORT/, // Port number

  // Timestamps and IDs
  /1640995200/, // Unix timestamp
  /12345/, // Numeric ID
  /67890/, // Numeric ID
  /11111/, // Numeric ID

  // Common strings
  /"Acme Corp"/, // Company name
  /"https:\/\/example\.com"/, // Website URL
  /"support@example\.com"/, // Email

  // Comment patterns
  /#.*API_KEY=not_a_real_key/, // Comment with fake key
  /#.*SECRET=also_not_real/, // Comment with fake secret
  /#.*JWT token example:/, // Comment with example

  // Multiline config patterns
  /api_key: not_a_real_key/, // Fake key in config
  /secret: also_not_real/, // Fake secret in config
  /token: fake_token/, // Fake token in config
];
