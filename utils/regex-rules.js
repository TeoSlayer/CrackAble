module.exports = {
    KEY_PATTERNS: {
        OPENAI_API_KEY: /sk-(?:proj-)?[a-zA-Z0-9]{48}/,
        AWS_ACCESS_KEY: /AKIA[0-9A-Z]{16}/,
        AWS_SECRET_KEY: /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/i,
        GOOGLE_API_KEY: /AIza[0-9A-Za-z\\-_]{35}/,
        GOOGLE_OAUTH: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,
        MONGODB_URI: /mongodb(\+srv)?:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@.+/,
        POSTGRES_URL: /postgres:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@.+/,
        BASIC_AUTH: /(authorization|basic)[\s:]+['"]?[a-zA-Z0-9]+:[a-zA-Z0-9]+['"]?/i,
        JWT_TOKEN: /eyJ[a-zA-Z0-9]+\.eyJ[a-zA-Z0-9]+\.([a-zA-Z0-9-_]+)/,
        TWITTER_BEARER: /AAAAAAAAA[A-Za-z0-9%]{30,}/,
        FACEBOOK_TOKEN: /EAACEdEose0cBA[0-9A-Za-z]+/,
        STRIPE_KEY: /(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24}/,
        PAYPAL_CLIENT: /[A-Za-z0-9]{64}:[A-Za-z0-9]{64}/,
        ENV_SECRETS: /(?:SECRET|TOKEN|KEY|PASSWORD)[_]*?\s*=\s*['"][a-zA-Z0-9_\-]{20,}['"]/i
    },
    WHITELIST: [],
    INSECURE_API_PATTERNS: {
        HTTP_ENDPOINT: /http:\/\/[^\s/"']+/,
        URL_API_KEY: /\?(api|access)_key=\w+/,
        BASIC_AUTH_IN_URL: /https?:\/\/[^:]+:[^@]+@/,
        EMPTY_AUTH_HEADER: /(Authorization|Bearer|Token):\s*['"]?(null|undefined|YOUR_.+|example)['"]?/i,
        DEBUG_ENDPOINTS: /\/(debug|test|sandbox|stage|v1)\//,
        PUBLIC_WRITE_ENDPOINTS: /(\/upload|\/post|\/write)(\/|\?|$)/,
        WILD_CORS: /Access-Control-Allow-Origin:\s*['"]\*['"]/,
        UNSANITIZED_INPUT: /(query|sql|exec)\s*=\s*.+\${/,
        DEFAULT_CREDS: /(username|user|password)\s*=\s*['"](admin|root|test|password)['"]/,
        API_VERSION_EXPOSURE: /v[0-9]+\/public|\/api\/v[0-9]+\//,
        WEAK_PROTOCOL: /TLSv1\.0|SSLv3|_http\._tcp/
    },
};