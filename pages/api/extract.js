import puppeteer from "puppeteer";
import { KEY_PATTERNS, WHITELIST, INSECURE_API_PATTERNS } from '../../utils/regex-rules.js';

const MAX_BROWSERS = 8;
const BROWSER_TIMEOUT = 30000;
const PAGE_TIMEOUT = 20000;
const RATE_LIMIT_WINDOW = 60000;

const browserPool = {
    instances: [],
    pending: [],
    activeCount: 0,

    async getBrowser() {
        if (this.instances.length > 0) {
            return this.instances.pop();
        }

        if (this.activeCount < MAX_BROWSERS) {
            this.activeCount++;
            try {
                return await puppeteer.launch({
                    headless: true,
                    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser',
                    args: [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--single-process'
                    ],
                    timeout: BROWSER_TIMEOUT
                });
            } catch (error) {
                this.activeCount--;
                throw error;
            }
        }

        return new Promise(resolve => this.pending.push(resolve));
    },

    releaseBrowser(browser) {
        if (this.pending.length > 0) {
            const resolve = this.pending.shift();
            resolve(browser);
        } else {
            this.instances.push(browser);
        }
    }
};

const rateLimitMap = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamp] of rateLimitMap.entries()) {
        if (now - timestamp > RATE_LIMIT_WINDOW * 2) {
            rateLimitMap.delete(ip);
        }
    }
}, 3600000);


function scanForSecurityIssues(content) {
    const secretFindings = scanForSecrets(content);
    const apiFindings = [];

    const lines = content.split('\n');

    lines.forEach((line, lineNumber) => {
        for (const [issueType, pattern] of Object.entries(INSECURE_API_PATTERNS)) {
            const matches = line.match(pattern) || [];

            matches.forEach(match => {
                apiFindings.push({
                    line: lineNumber + 1,
                    issueType,
                    match: match,
                    context: getContext(lines, lineNumber),
                    severity: getApiIssueSeverity(issueType)
                });
            });
        }
    });

    return {
        secrets: secretFindings,
        apiIssues: apiFindings
    };
}

function scanForSecrets(content) {
    const findings = [];
    const lines = content.split('\n');

    lines.forEach((line, lineNumber) => {
        for (const [keyType, pattern] of Object.entries(KEY_PATTERNS)) {
            const regex = new RegExp(pattern.source, pattern.flags);
            const matches = line.match(regex) || [];

            matches.forEach(match => {
                if (WHITELIST.some(w => w.test(match))) return;

                findings.push({
                    line: lineNumber + 1,
                    keyType,
                    match: match,
                    context: getContext(lines, lineNumber)
                });
            });
        }
    });

    return findings;
}

function getApiIssueSeverity(issueType) {
    const severityMap = {
        HTTP_ENDPOINT: 'critical',
        URL_API_KEY: 'high',
        BASIC_AUTH_IN_URL: 'critical',
        WILD_CORS: 'medium',
        DEFAULT_CREDS: 'high',
    };
    return severityMap[issueType] || 'low';
}

function anonymizeMatch(match) {
    // For pussies ... I'll let it roll without it for now
    return match
        .replace(/[a-zA-Z0-9]{4,}/g, match =>
            match.substring(0, 3) + '*'.repeat(match.length - 3)
        );
}

function getContext(lines, lineNumber, contextLines = 2) {
    const start = Math.max(0, lineNumber - contextLines);
    const end = Math.min(lines.length - 1, lineNumber + contextLines);
    return lines.slice(start, end + 1).join('\n');
}

export default async function handler(req, res) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();

    if (rateLimitMap.has(ip) && now - rateLimitMap.get(ip) < RATE_LIMIT_WINDOW) {
        return res.status(429).json({ error: 'Too many requests. Please wait 1 minute between scans.' });
    }
    rateLimitMap.set(ip, now);

    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });

        const browser = await browserPool.getBrowser();
        const page = await browser.newPage();

        try {
            await page.setDefaultNavigationTimeout(PAGE_TIMEOUT);
            const scripts = await collectScripts(page, url);
            const securityReport = scanForSecurityIssues(scripts);

            const compressedResults = {
                secrets: securityReport.secrets.map(secret => ({
                    line: secret.line,
                    keyType: secret.keyType,
                    snippet: secret.match,
                    context: secret.context,
                })),
                apiIssues: securityReport.apiIssues.map(issue => ({
                    line: issue.line,
                    issueType: issue.issueType,
                    severity: issue.severity,
                    snippet: truncateSnippet(issue.match, 40)
                })),
                metadata: {
                    scannedUrl: url,
                    scannedAt: new Date().toISOString(),
                    totalSecrets: securityReport.secrets.length,
                    totalApiIssues: securityReport.apiIssues.length
                }
            };


            res.json({
                success: true,
                ...compressedResults
            });

        } finally {
            await page.close().catch(() => { });
            browserPool.releaseBrowser(browser);
        }
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            error: error.message || 'An error occurred during the scan'
        });
    }
}

function truncateSnippet(text, maxLength = 40) {
    if (text.length <= maxLength) return anonymizeMatch(text);
    return text.substring(0, maxLength) + '...';
}

async function collectScripts(page, url) {
    const scripts = {
        external: [],
        inline: [],
        handlers: [],
        dynamic: []
    };

    await page.setRequestInterception(true);
    page.on('request', handleRequest(scripts));
    page.on('response', handleResponse(scripts));

    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForNetworkIdle({ idleTime: 2000 });

    const [inlineScripts, handlers, evalScripts] = await Promise.all([
        collectInlineScripts(page),
        collectEventHandlers(page),
        collectEvalScripts(page)
    ]);

    scripts.inline = inlineScripts;
    scripts.handlers = handlers;
    scripts.dynamic = evalScripts;

    return [
        ...scripts.external.filter(s => s.status === 'loaded').map(s => s.content),
        ...scripts.inline.map(s => s.content),
        ...scripts.handlers.map(h => h.handler),
        ...scripts.dynamic.map(s => s.content)
    ].join('\n');
}

const handleRequest = (scripts) => (request) => {
    if (request.resourceType() === 'script') {
        scripts.external.push({
            url: request.url(),
            status: 'pending',
            content: null
        });
    }
    request.continue();
};

const handleResponse = (scripts) => async (response) => {
    if (response.request().resourceType() === 'script') {
        const script = scripts.external.find(s => s.url === response.url());
        if (script) {
            try {
                script.content = await response.text();
                script.status = 'loaded';
            } catch (error) {
                script.status = 'error';
                script.error = error.message;
            }
        }
    }
};

async function collectInlineScripts(page) {
    const scripts = await page.$$eval('script', allScripts =>
        allScripts.map(script => ({
            isDynamic: !script.hasAttribute('data-initial'),
            src: script.src || null,
            content: script.innerHTML
        }))
    );
    return scripts
        .filter(script => !script.src)
        .map(script => ({
            type: script.isDynamic ? 'dynamic-inline' : 'initial-inline',
            content: script.content
        }));
}

async function collectEventHandlers(page) {
    return page.$$eval('*', elements =>
        elements.flatMap(element =>
            Array.from(element.attributes)
                .filter(attr => attr.name.startsWith('on'))
                .map(attr => ({
                    tag: element.tagName.toLowerCase(),
                    event: attr.name,
                    handler: attr.value
                }))
        )
    );
}

async function collectEvalScripts(page) {
    const evalContent = await page.evaluate(() =>
        Array.from(document.querySelectorAll('script[data-eval]'))
            .map(script => script.innerHTML)
    );
    return evalContent.map(content => ({
        type: 'eval-generated',
        content
    }));
}
