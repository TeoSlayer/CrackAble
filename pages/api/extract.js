import puppeteer from "puppeteer";
import { KEY_PATTERNS, WHITELIST, INSECURE_API_PATTERNS } from '../../utils/regex-rules.js';

const rateLimitMap = new Map();

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
    const lastRequest = rateLimitMap.get(ip) || 0;
    const now = Date.now();
    if (now - lastRequest < 60_000) {
        return res.status(429).json({ error: 'Too many requests. Please chill. You have 1(one) per minute. Let some go around...' });
    }
    rateLimitMap.set(ip, now);

    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });

        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        const page = await browser.newPage();
        const scripts = {
            external: [],
            inline: [],
            handlers: [],
            dynamic: []
        };

        await page.setRequestInterception(true);
        page.on('request', request => {
            if (request.resourceType() === 'script') {
                scripts.external.push({
                    url: request.url(),
                    status: 'pending',
                    content: null
                });
            }
            request.continue();
        });

        page.on('response', async response => {
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
        });

        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

        await page.waitForNetworkIdle({ idleTime: 2000, timeout: 30000 });

        const currentScripts = await page.$$eval('script', allScripts =>
            allScripts.map(script => ({
                isDynamic: !script.hasAttribute('data-initial'),
                src: script.src || null,
                content: script.innerHTML
            }))
        );

        scripts.inline = currentScripts
            .filter(script => !script.src)
            .map(script => ({
                type: script.isDynamic ? 'dynamic-inline' : 'initial-inline',
                content: script.content
            }));

        scripts.handlers = await page.$$eval('*', elements =>
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

        const evalScripts = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('script[data-eval]'))
                .map(script => script.innerHTML);
        });

        scripts.dynamic = evalScripts.map(content => ({
            type: 'eval-generated',
            content
        }));

        const allScripts = [
            ...scripts.external.filter(script => script.status === 'loaded').map(script => script.content),
            ...scripts.inline.map(script => script.content),
            ...scripts.handlers.map(handler => handler.handler),
            ...scripts.dynamic.map(script => script.content)
        ].join('\n');

        if (!allScripts || allScripts.length === 0) {
            throw new Error('No JavaScript content found');
        }

        const securityReport = scanForSecurityIssues(allScripts);

        await browser.close();

        res.json({
            success: true,
            ...securityReport,
            scannedUrl: url,
            scannedAt: new Date().toISOString()
        });

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            error: error.message || 'An error occurred during the scan'
        });
    }
}
