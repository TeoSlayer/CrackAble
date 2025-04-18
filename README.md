# CrackAble Security Scanner

A Next.js application that crawls a given URL using Puppeteer, extracts all JavaScript (external, inline, event-handlers, eval), and scans the code for potential secrets (API keys, tokens, database URIs) and insecure API patterns (HTTP endpoints, exposed credentials, CORS misconfigurations, etc.). The UI mimics a chat interface for an intuitive, conversational scan experience.

## Features

- **Headless Puppeteer crawler** to capture:
  - External scripts
  - Inline scripts (initial & dynamic)
  - Event-handler code
  - Eval-generated scripts
- **Regex-based detection** for:
  - OpenAI, AWS, Google API keys
  - Database URIs (MongoDB, Postgres)
  - JWTs, Basic Auth, Twitter/Facebook tokens
  - Stripe/PayPal credentials
  - Generic secrets via environment-style patterns
- **Insecure API patterns** (HTTP, URL keys, default creds, etc.)
- **Per-IP rate limit** (1 scan per minute)
- **Chat-style frontend** built with Next & Tailwind CSS
- **“Show Info” panel** listing all applied regex patterns

## Installation

1. Clone the repo
2. Install dependencies
3. Run in development mode
4. Open your browser at `http://localhost:3000`

## Usage

1. Paste the target URL into the input at the bottom.
2. Hit **Scan**.
3. View findings in the chat window:
   - **Secrets Detected**: red bubbles with key type, line number, masked match
   - **API Issues Detected**: yellow bubbles with issue type, severity, match.(May not always represent a vulnerability)
4. Toggle **“Show Info”** to inspect the exact regex rules powering the scan.

## Configuration

- Regex rules live in `utils/regex-rules.js`
- Rate limiting enforced in the `pages/api/extract.js`

## Deployment

1. Ensure the hosting environment supports Puppeteer’s Chromium binary and allows `--no-sandbox`.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/...`)
3. Commit your changes (`git commit -m "feat: ..."`)
4. Push to your fork and open a PR

## License

MIT © Teoslayer
