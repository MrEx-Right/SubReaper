<h1 align="center">
  <br>
  SubReaper
  <br>
</h1>

<h4 align="center">A professional-grade Go CLI tool for detecting dangling subdomains and subdomain takeover vulnerabilities.</h4>

<p align="center">
  <a href="https://golang.org/doc/install"><img src="https://img.shields.io/badge/Made%20with-Go-1f425f.svg" alt="Made with Go"></a>
  <a href="https://github.com/MrEx-Right/SubReaper/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPL%203.0-blue.svg" alt="License: AGPL 3.0"></a>
  <a href="https://github.com/MrEx-Right/SubReaper/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

<p align="center">
  <a href="#what-it-does">What It Does</a> •
  <a href="#key-features">Features</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#severity-model">Severity Model</a>
</p>

---

## 🎯 What It Does

**SubReaper** identifies subdomains that point to cloud services no longer under the control of the target organization — a condition known as a *dangling DNS record* or *subdomain takeover*. An attacker who claims the unclaimed resource can then serve content on the victim's subdomain, intercept cookies, bypass CSP, or phish users.

## ✨ Key Features

- **Blazing Fast:** Written in Go with high concurrency and optimized DNS resolution.
- **Low False Positives:** Uses a multi-stage verification pipeline to ensure accurate findings.
- **Active Verification:** Actually verifies if a cloud resource can be claimed, instead of relying purely on regex patterns.
- **Rich Output:** Supports beautiful colored terminal output, JSON, Markdown, and HTML reports.
- **Built-in OSINT:** Built-in crt.sh scraping and wordlist generation for active subdomain discovery.
- **Broad Coverage:** Supports fingerprinting for over 30+ major cloud providers.

## ⚙️ How It Works

Unlike legacy tools that simply pattern-match HTTP response bodies, SubReaper runs a **four-stage verification pipeline** per target:

1. 🔍 **DNS Chain Traversal** → Full CNAME/NS/MX chain analysis with loop detection.
2. 🌐 **HTTP Probing** → Status codes, headers, redirect chains, TLS cert info.
3. 🔬 **Provider Fingerprinting** → Multi-signal confidence scoring (not regex-first).
4. 💣 **Claim Verification** → Provider-specific active check (API, DNS, HTTP) to confirm vulnerability.

A finding requires consistent evidence across multiple independent signals before it's reported. Body pattern matching is a *contributing* signal, never a standalone confirmation.

## 📦 Installation

Ensure you have **Go 1.20+** installed.

```bash
# Build from source
git clone https://github.com/MrEx-Right/SubReaper.git
cd subreaper
go mod tidy
go build -o subreaper .

# Or install directly via go install
go install github.com/MrEx-Right/SubReaper@latest
```

## 🚀 Usage

### 1. Scan a single domain
```bash
subreaper scan -t example.com
```

### 2. Scan a list of domains
```bash
subreaper scan -l targets.txt --only-vulnerable
```

### 3. Discover subdomains then scan
```bash
# Uses crt.sh (Certificate Transparency) by default + built-in wordlist
subreaper brute -t example.com

# Custom wordlist + permutation generation
subreaper brute -t example.com -w /path/to/wordlist.txt --permutations
```

### 4. Output formats
```bash
subreaper scan -t example.com --json -o results.json
subreaper scan -t example.com -f markdown -o report.md
subreaper scan -t example.com -f html -o report.html
```

## 🚩 Flags

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format` | `terminal` | Output format: `terminal\|json\|markdown\|html` |
| `-j, --json` | `false` | Shorthand for `--format json` |
| `-o, --output` | `stdout` | Write output to file |
| `-c, --concurrency` | `50` | Concurrent workers |
| `--rate-limit` | `100` | Max requests per second |
| `--timeout` | `10s` | Per-request timeout |
| `--retries` | `2` | Retry count on failure |
| `--resolvers` | — | File with custom DNS resolvers |
| `--only-vulnerable` | `false` | Show confirmed takeover candidates only |
| `--min-severity` | `info` | Minimum severity: `info\|low\|medium\|high\|critical` |
| `--no-http` | `false` | DNS analysis only |
| `--no-verify` | `false` | Skip Stage 4 claim verification |
| `--no-color` | `false` | Disable colored output |
| `--silent` | `false` | Suppress banner and progress |
| `-v, --verbose` | `false` | Verbose output |

### Brute-specific Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-w, --wordlist` | built-in | Custom wordlist file |
| `--no-crtsh` | `false` | Skip Certificate Transparency queries |
| `--permutations` | `false` | Generate subdomain permutations |

## 📊 Severity Model

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | Claim check passed — resource confirmed unclaimed and vulnerable |
| **HIGH** | Provider identified with confidence ≥80%, no active claim check available |
| **MEDIUM** | Provider identified with confidence 60–79%, or NS record is dangling |
| **LOW** | DNS dangling confirmed, but provider is unknown |
| **INFO** | Possible issue (IP unresponsive, MX dangling, wildcard detected) |

## ☁️ Supported Providers (30+)

AWS S3, AWS CloudFront, AWS Elastic Beanstalk, Azure Web Apps, Azure Blob Storage,
Azure Traffic Manager, GitHub Pages, Heroku, Netlify, Vercel, Render, Fly.io,
DigitalOcean App Platform, Webflow, Firebase Hosting, Fastly, Shopify, Tumblr,
Ghost, Zendesk, Freshdesk, HubSpot, Surge.sh, Pantheon, Read the Docs,
Bitbucket Pages, UserVoice, Intercom, WordPress.com, Squarespace, Cargo Collective,
Agile CRM.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check [issues page](https://github.com/MrEx-Right/SubReaper/issues).

## ⚠️ Legal Notice

SubReaper is intended for **authorized security testing only**. Using this tool against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

## 📚 References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — Community reference for takeover feasibility per provider
- [HackerOne Subdomain Takeover reports](https://hackerone.com/hacktivity?querystring=subdomain+takeover)
