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

1. 🔍 **DNS Chain Traversal** → Full CNAME/NS/MX chain analysis with loop and wildcard detection.
2. 🌐 **HTTP Probing** → Status codes, headers, redirect chains, TLS cert info.
3. 🔬 **Provider Fingerprinting** → Multi-signal confidence scoring (not regex-first).
4. 💣 **Claim Verification** → Provider-specific active check (API, DNS, HTTP) to confirm vulnerability.

A domain enters stages 2–4 when a CNAME target returns NXDOMAIN, **or** when any CNAME in its chain points at a known provider. The second case catches takeovers where the provider's DNS still resolves and only the HTTP response shows the resource is unclaimed (GitHub Pages, S3, Heroku, Shopify, ...).

A takeover candidate needs a provider CNAME **plus** evidence that the resource is unclaimed: an NXDOMAIN target or the provider's unclaimed-resource page. Body pattern matching is never a standalone confirmation, and provider headers alone only identify a working deployment.

What is *not* reported:
- Names that do not exist at all (NXDOMAIN on the queried name itself).
- Resolver failures (timeouts, SERVFAIL): these appear under scan errors (`-v`), never as findings.
- Null MX records (`MX 0 .`, RFC 7505).
- Each name answered by a parent wildcard: the wildcard is reported once as `*.parent`.

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

# Add every passive OSINT source (queried in parallel)
subreaper brute -t example.com --all-sources
```

The built-in wordlist is compiled into the binary, so `brute` works from any directory and after `go install`.

### 4. Passive research
```bash
# crt.sh + all passive OSINT sources, tech detection, no active claim checks
subreaper research -t example.com

# Pick sources explicitly
subreaper research -t example.com --sources hackertarget,anubis,certspotter
```

| Source | Key |
|--------|-----|
| crt.sh, Hackertarget, URLScan.io, Wayback Machine, RapidDNS, Anubis, CertSpotter | none |
| AlienVault OTX | `OTX_API_KEY` (used automatically when set; skipped otherwise) |

`URLSCAN_API_KEY` and `CERTSPOTTER_API_KEY` are optional and raise those sources' rate limits.

### 5. Output formats
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
| `--rate-limit` | `100` | Max DNS + HTTP requests per second (`0` = unlimited) |
| `--timeout` | `10s` | Per-request timeout |
| `--retries` | `2` | Retry count on failure |
| `--resolvers` | — | File with custom DNS resolvers, one per line (`1.1.1.1` or `1.1.1.1:53`) |
| `--only-vulnerable` | `false` | Show confirmed takeover candidates only |
| `--min-severity` | `info` | Minimum severity: `info\|low\|medium\|high\|critical` |
| `--no-http` | `false` | DNS analysis only |
| `--no-verify` | `false` | Skip Stage 4 claim verification |
| `--no-color` | `false` | Disable colored output |
| `--silent` | `false` | Suppress banner and progress |
| `-v, --verbose` | `false` | Verbose output (lists scan errors) |

### Brute-specific Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-w, --wordlist` | built-in | Custom wordlist file |
| `--no-crtsh` | `false` | Skip Certificate Transparency queries |
| `--permutations` | `false` | Generate subdomain permutations |
| `--sources` | — | Comma-separated OSINT sources |
| `--all-sources` | `false` | Query all passive OSINT sources |
| `--tech-detect` | `false` | Technology fingerprinting on probed subdomains |

Flags are validated before any network work starts, and the output file is opened up front, so a typo never costs a finished scan.

## 📊 Severity Model

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | Claim check passed — resource confirmed unclaimed and vulnerable |
| **HIGH** | Takeover evidence with confidence ≥80% (e.g. provider CNAME + NXDOMAIN target, or unclaimed page + provider header); SPF `+all` |
| **MEDIUM** | Takeover evidence with confidence 60–79%, or NS record points to an NXDOMAIN nameserver |
| **LOW** | CNAME target is NXDOMAIN but the provider is unknown; MX points to an NXDOMAIN host; SPF or DMARC missing, DMARC `p=none`, SPF `?all` |
| **INFO** | Dangling CNAME into a provider that does not allow claiming names; SPF `~all`; domain verification tokens to review |

Email checks (SPF, DMARC, verification tokens) run once per registrable domain, not per subdomain.

## ☁️ Supported Providers (45+)

Statuses follow [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

**Vulnerable:** AWS S3, AWS Elastic Beanstalk, Microsoft Azure (App Service, Cloud Services,
Traffic Manager, Blob Storage, API Management, Front Door, ...), Digital Ocean, Surge.sh,
Pantheon, Read the Docs, Bitbucket, Ghost, WordPress.com, Agile CRM, Cargo Collective,
Campaign Monitor, Canny, Gemfury, Help Juice, Help Scout, JetBrains YouTrack, Ngrok,
Pingdom, Readme.io, SmartJobBoard, Strikingly, SurveySparrow, Uberflip, UptimeRobot,
Worksites, HatenaBlog, Discourse.

**Edge case** (works only in some configurations): GitHub Pages, Heroku, Netlify, Vercel,
Render, Webflow, Shopify, Tumblr, Intercom.

**Not vulnerable** (identified for cleanup, reported as INFO at most): AWS CloudFront,
Fly.io, Firebase Hosting, Fastly, Zendesk, Freshdesk, HubSpot, UserVoice, Squarespace.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check [issues page](https://github.com/MrEx-Right/SubReaper/issues).

## ⚠️ Legal Notice

SubReaper is intended for **authorized security testing only**. Using this tool against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

## 📚 References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — Community reference for takeover feasibility per provider
- [HackerOne Subdomain Takeover reports](https://hackerone.com/hacktivity?querystring=subdomain+takeover)
