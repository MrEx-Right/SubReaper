<h1 align="center">
  <br>
  SubReaper
  <br>
</h1>

<h4 align="center">A Go CLI tool for detecting dangling subdomains and subdomain takeover vulnerabilities.</h4>

<p align="center">
  <a href="https://github.com/MrEx-Right/SubReaper/releases"><img src="https://img.shields.io/badge/version-2.0.0-red.svg" alt="Version 2.0.0"></a>
  <a href="https://go.dev/doc/install"><img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg" alt="Go 1.25+"></a>
  <a href="https://github.com/MrEx-Right/SubReaper/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/MrEx-Right/SubReaper/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

<p align="center">
  <a href="#-what-it-does">What It Does</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-severity-model">Severity Model</a> •
  <a href="#-license">License</a>
</p>

---

## 🎯 What It Does

**SubReaper** finds subdomains that point to cloud services no longer under the control of the target organization, a condition known as a *dangling DNS record* or *subdomain takeover*. An attacker who claims the abandoned resource can serve content on the victim's subdomain, steal cookies, bypass CSP or phish users.

## ✨ Key Features

- **Evidence-based findings:** a takeover is only reported when the CNAME points at a known provider *and* there is proof the resource is unclaimed (an NXDOMAIN target or the provider's unclaimed-resource page).
- **Catches resolving takeovers:** GitHub Pages, S3, Heroku, Shopify and similar cases are probed even when the provider's DNS still resolves.
- **Active verification:** provider-specific claim checks (DNS, HTTP, API) confirm whether a resource can really be claimed.
- **Low noise:** names that don't exist, resolver failures, null MX records and wildcard duplicates are never reported as findings.
- **45+ providers:** each tagged *vulnerable*, *edge case* or *not vulnerable* following [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).
- **Built-in discovery:** crt.sh, 7 more passive OSINT sources queried in parallel, an embedded wordlist and permutations.
- **Rich output:** colored terminal output, JSON, Markdown and HTML reports.
- **Fast and polite:** concurrent workers with a request-level rate limit shared by DNS and HTTP, and Ctrl+C returns partial results right away.

## 🔧 How It Works

SubReaper runs a **four-stage verification pipeline** per target:

1. 🔍 **DNS Chain Traversal** → Full CNAME/NS/MX chain analysis with loop and wildcard detection.
2. 🌐 **HTTP Probing** → Status codes, headers, redirect chains, TLS certificate info.
3. 🔬 **Provider Fingerprinting** → Multi-signal confidence scoring (not regex-first).
4. 💣 **Claim Verification** → Provider-specific active check to confirm the resource is unclaimed.

A domain enters stages 2–4 when a CNAME target returns NXDOMAIN, **or** when any CNAME in its chain points at a known provider. The second case catches takeovers where the provider's DNS still resolves and only the HTTP response shows the resource is unclaimed.

Body pattern matching is never a standalone confirmation, and provider headers alone only identify a working deployment.

What is *not* reported:
- Names that do not exist at all (NXDOMAIN on the queried name itself).
- Resolver failures (timeouts, SERVFAIL): these appear under scan errors (`-v`), never as findings.
- Null MX records (`MX 0 .`, RFC 7505).
- Each name answered by a parent wildcard: the wildcard is reported once as `*.parent`.

## 📦 Installation

Requires **Go 1.25+**.

```bash
# Build from source
git clone https://github.com/MrEx-Right/SubReaper.git
cd SubReaper
make build            # or: go build -o subreaper .
```

```bash
# Or install with go install
go install github.com/MrEx-Right/SubReaper@main
```

Use `@main` for v2: `@latest` still resolves to v1.0.0.

Check the installed version with `subreaper --version`.

## 🚀 Usage

### 1. Scan a single domain
```bash
subreaper scan -t example.com
```

### 2. Scan a list of domains
```bash
subreaper scan -l targets.txt --only-vulnerable
```

### 3. Discover subdomains, then scan
```bash
# crt.sh (Certificate Transparency) + built-in wordlist
subreaper brute -t example.com

# Custom wordlist + permutation generation
subreaper brute -t example.com -w /path/to/wordlist.txt --permutations

# Add every passive OSINT source (queried in parallel)
subreaper brute -t example.com --all-sources
```

The built-in wordlist is compiled into the binary, so `brute` works from any directory.

### 4. Passive research
```bash
# crt.sh + all passive OSINT sources, tech detection, no active claim checks
subreaper research -t example.com

# Pick sources explicitly
subreaper research -t example.com --sources hackertarget,anubis,certspotter
```

### 5. Output formats
```bash
subreaper scan -t example.com --json -o results.json
subreaper scan -t example.com -f markdown -o report.md
subreaper scan -t example.com -f html -o report.html
```

## 🛰️ OSINT Sources

| Source | API key |
|--------|---------|
| crt.sh, Hackertarget, URLScan.io, Wayback Machine, RapidDNS, Anubis, CertSpotter | none |
| AlienVault OTX | `OTX_API_KEY` (used automatically when set, skipped otherwise) |

| Environment variable | Effect |
|----------------------|--------|
| `OTX_API_KEY` | Enables AlienVault OTX |
| `URLSCAN_API_KEY` | Optional, raises the URLScan.io rate limit |
| `CERTSPOTTER_API_KEY` | Optional, raises the CertSpotter rate limit |

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
| `-V, --only-vulnerable` | `false` | Show confirmed takeover candidates only |
| `--min-severity` | `info` | Minimum severity: `info\|low\|medium\|high\|critical` |
| `--no-http` | `false` | DNS analysis only |
| `--no-verify` | `false` | Skip Stage 4 claim verification |
| `--no-color` | `false` | Disable colored output |
| `--silent` | `false` | Suppress banner and progress |
| `-v, --verbose` | `false` | Verbose output (lists scan errors) |
| `--version` | — | Print the version |

### `scan` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Single target domain |
| `-l, --list` | — | File with one domain per line |

### `brute` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target domain (required) |
| `-w, --wordlist` | built-in | Custom wordlist file |
| `--no-crtsh` | `false` | Skip Certificate Transparency queries |
| `--permutations` | `false` | Generate subdomain permutations |
| `--sources` | — | Comma-separated OSINT sources |
| `--all-sources` | `false` | Query all passive OSINT sources |
| `--tech-detect` | `false` | Technology fingerprinting on probed subdomains |

### `research` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target domain (required) |
| `--all-sources` | `true` | Query all passive OSINT sources |
| `--sources` | — | Comma-separated OSINT sources (overrides `--all-sources`) |
| `--no-crtsh` | `false` | Skip Certificate Transparency queries |
| `-w, --wordlist` | — | Also run wordlist bruteforce with this file |
| `--no-wordlist` | `false` | Skip the wordlist even when `--wordlist` is given |
| `--tech-detect` | `true` | Technology fingerprinting |

`research` is passive: it never runs active claim checks.

Flags are validated before any network work starts, and the output file is opened up front, so a typo never costs a finished scan.

## 📊 Severity Model

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | Claim check passed: resource confirmed unclaimed and vulnerable |
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

## 🛠️ Development

```bash
make test        # unit tests with the race detector
make vet         # go vet
make build-all   # cross-compile for Linux, Windows and macOS
```

The tests use an in-process DNS server, so they need no network access.

## 🤝 Contributing

Contributions, issues and feature requests are welcome. See the [issues page](https://github.com/MrEx-Right/SubReaper/issues).

## ⚠️ Legal Notice

SubReaper is intended for **authorized security testing only**. Using this tool against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

## 📄 License

SubReaper is released under the [MIT License](LICENSE).

## 📚 References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz): community reference for takeover feasibility per provider
- [HackerOne subdomain takeover reports](https://hackerone.com/hacktivity?querystring=subdomain+takeover)
- [CHANGELOG](CHANGELOG.md): release history
