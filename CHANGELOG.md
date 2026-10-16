# Changelog

All notable changes to this project will be documented in this file.


## [2.0.0] - 2026-10-16

### Breaking
- Severities changed (see the Severity Model in the README). Dangling NS is MEDIUM, SPF `~all` and verification tokens are INFO, and dangling CNAMEs into providers that are not vulnerable are INFO.
- SPF, DMARC and verification-token findings are reported once, on the registrable domain (for example `example.com`), not on every subdomain.
- A dangling wildcard is reported once, as `*.parent`, instead of once per name.
- `--rate-limit` now caps DNS + HTTP requests per second, not domains per second, so scans with the same value run slower.
- `research --no-wordlist` now defaults to `false` and only takes effect when you also pass `--wordlist`.
- AlienVault OTX needs `OTX_API_KEY` and is skipped without it.

### Fixed
- **Detection**: domains whose CNAME points at a known provider are now probed and fingerprinted even when the provider's DNS still resolves, so GitHub Pages, S3, Heroku, Shopify and similar takeovers are no longer missed.
- **Fingerprinting**: an NXDOMAIN provider target now counts as evidence, so HIGH and CRITICAL findings can actually be reached. A takeover needs a provider CNAME plus evidence (NXDOMAIN target or unclaimed-resource page); headers alone only identify a working deployment. Duplicate signals from several probes are counted once.
- **False positives**: names that do not exist, resolver timeouts/SERVFAIL, null MX records and unresolved (but not NXDOMAIN) NS/MX hosts are no longer reported as dangling.
- **Email checks**: SPF/DMARC/verification tokens are analysed once per registrable domain (public suffix aware) instead of on every subdomain; verification tokens are grouped into one INFO finding; SPF `~all` is INFO.
- **Claim checks**: network errors are no longer treated as "claimable"; checks use the scanner's resolvers and require the provider's unclaimed-resource response.
- **Engine**: fixed a permanent hang when a scan with more than 64 workers was cancelled; Ctrl+C now interrupts in-flight DNS queries immediately and reports partial results.
- **Resolvers**: entries without a port (`8.8.8.8`) get `:53`; invalid entries are rejected up front; `--resolvers` now works for `brute` and `research` too.
- **CLI**: `--format`, `--min-severity`, `--sources` and the output path are validated before scanning; `research --no-wordlist` is honoured; `--rate-limit` now limits DNS and HTTP requests rather than domains.
- **Wordlist**: the built-in wordlist is embedded in the binary.
- **OSINT**: sources run in parallel; Anubis moved to anubisdb.com; RapidDNS results are parsed from HTML; Wayback returns partial results on slow responses; CertSpotter paginates; AlienVault OTX requires `OTX_API_KEY` and is skipped without it.
- **Wildcards**: wildcard detection now probes the parent zone and reports a dangling wildcard once as `*.parent`.

### Changed
- Provider database updated against can-i-take-over-xyz: providers carry a vulnerable / edge case / not vulnerable status, outdated fingerprints were corrected, Heroku's `herokudns.com` was added, and 17 vulnerable services were added.
- New startup banner with a scythe, the version and a tagline; it adapts to the terminal width and stays plain when output is redirected. `--version` prints the version.
- Reports now include resolved IPs, HTTP probe status, technologies, TXT records, provider status, claim URL and scan errors.

### Added
- Unit tests with an in-process DNS server for the resolver, pipeline, engine, providers and discovery packages.

## [1.0.0] - 2026-07-25

### Added
- **Core Engine**: High-performance, concurrent execution architecture with configurable rate limiting, timeouts, and retry logic.
- **Verification Pipeline**: Implemented a robust 4-stage pipeline to eliminate false positives:
  - *Stage 1 (DNS)*: Full CNAME/NS/MX chain resolution with loop detection.
  - *Stage 2 (HTTP)*: Probing for status codes, headers, redirects, and TLS information.
  - *Stage 3 (Fingerprinting)*: Multi-signal confidence scoring across 30+ major cloud providers (AWS, Azure, GitHub Pages, Vercel, Netlify, etc.).
  - *Stage 4 (Verification)*: Active claim checks (API, DNS, HTTP) to definitively confirm resource vulnerability.
- **CLI Commands**:
  - `scan`: Scan specific targets or bulk lists of domains.
  - `brute`: Actively discover subdomains using crt.sh scraping and built-in wordlists with permutation support.
  - `research`: Passive OSINT-first subdomain research functionality.
- **Reporting System**: Beautiful colored terminal output, alongside structured exports for JSON, Markdown, and HTML reports.
- **Severity Model**: Automated threat scoring (INFO, LOW, MEDIUM, HIGH, CRITICAL) based on confidence levels and active claim status.
- **Customization**: Full support for custom DNS resolvers, user-provided wordlists, and silent operation modes for CI/CD integration.
- **CLI Experience**: Auto-generated completions, rich ASCII banners, and comprehensive help menus.

### Security
- Shifted the paradigm from legacy "regex-only" matching to contextual multi-signal verification to prevent false assumptions on unclaimed resources.
