# Changelog

All notable changes to this project will be documented in this file.


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
