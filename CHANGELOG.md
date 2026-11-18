# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned, not implemented yet:

- Residential, mobile or datacenter classification of the exit IP (needs an ASN data source that can be shipped or configured).
- Interactive terminal UI with live progress.
- Reading proxy lists from URLs.
- A reusable GitHub Action (`uses: quanticdata-io/proxy-checker@v0`); today a workflow example lives in `docs/github-action.yml`.

## [0.1.0] - 2026-11-18

### Added

- `proxy-checker` command: checks HTTP, HTTPS (TLS to the proxy), SOCKS4/4a and SOCKS5 proxies from arguments, files or stdin.
- Proxy formats `host:port`, `user:pass@host:port`, `host:port:user:pass`, `scheme://user:pass@host:port`, IPv6 literals, percent-encoded credentials.
- Checks: reachability, success rate, connect time, time to first byte, p50/p95 latency, exit IP, country/region/city, `--expect-country`, `--expect-rotation`, `--expect-sticky`, `--min-success`, target URL with `--expect-status` and `--expect-text`, anonymity level through a header echo.
- Output as table, JSON (with summary), JSON Lines and CSV; `--save-pass`; `--fail-under` exit code for CI; passwords masked by default.
- `proxy-checker quanticdata`: lists QuanticData proxy plans and checks freshly generated proxy strings.
- Go packages `pkg/proxy` (parsing) and `pkg/checker` (checks) for use as a library.
- Local lab (`examples/locallab`) with an IP echo, HTTP proxies and a SOCKS proxy on 127.0.0.1.

[Unreleased]: https://github.com/quanticdata-io/proxy-checker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quanticdata-io/proxy-checker/releases/tag/v0.1.0
