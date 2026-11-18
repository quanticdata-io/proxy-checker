# proxy-checker

[![CI](https://github.com/quanticdata-io/proxy-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/quanticdata-io/proxy-checker/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/quanticdata-io/proxy-checker.svg)](https://pkg.go.dev/github.com/quanticdata-io/proxy-checker)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast, single-binary proxy checker for HTTP, HTTPS, SOCKS4 and SOCKS5 proxies.
Give it any proxy list and it tells you, per proxy:

- **does it work**: reachability, success rate over N requests, a clear error when it does not (timeout, refused, 407);
- **how fast**: connect time, time to first byte, p50 and p95 latency;
- **where it exits**: exit IP, country, region and city, with an `--expect-country` assertion;
- **does it rotate or stick**: unique exit IPs over N requests, with `--expect-rotation` and `--expect-sticky` assertions for rotating gateways and sticky sessions;
- **how anonymous it is**: transparent, anonymous or elite, from the headers a target receives;
- **does it open the site you care about**: `--target URL --expect-text "..."`.

Output as a table, JSON, JSON Lines or CSV, keep only the working proxies with `--save-pass`, and gate CI with `--fail-under`.

It works with any proxy provider and any public or private list. It has no dependencies outside the Go standard library.

## Install

```sh
go install github.com/quanticdata-io/proxy-checker/cmd/proxy-checker@latest
```

Prebuilt binaries for Linux, macOS and Windows (amd64, arm64) are attached to each [release](https://github.com/quanticdata-io/proxy-checker/releases). A container image can be built from the `Dockerfile`.

## Quickstart

Check proxies passed as arguments, from a file, or piped on stdin:

```sh
proxy-checker 203.0.113.7:3128 socks5://user:pass@198.51.100.4:1080
proxy-checker -f proxies.txt
cat proxies.txt | proxy-checker --csv > report.csv
```

```
PROXY                                RESULT  OK   P50    P95    EXIT IP       IPS  COUNTRY          ANON  NOTE
http://user:xxxxx@gw.example.net:80  PASS    3/3  412ms  530ms  203.0.113.21  3    US New York      -
socks5://198.51.100.4:1080           FAIL    0/3  -      -      -             0    -                -     unreachable: timeout

2 checked, 1 passed, 1 failed (50.0% pass), 3 unique exit IPs, median p50 412ms, countries: US 1
```

Passwords are masked in every output format unless you pass `--show-credentials`.

### Try it without any proxy

The repository ships a local lab (an IP echo, two HTTP proxies and a SOCKS proxy, all on 127.0.0.1) so every feature can be tried offline:

```sh
git clone https://github.com/quanticdata-io/proxy-checker && cd proxy-checker
go run ./examples/locallab          # leave it running, open a second terminal
go run ./cmd/proxy-checker --echo-url http://127.0.0.1:18081/ip demo:demo@127.0.0.1:18080 127.0.0.1:18083 socks5://demo:demo@127.0.0.1:18082
go run ./cmd/proxy-checker --echo-url http://127.0.0.1:18081/ip -n 5 --expect-rotation demo:demo@127.0.0.1:18080
go run ./cmd/proxy-checker --echo-url http://127.0.0.1:18081/ip -n 5 --expect-sticky --expect-country DE 127.0.0.1:18083
go run ./cmd/proxy-checker --echo-url http://127.0.0.1:18081/ip --headers-url http://127.0.0.1:18081/headers 127.0.0.1:18083
```

## Proxy formats

One proxy per line; blank lines and lines starting with `#` are ignored, unparseable lines are reported on stderr and skipped.

| Format | Example |
|---|---|
| `host:port` | `203.0.113.7:3128` |
| `user:pass@host:port` | `user:pass@gw.example.net:8080` |
| `host:port:user:pass` | `gw.example.net:8080:user:pass` |
| `scheme://[user:pass@]host:port` | `socks5://user:pass@198.51.100.4:1080` |

Schemes: `http`, `https` (TLS to the proxy), `socks4`, `socks4a`, `socks5`, `socks5h`. Lines without a scheme use `--protocol` (default `http`). Credentials may be percent-encoded; a password may contain `:` or `@`.

## What is checked

Each proxy gets `-n` requests (default 3) to an **IP echo** endpoint over a fresh connection each time, so a rotating gateway shows its rotation. Then, if configured, one request to `--target` and one to `--headers-url`.

| Check | Flag | Fails the proxy when |
|---|---|---|
| Reachability | always | no request succeeded |
| Success rate | `--min-success 80` | fewer than 80% of the requests succeeded |
| Exit country | `--expect-country US` | the echo reports another country |
| Rotation | `-n 10 --expect-rotation` | one exit IP for all requests |
| Sticky session | `-n 10 --expect-sticky` | the exit IP changed |
| Target site | `--target URL [--expect-status 200] [--expect-text STR]` | wrong status or text missing |
| Anonymity | `--headers-url URL [--real-ip IP or --detect-real-ip]` | never fails; reports `transparent`, `anonymous` or `elite` |

A request succeeds when the proxy answers and the destination returns 2xx or 3xx.

### The IP echo

By default the exit IP and location come from `https://api.quanticdata.io/v1/public/ip-echo`, a free endpoint that needs no account or API key and is never cached. It answers with the IP the request came from and where Cloudflare places it (country, region, city, timezone), which is how most websites locate their visitors. Any other echo service works with `--echo-url`: the checker reads the common shapes (`ip`, `origin`, `query`; `countryCode`, `country_code`, `country`; `region`, `regionName`; `city`) and plain-text answers holding just an IP. With `--no-echo --target URL` the attempts go to your target instead and no IP or country is reported.

### Anonymity, honestly

Anonymity is about the headers a proxy adds (`Via`, `X-Forwarded-For`, `Forwarded`, ...). It can only be observed on a **plain `http://` header-echo endpoint**: over HTTPS the proxy only relays an encrypted tunnel and cannot add headers, so every working proxy looks elite. The default IP echo does not return headers, so this check runs only when you pass `--headers-url` pointing to an httpbin-style endpoint (answering `{"headers": {...}}`) that you trust. To tell transparent from anonymous, the checker needs your own IP: pass `--real-ip` or `--detect-real-ip` (one direct request to the echo URL).

## Output

| Flag | Output |
|---|---|
| (default) | aligned table and a summary line |
| `--json` | `{"summary": {...}, "results": [...]}`; add `--details` for every attempt |
| `--jsonl` | one result per line, for streaming into other tools |
| `--csv` | one row per proxy (columns listed in [`internal/report`](internal/report/report.go)) |
| `--save-pass FILE` | the proxies that passed, one URL per line (credentials included, file mode 0600) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | the run completed (and met `--fail-under` when given) |
| 1 | fewer proxies passed than `--fail-under PERCENT` |
| 2 | bad flags or no proxies to check |
| 3 | runtime error (I/O, API error, interrupted) |

## Use it in CI

Fail a pipeline when less than 90% of a proxy pool works, and keep the CSV as an artifact:

```sh
proxy-checker -f proxies.txt --expect-country US --fail-under 90 --csv > proxy-report.csv
```

[`docs/github-action.yml`](docs/github-action.yml) is a ready scheduled GitHub Actions workflow that checks a list every 6 hours and commits the report.

## QuanticData proxies

If you use QuanticData residential, mobile, ISP or datacenter proxies, the checker can fetch fresh proxy strings from your plan and check them in one step. Create an API key in the QuanticData dashboard, then:

```sh
export QUANTICDATA_API_KEY=qd_live_...
proxy-checker quanticdata --list-plans
proxy-checker quanticdata --order-id ORDER_ID --country us --quantity 10
proxy-checker quanticdata --order-id ORDER_ID --rotation sticky --session-time 10 -n 10 --expect-sticky
proxy-checker quanticdata --order-id ORDER_ID --protocol socks5 --country de --city berlin --json
```

`--list-plans` calls `GET /public/proxies`; the check calls `POST /public/proxies/generate` with the targeting you pass (`--country`, `--state`, `--city`, `--rotation`, `--session-time`, `--gateway`, `--quantity`, `--protocol http|socks5`). The strings come back with targeting and session already applied: the checker never edits usernames. A 2-letter `--country` also becomes the `--expect-country` assertion. Generating strings is free; using them consumes the plan's traffic like any other request. `QUANTICDATA_API_BASE` overrides the API host. API reference: [quanticdata.io/docs](https://quanticdata.io/docs/); plans: [quanticdata.io/pricing](https://quanticdata.io/pricing/).

## Use it as a Go library

```go
import (
	"context"
	"fmt"

	"github.com/quanticdata-io/proxy-checker/pkg/checker"
	"github.com/quanticdata-io/proxy-checker/pkg/proxy"
)

func main() {
	p, _ := proxy.Parse("user:pass@gw.example.net:8080", proxy.HTTP)
	opts := checker.DefaultOptions()
	opts.Attempts = 5
	opts.ExpectCountry = "US"
	c, _ := checker.New(opts)
	r := c.Check(context.Background(), p)
	fmt.Println(r.Pass, r.ExitIPs, r.Failures)
	if r.Latency != nil {
		fmt.Println("p50 ms:", r.Latency.P50)
	}
}
```

`checker.Run` checks a slice concurrently and keeps the input order; `checker.Summarise` aggregates results. The API is pre-1.0: minor versions may change it, as recorded in the [changelog](CHANGELOG.md).

## All flags

Run `proxy-checker -h`. The most used:

```
-f, --file FILE          proxies, one per line ('-' for stdin)
--protocol P             protocol for lines without a scheme (http)
-n, --attempts N         requests per proxy (3)
--retries N              retries after a connection error (1)
--timeout D              timeout of one request (15s)
-c, --concurrency N      proxies checked in parallel (20)
--echo-url URL           IP echo endpoint
--expect-country CC      exit country assertion
--expect-rotation        exit IP must change
--expect-sticky          exit IP must not change
--min-success PERCENT    per-proxy success rate threshold
--target URL             also fetch this URL
--expect-status N        status the target must answer
--expect-text STR        text the target body must contain
--headers-url URL        header echo for the anonymity check
--json --jsonl --csv     output format
--fail-under PERCENT     exit 1 below this pool pass rate
--save-pass FILE         write passing proxies to FILE
--insecure               skip TLS verification
```

## Responsible use

Check proxies you own, rent or are allowed to use. Many "free proxy" lists contain compromised machines; do not route traffic through hosts whose owners did not agree to it.

## Contributing

Bug reports and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
