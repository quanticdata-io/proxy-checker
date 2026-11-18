# Contributing

Thanks for helping improve proxy-checker.

## Development

Requirements: Go 1.22 or newer.

```sh
go build ./...
go vet ./...
go test ./...
go test -race ./...        # needs cgo (a C compiler); CI runs it on Linux and macOS
staticcheck ./...          # go install honnef.co/go/tools/cmd/staticcheck@latest
gofmt -l .                 # must print nothing
```

CI also runs `golangci-lint` with the configuration in `.golangci.yml`.

## Tests never use the network

Every test runs against in-process servers from `internal/testutil` (an IP echo, an HTTP/CONNECT proxy and a SOCKS4/SOCKS5 server). Do not add tests that reach the internet, a real proxy provider or a paid API. The same servers power `go run ./examples/locallab` for manual testing.

## Pull requests

- One topic per pull request, with tests for new behaviour and bug fixes.
- Keep the binary dependency-free (standard library only) unless there is a strong reason; discuss it in an issue first.
- Update `CHANGELOG.md` under "Unreleased".
- Keep output formats backwards compatible: add JSON fields and CSV columns at the end, do not rename them.

## Releases

Maintainers tag `vX.Y.Z`; the release workflow builds the binaries with GoReleaser and publishes them on the GitHub release.
