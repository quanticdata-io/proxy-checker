# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/quanticdata-io/proxy-checker/pkg/checker.Version=${VERSION}" -o /out/proxy-checker ./cmd/proxy-checker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/proxy-checker /usr/local/bin/proxy-checker
ENTRYPOINT ["proxy-checker"]
