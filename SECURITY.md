# Security policy

## Supported versions

Security fixes are released for the latest minor version.

## Reporting a vulnerability

Please do not open a public issue for security problems. Email **hello@quanticdata.io** with "proxy-checker security" in the subject, a description of the issue and, if possible, steps to reproduce. You will get an answer within 3 working days, and we will agree on a disclosure date with you once a fix is ready.

## Handling credentials

proxy-checker masks proxy passwords in its output unless `--show-credentials` is given, and writes `--save-pass` files with mode 0600. The QuanticData preset reads the API key only from the `QUANTICDATA_API_KEY` environment variable and sends it only to the API host (`QUANTICDATA_API_BASE`, default `https://api.quanticdata.io/v1`). Report any path where a credential is printed, logged or sent elsewhere.
