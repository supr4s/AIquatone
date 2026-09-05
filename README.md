# AIquatone

AIquatone is a fork of [Aquatone](https://github.com/michenriksen/aquatone),
the superb visual reconnaissance tool by Michael Henriksen, archived in 2023.
The goal: pick up development where it stopped, make it faster and more
reliable on large scopes, and add the few features that matter in real bug
bounty and pentest work.

## Why (AI)quatone?

Because its development was taken over by AI, guided by my own experience,
my tests on real targets, and the features I actually needed on large
scopes. The tool itself contains no AI: every result comes from
reproducible HTTP, DNS, browser, fingerprint and heuristic signals.

## What's new compared to Aquatone

- Scans of 1000+ URLs without file descriptor leaks or Chrome crashes
- Up-to-date technology fingerprints and versions via `wappalyzergo`
- Triage tags: login, signup, SSO, MFA, admin, API, upload, debug,
  default install, sensitive exposure, cloud storage, control panel,
  payment, open redirect, CAPTCHA, 404 classification
- Interesting Titles tab for "juicy" page titles (admin, dev, preprod,
  intranet, jenkins, vpn, backup, ...)
- Report tabs for Technologies, Features and Interesting Titles, with URL
  export
- Linux and Windows binaries

The inherited subdomain-takeover detector is disabled until its signatures
are refreshed.

## Install

Download the archive for your platform from the
[Releases page](https://github.com/supr4s/AIquatone/releases), extract it
and run `aiquatone` (or `aiquatone.exe`). Chrome or Chromium is required
for screenshots and is auto-detected; use `-chrome-path` otherwise.

From source (Go 1.25+):

```bash
go install github.com/supr4s/aiquatone@latest
```

## Usage

```bash
cat targets.txt | ./aiquatone -out ./results
cat targets.txt | ./aiquatone -ports large -out ./results
cat scan.xml | ./aiquatone -nmap -out ./results
./aiquatone -session ./results/aiquatone_session.json -out ./results
```

URLs are requested directly; hostnames and IPs are port-scanned first. The
output directory is created if needed and receives `aiquatone_report.html`,
`aiquatone_urls.txt`, `aiquatone_session.json` and the `headers/`, `html/`
and `screenshots/` evidence. Run `./aiquatone -h` for all options.

Only scan systems you are explicitly authorized to test.

## Development

```bash
go test ./... && go vet ./... && go build -o aiquatone .
```

Report assets are embedded in `core/bindata.go`. After editing `static/`,
run `go-bindata -pkg core -o core/bindata.go static/`.

## License

Free and open source under the MIT License, like the original Aquatone.
See [`LICENSE.txt`](LICENSE.txt) and [`NOTICE`](NOTICE). Contributions are
welcome.
