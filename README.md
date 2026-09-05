# AIquatone

AIquatone is a fork of [Aquatone](https://github.com/michenriksen/aquatone),
the superb visual reconnaissance tool created by Michael Henriksen and
archived in January 2023. The idea behind this project is simple: pick up
development where Aquatone left off, make it faster and more reliable on
large scopes, and add a handful of features that matter in today's bug bounty
and pentest workflows, without changing what made the original great.

Compared to the archived Aquatone, AIquatone:

- Handles scans of 500-1000+ URLs without leaking file descriptors or
  crashing Chrome (per-screenshot profiles, bounded Chrome concurrency,
  batched URL publishing)
- Replaces the stale embedded fingerprints with the maintained
  `wappalyzergo` library, with version detection
- Adds rule-based triage: login, signup, SSO, MFA, admin, API, upload,
  debug, default-install, sensitive-exposure, cloud-storage, control-panel,
  payment, open-redirect and CAPTCHA signals, plus 404 classification
- Adds an Interesting Titles tab that surfaces "juicy" page titles (admin,
  dev, preprod, intranet, jenkins, vpn, backup, ...)
- Ships an updated interactive report with Technologies, Features and
  Interesting Titles tabs and URL export
- Builds and runs on Linux and Windows, with pre-built binaries

AIquatone is deterministic: it contains no AI model and makes no AI service
calls at runtime. Its results come from reproducible HTTP, DNS, browser,
fingerprint and heuristic signals. Detected product versions are inventory
data only: the tool does not map them to CVEs.

## Features

- Extract URLs and hosts from text, Nmap XML or Masscan XML
- Scan common or custom TCP ports and probe HTTP/HTTPS services
- Capture screenshots with Chrome or Chromium
- Fingerprint technologies and detected versions with `wappalyzergo`
- Identify login, signup, SSO, MFA, admin, API, upload, debug, default-install,
  sensitive-exposure, cloud-storage, control-panel and payment surfaces
- Flag open-redirect query parameters and CAPTCHA-protected forms
- Flag "juicy" page titles (admin, dev, preprod, intranet, jenkins, vpn,
  backup, ...) in a dedicated Interesting Titles report tab
- Separate full authentication pages from simple login or signup links
- Cluster structurally similar pages
- Generate an interactive HTML report with technology and feature filters
- Save responsive URLs, headers, response bodies and reusable session data

The inherited subdomain-takeover detector is disabled. Its provider signatures
are outdated and must be refreshed and tested before it can rejoin the scan
pipeline.

## Requirements

- Go 1.25 or newer
- Google Chrome or Chromium for screenshots

## Install

### Pre-built binaries

Download the archive for your platform from the
[Releases page](https://github.com/supr4s/AIquatone/releases):

| Platform | Archive |
|----------|---------|
| Linux amd64 | `aiquatone_<version>_linux_amd64.tar.gz` |
| Windows amd64 | `aiquatone_<version>_windows_amd64.zip` |

Each release ships a `checksums.txt` with SHA-256 sums.

```bash
# Linux
tar -xzf aiquatone_<version>_linux_amd64.tar.gz
./aiquatone -h
```

On Windows, extract the zip and run `aiquatone.exe` from PowerShell or `cmd`.
Chrome or Chromium is auto-detected in `Program Files`, `Program Files (x86)`
and `LocalAppData`; use `-chrome-path` otherwise.

### From source

```bash
go install github.com/supr4s/aiquatone@latest
```

Or build from a clone:

```bash
go build -o aiquatone .
```

## Usage

The output directory is created if it does not exist.

```bash
cat targets.txt | ./aiquatone -out ./results
```

URLs are requested directly. Hostnames and IP addresses are scanned on the
configured ports first.

```bash
cat targets.txt | ./aiquatone -ports large -out ./results
cat scan.xml | ./aiquatone -nmap -out ./results
./aiquatone -session ./results/aquatone_session.json -out ./results
```

Run `./aiquatone -h` for all options.

The scan writes:

- `aquatone_report.html`: interactive report
- `aquatone_urls.txt`: responsive URLs
- `aquatone_session.json`: reusable scan metadata
- `headers/`, `html/`, `screenshots/`: collected evidence

Only scan systems for which you have explicit authorization.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o aiquatone .
```

The report assets are embedded in `core/bindata.go`. After changing a file in
`static/`, regenerate them with:

```bash
go install github.com/go-bindata/go-bindata/v3/go-bindata@latest
go-bindata -pkg core -o core/bindata.go static/
```

## License and origin

AIquatone is free and open source software, distributed under the MIT
License, the same license as the original Aquatone. You can use, modify,
redistribute and build on it, commercially or not, as long as the copyright
and license notices are kept. See [`LICENSE.txt`](LICENSE.txt) for the full
text and [`NOTICE`](NOTICE) for attribution to the original project.

Contributions are welcome through issues and pull requests.
