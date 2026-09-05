# AIquatone

AIquatone is a deterministic web reconnaissance and attack-surface triage tool.
It probes hosts, collects HTTP evidence, captures screenshots, fingerprints
technologies and highlights pages worth reviewing during authorized security
testing.

AIquatone is a fork of
[Aquatone](https://github.com/michenriksen/aquatone), created by Michael
Henriksen and archived in January 2023. The original project provides the scan
pipeline, Chromium capture and HTML report architecture. This fork updates that
base and adds rule-based triage focused on current bug bounty workflows.

AIquatone contains no AI model and makes no AI service calls at runtime. Its
results come from reproducible HTTP, DNS, browser, fingerprint and heuristic
signals. Detected product versions are inventory data only: the tool does not
map them to CVEs.

## Features

- Extract URLs and hosts from text, Nmap XML or Masscan XML
- Scan common or custom TCP ports and probe HTTP/HTTPS services
- Capture screenshots with Chrome or Chromium
- Fingerprint technologies and detected versions with `wappalyzergo`
- Identify login, signup, SSO, MFA, admin, API, upload, debug, default-install,
  sensitive-exposure, cloud-storage, control-panel and payment surfaces
- Flag open-redirect query parameters and CAPTCHA-protected forms
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

The output directory must already exist.

```bash
mkdir -p results
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

AIquatone is distributed under the MIT License inherited from Aquatone. See
[`LICENSE.txt`](LICENSE.txt) and [`NOTICE`](NOTICE) for attribution.
