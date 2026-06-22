# JSieve

JSieve is a passive JavaScript reconnaissance tool for authorized web security testing. It enumerates public JavaScript files, downloads them locally, checks for source maps, extracts API endpoints, and detects exposed secrets using regex and entropy-based analysis.

Use this tool only on assets you own, CTF/lab targets, or bug bounty targets where this activity is explicitly allowed.

## Features

- Installable command-line tool: `jsieve`
- Single-domain scan or target-list scan
- Optional subdomain enumeration with `subfinder` and `httpx/httpx-toolkit`
- JavaScript URL enumeration with `katana`
- Concurrent JavaScript downloading
- Source map discovery and validation
- Regex-based secret detection
- Entropy-based sensitive assignment detection
- Endpoint extraction from `fetch`, `axios`, XHR, absolute URLs, API paths, and route-like strings
- JSON output files
- Plain text endpoint output
- Optional HTML report generation with `-gr / --generate-report`
- Local demo lab for offline testing

## Project structure

```text
JS-Secret-Finder/
├── analyzer/
│   ├── endpoint_extractor.py
│   ├── entropy_engine.py
│   ├── secret_regex_engine.py
│   └── sensitive_analyzer.py
├── collector/
│   ├── js_downloader.py
│   └── sourcemap_checker.py
├── recon/
│   ├── crawler.py
│   └── get_LiveHosts.py
├── reporting/
│   └── json_to_html.py
├── demo-lab/
│   └── js-test-lab/
├── tests/
│   └── run_demo_lab.py
├── main.py
├── pyproject.toml
├── requirements.txt
├── install.sh
└── README.md
```

## Requirements

### Python

- Python 3.10+
- `requests`
- `jsbeautifier`
- `pandas` for HTML report generation

### External tools

Real scans require ProjectDiscovery tools:

- `katana`
- `subfinder` when subdomain enumeration is enabled
- `httpx` or `httpx-toolkit` when subdomain enumeration is enabled

Install Go if needed, then install:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Make sure Go binaries are in your PATH:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

On some Kali/Debian systems the HTTP probing binary may be named `httpx-toolkit` instead of `httpx`. JSieve supports both names.

Check installation:

```bash
subfinder -h
httpx -h        # or: httpx-toolkit -h
katana -h
```

## Installation

### Recommended local installation

```bash
git clone <repo-url>
cd JS-Secret-Finder
chmod +x install.sh
./install.sh
source .venv/bin/activate
jsieve -h
```

The command after installation is:

```bash
jsieve -h
```

### Manual installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
jsieve -h
```

### Global user installation

Use this only if you understand where pip installs user scripts:

```bash
python3 -m pip install --user -e .
jsieve -h
```

If `jsieve` is not found after `--user` installation, add your user scripts folder to PATH. Common Linux path:

```bash
export PATH="$PATH:$HOME/.local/bin"
```

## Usage

### Help menu

```bash
jsieve -h
```

### Scan one exact host without subdomains

```bash
jsieve -d example.com --no-subdomains
```

### Scan one exact URL

```bash
jsieve -d https://app.example.com --no-subdomains
```

### Scan a domain with subdomain enumeration

```bash
jsieve -d example.com
```

### Scan targets from a file

Create `targets.txt`:

```text
https://app.example.com
https://api.example.com
example.org
```

Run:

```bash
jsieve -l targets.txt --no-subdomains
```

### Generate HTML report

```bash
jsieve -d example.com --no-subdomains -gr
```

or:

```bash
jsieve -d example.com --no-subdomains --generate-report
```

### Use more threads

```bash
jsieve -d example.com --no-subdomains -t 30
```

### Change output directory

```bash
jsieve -d example.com --no-subdomains -o scans
```

## Output files

Each scan creates a folder like:

```text
output/example.com/
├── hosts.txt
├── js_urls.txt
├── downloaded_js_files.json
├── sourcemaps.json
├── findings.json
├── endpoints.json
├── endpoints.txt
└── report.html          # only when -gr is used
```

### `findings.json`

Contains detected exposed secrets and high-entropy sensitive assignments. Secret values should be masked before being written.

Example:

```json
{
    "type": "Stripe Secret Key",
    "keyword": "Stripe Secret Key",
    "value": "sk_t************7890",
    "severity": "Critical",
    "confidence": "High",
    "file": "auth.bundle.js",
    "url": "https://example.com/assets/auth.bundle.js",
    "engine": "regex"
}
```

### `endpoints.json`

Contains extracted endpoints with category, confidence, and method hints.

Example:

```json
{
    "type": "Endpoint",
    "category": "Auth",
    "confidence": "High",
    "method": "POST",
    "endpoint": "/api/v1/auth/login",
    "file": "auth.bundle.js",
    "url": "https://example.com/assets/auth.bundle.js",
    "engine": "endpoint_extractor"
}
```

### `endpoints.txt`

Plain text list of extracted endpoint values.

## Legal notice

JSieve is for authorized security testing only. Do not use it against systems where you do not have permission.
