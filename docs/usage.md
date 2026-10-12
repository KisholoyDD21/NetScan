# Usage guide

> **Authorization required:** Only scan systems you own or have explicit written permission to assess. Use `--authorized` and a scope file. NetScan is a tool, not legal advice or proof of permission.

## Install

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Install Nmap separately and confirm `nmap --version` works. Copy `examples/scope.example.yaml` to a local `scope.yaml`, then edit it to the exact assets authorized for your assessment. Never commit real client scope files.

## Basic scan

```bash
netscan scan --targets 127.0.0.1 --scope-file scope.yaml --authorized --profile quick --report html --report json
netscan scan --targets-file examples/targets.example.txt --scope-file scope.yaml --authorized --profile discovery
```

## Reports and profiles

Repeat `--report` for each output or pass a comma-separated value: `--report html,json,csv,md,pdf`. PDF requires `pip install 'netscan[pdf]'`. Use `netscan profiles` to show profile flags. Set `--engine subprocess` to force raw XML execution; `auto` selects the wrapper for built-ins and raw subprocess for `custom`/`vuln`. `--cve-enrichment` is opt-in and sends service product/version strings to the NVD API; results are unverified leads. Profile-specific examples are maintained in the README.

## Diffing

```bash
netscan diff reports/baseline.json reports/current.json
netscan scan --targets 127.0.0.1 --scope-file scope.yaml --authorized --compare-with reports/baseline.json --report html --report json
```

## Cache and concurrency

`--cache-ttl 600` reuses host results younger than ten minutes; `--sequential` forces one worker; `--workers 2` caps concurrent processes. The cache is convenience state, not a source of truth. Set TTL to zero to disable it.
