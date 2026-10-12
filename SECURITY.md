# Security policy

## Authorized use

NetScan is intended for owners and operators performing authorized network inventory and assessment. Use signed written authorization, strict scope, maintenance windows where appropriate, and conservative concurrency. The operator remains responsible for legal compliance.

## Reporting a vulnerability

Please do not publish sensitive details in a public issue. Use GitHub's private vulnerability reporting for this repository, or contact the maintainers through the private channel listed in the repository settings. Include affected versions, a minimal reproduction, impact, and suggested mitigation.

## Security boundaries

- The CLI requires `--authorized` and a YAML scope file before a scan starts.
- Every normalized target must be covered by the scope declaration.
- Custom Nmap flags are allowlisted and are passed through `subprocess.run` as an argument list with a timeout; no shell is used.
- NSE `vuln` scripts require a separate explicit acknowledgement.
- Risk scores are heuristic and must not be treated as vulnerability confirmation.

Please report ways to bypass target scope checks, inject unapproved Nmap flags, or cause unsafe report rendering as security issues.
