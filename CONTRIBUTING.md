# Contributing

Thanks for helping improve NetScan. Keep contributions reproducible, narrowly scoped, and security-conscious.

1. Open an issue before substantial changes.
2. Create a virtual environment and install `pip install -e ".[dev]"`.
3. Add tests for parsing, authorization, command construction, reports, and error paths.
4. Run `ruff check src tests`, `black --check src tests`, `mypy --strict src/netscan`, and `pytest`.
5. Do not include client IPs, credentials, scan outputs, private scope files, or sensitive hostnames in fixtures.
6. Never weaken the authorization gate or bypass `ScopeAuthorizer` for convenience.

Pull requests should explain security impact and compatibility changes. See the PR template.
