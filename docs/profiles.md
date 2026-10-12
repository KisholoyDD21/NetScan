# Scan profiles

| Profile | Behavior | Caution |
|---|---|---|
| `discovery` | `-sn` host discovery | Discovery may be blocked by network controls. |
| `quick` | TCP connect scan of top 100 ports | Default for a quick inventory. |
| `full-tcp` | TCP connect scan across all TCP ports | Can take a long time and generate traffic. |
| `stealth` | SYN scan of top 100 ports | Requires suitable privileges; downgraded to `-sT` when not elevated. |
| `service` | Service/version detection on top 100 TCP ports | Can generate more probes. |
| `udp-top` | UDP top 50 ports | Slow/noisy; may require elevated privileges. |
| `os-detect` | OS detection plus top 100 TCP ports | OS detection may be omitted without privileges. |
| `vuln` | Nmap NSE `vuln` category and service detection | Must be explicitly acknowledged with `--allow-vuln-scripts`; can be intrusive. |
| `custom` | Narrow allowlist of custom Nmap flags | Flags are validated; NSE scripts and output/target-control flags are blocked. |

Every profile remains subject to the authorization gate and scope coverage check. No profile permits scanning outside scope.
