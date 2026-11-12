# CertMaster

An open-source ACME certificate manager for Windows servers: a background agent service, a desktop app, and a
web-based Management Hub for many servers. Built on .NET 10, ASP.NET Core, SignalR, WPF + MahApps.Metro and
Blazor WebAssembly + MudBlazor, packaged with Inno Setup.


## Projects

| Project | Role |
|---|---|
| `CertMaster.Models` | Shared domain model: managed certificates, challenge and task configs, provider definitions, hub contracts |
| `CertMaster.Core` | Engine: ACME (Certes), SQLite document store, DPAPI-encrypted credentials, http-01 server (http.sys), DNS providers, deployment tasks, renewal logic |
| `CertMaster.Server.Core` | **Agent** Windows service: local REST API + SignalR status hub on `127.0.0.1:9696`, renewal worker, outbound connection to the Hub |
| `CertMaster.Client` | Typed client for the agent API (used by the desktop UI) |
| `CertMaster.UI.Desktop` | WPF / MahApps desktop app for a single server |
| `CertMaster.Server.Hub` | **Management Hub** service: JWT auth, users and roles, joining keys, agent gateway, OpenAPI + Scalar (`/docs`), hosts the Blazor UI |
| `CertMaster.UI.Blazor` | Hub web UI (Blazor WASM + MudBlazor) |

## How it fits together

```
 Desktop UI ──HTTP + SignalR (API key)──> Agent service ──ACME──> Let's Encrypt / ZeroSSL / Google / ...
                                             │  ▲
                        outbound SignalR      │  │ commands (client results), progress, summaries
                                             ▼  │
 Browser ──HTTPS (JWT)──> Management Hub (API + Blazor UI)
```

Agents connect *out* to the hub, so managed servers don't need an inbound port. The hub never stores provider
secrets; it proxies commands to agents, and secrets stay encrypted on each agent.

## Features in this MVP

- ACME accounts with EAB for Let's Encrypt, ZeroSSL, Google, SSL.com, Sectigo and Actalis, plus custom CAs.
- Orders for multiple domains, wildcards and IP addresses, with ACME profiles and ARI replacement orders.
- RSA and ECDSA keys, private key reuse, and preferred chain.
- http-01 via the built-in http.sys listener (shares port 80 with IIS) and/or web-root files.
- dns-01 via Cloudflare, GoDaddy, acme-dns or custom scripts, with CNAME delegation rules and propagation delay.
- Deployment tasks: Windows certificate store, export (PFX/PEM), script (PowerShell/batch/shell/Python),
  webhook, service restart and wait. Tasks have triggers, retries, fatal-on-error and run-if-previous-failed options.
- Renewal scheduler: days before expiry, or one third of the lifetime for short-lived certificates. Failures
  back off exponentially. Configuration tests, revoke, per-item logs, and PFX/PEM download.
- Hub:
  - Initial admin account, PBKDF2 password hashes, JWT with rotating refresh tokens, and login rate limits.
  - Administrator, CertificateManager and Viewer roles.
  - Expiring joining keys, a dashboard, and certificate management across all instances.
  - Credentials and accounts managed per instance, plus user management.

## Develop

```bash
dotnet build CertMaster.sln
```

Run the agent and hub with isolated data folders. Environment variables `CERTMASTER_DATA`, `CERTMASTER_HUB_DATA`,
`Agent__Url` and `Hub__Url` override the defaults:

```powershell
$env:CERTMASTER_DATA="$PWD\.data\agent"; dotnet run --project src/CertMaster.Server.Core
$env:CERTMASTER_HUB_DATA="$PWD\.data\hub"; dotnet run --project src/CertMaster.Server.Hub   # http://localhost:9697
$env:CERTMASTER_DATA="$PWD\.data\agent"; dotnet run --project src/CertMaster.UI.Desktop
```

The first hub start writes `initial-admin-password.txt` to the hub data folder. In the hub, create a joining key
under **Instances**, then in the desktop app go to **Settings > Management Hub** and join.

## Test end to end with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's local ACME test server. It needs no domain
and no admin rights.

1. Start `pebble-challtestsrv -management 127.0.0.1:8055 -dnsserver 127.0.0.1:8053 -http01= -https01= -tlsalpn01= -doh=`
   (mock DNS that answers 127.0.0.1 for every name, and serves TXT records you set over HTTP).
2. Start `pebble -config pebble-config.json -dnsserver 127.0.0.1:8053` with `PEBBLE_VA_NOSLEEP=1`.
3. In the agent:
   - Set **Preferences > HTTP challenge server prefix** to `http://localhost:5002/.well-known/acme-challenge/`.
   - Add a custom CA with directory `https://localhost:14000/dir` and **AllowUntrustedTls** on. Pebble uses a
     self-signed TLS certificate; this option only applies to custom CAs.
   - Register an account.
4. Run both checks:
   - **http-01:** request a certificate for `localhost`.
   - **dns-01:** use the custom script provider with scripts that call `http://127.0.0.1:8055/set-txt` and
     `/clear-txt`; any name works, wildcards included.

Verified on 2026-11-12 with Pebble 2.10.3:
- http-01 issuance.
- Wildcard and multi-domain dns-01 issuance with the `shortlived` profile.
- RSA-3072 and ECDSA keys.
- ARI replacement-order renewal.
- PEM export task and PFX download.
- Revoke, then automatic re-issue on the next renewal run.

## Package

```powershell
./build/publish.ps1          # self-contained win-x64 builds in ./dist
iscc installer/certmaster-agent.iss
iscc installer/certmaster-hub.iss
```

Production hub deployments should sit behind HTTPS (a reverse proxy, or Kestrel certificate configuration).
