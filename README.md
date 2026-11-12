# CertMaster

**Free, open-source ACME certificate manager for Windows servers.** CertMaster requests, renews and deploys TLS
certificates from Let's Encrypt and other ACME certificate authorities. It can bind them to IIS automatically, push them
to other services with deployment tasks, and manage many servers from one web-based Management Hub.

- **CertMaster** (Windows service + desktop app) runs on each server. It does the ACME work, renews certificates
  on schedule, and applies them to IIS and your deployment targets.
- **CertMaster Management Hub** (Windows service + web UI) gives you one dashboard and editor for many servers. Agents
  connect *out* to the hub, so managed servers need no inbound firewall rule.

There are no license keys, evaluation limits or paid tiers. MIT licensed.

Website: **https://parthh37.github.io/certmaster/**

## Features

**Certificates**
- Any ACME (RFC 8555) CA: Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, Sectigo, Actalis, and custom or
  internal CAs (step-ca and similar). External Account Binding (EAB) is supported.
- Multi-domain, wildcard and IP-address certificates. RSA 2048/3072/4096 and ECDSA P-256/P-384 keys, with
  optional private-key reuse.
- Preferred chain, ACME profiles (e.g. `shortlived`), and ARI (RFC 9773) replacement orders.
- Automatic renewal: at a configurable number of days before expiry (one third of the lifetime for short-lived
  certificates), or at a percentage of the certificate lifetime. Failures retry with exponential back-off.
- Failure alerts: failed requests, failed deployment tasks and recoveries are POSTed as JSON to a webhook
  (Slack-compatible `text` field). Each certificate can opt out.
- Test (dry-run checks), Preview (a full plan of what a request will do), revoke, PFX/PEM export, and per-certificate
  request logs.

**Domain validation**
- http-01 through a built-in http.sys listener that shares port 80 with IIS, or by writing challenge files to a web root.
- dns-01 through native DNS provider integrations plus about 95 more via the bundled
  [Posh-ACME](https://github.com/rmbolger/Posh-ACME) plugins, acme-dns, or your own scripts. CNAME delegation rules,
  and propagation checks against authoritative nameservers.

**Deployment**
- Automatic IIS deployment modes:
  - Auto, Single Site, All Sites, Certificate Store Only, or No Deployment.
  - Add or update https bindings, or update existing bindings only.
  - Match existing bindings by hostname, by blank hostname, or by previous certificate.
  - SNI or specific IP/port bindings.
- Deployment tasks with triggers (on success, on error, always, manual), retries and run-if-previous-failed options.
  Tasks can target the local machine, a Windows network share (UNC), or a remote host over SSH/SFTP.

**Operations and security**
- Stored credentials are encrypted with Windows DPAPI and never returned by the API or shown in a UI.
- The data folder is locked to SYSTEM and Administrators.
- Daily database backups, a database integrity check at startup, and service crash recovery.
- Hub sign-in uses PBKDF2 password hashes, JWT with rotating refresh tokens, and rate limits.
- Hub roles: Administrator, CertificateManager and Viewer.
- Expiring, revocable joining keys connect agents to the hub.
- OpenAPI reference at `/docs` on the hub.

## Install

Download the installers from [Releases](https://github.com/parthh37/certmaster/releases):

| Installer | Installs |
|---|---|
| `certmaster-windows-x64-<version>.exe` | The **CertMaster Agent** service and the desktop app (optional component). The desktop app runs as Administrator. |
| `certmaster-hub-windows-x64-<version>.exe` | The **CertMaster Management Hub** service. The setup asks for the port (default 9697) and can open the firewall. |

Both are self-contained (no .NET install needed) and support Windows 10 / Server 2019 or later.

**First steps**
1. Open CertMaster. Go to **Settings > Certificate Authorities** and register an ACME account.
2. Click **New Certificate**. Pick an IIS site (or type domains), choose how domains are validated
   (**Authorization**), check **Deployment** and **Tasks**, then click **Test** and **Request Certificate**.
3. Optional: open the Hub, sign in as `admin` with the password from
   `C:\ProgramData\CertMasterHub\initial-admin-password.txt`, and change it. Create a joining key under **Instances**.
   Then in each server's CertMaster go to **Settings > Management Hub** and join.

Production hub deployments should sit behind HTTPS (a reverse proxy, or Kestrel certificate configuration).

## Build from source

Requirements: .NET 10 SDK on Windows, and Inno Setup 6 for the installers.

```powershell
dotnet build CertMaster.sln
dotnet test CertMaster.sln
./build/publish.ps1          # tests, self-contained publish to ./dist, then both installers
```

Run the services locally with isolated data folders. `CERTMASTER_DATA`, `CERTMASTER_HUB_DATA`, `Agent__Url` and
`Hub__Url` override the defaults.

```powershell
$env:CERTMASTER_DATA="$PWD\.data\agent"; dotnet run --project src/CertMaster.Server.Core       # agent on 127.0.0.1:9696
$env:CERTMASTER_HUB_DATA="$PWD\.data\hub"; dotnet run --project src/CertMaster.Server.Hub      # hub on http://localhost:9697
$env:CERTMASTER_DATA="$PWD\.data\agent"; dotnet run --project src/CertMaster.UI.Desktop
```

### End-to-end test with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's local test CA. It needs no domain and no
admin rights.

1. Start `pebble-challtestsrv -management 127.0.0.1:8055 -dnsserver 127.0.0.1:8053 -http01= -https01= -tlsalpn01= -doh=`
   and `pebble -config pebble-config.json -dnsserver 127.0.0.1:8053` (with `PEBBLE_VA_NOSLEEP=1`).
2. In CertMaster settings, set the HTTP challenge listener prefix to `http://localhost:5002/.well-known/acme-challenge/`.
3. Add a custom CA `https://localhost:14000/dir` with *Allow untrusted TLS* enabled, then register an account.
4. Request a certificate for `localhost` (http-01). For dns-01, use the custom-script provider calling the challenge
   test server's `/set-txt` and `/clear-txt` endpoints; any name works, wildcards included.

## Releasing

Go to **Actions > release > Run workflow** on `main` and pick a bump (`patch`, `minor`, `major`) or type an exact
version. The workflow bumps `Version` in `Directory.Build.props`, builds, tests and builds both installers. Only
then does it commit the bump to `main`, push the `v<version>` tag, and publish a GitHub release with the installers
and generated release notes. Pre-release and draft are options on the same form.

From a terminal: `gh workflow run release.yml -f bump=minor`. To bump locally instead, run
`./build/bump-version.ps1 -Bump minor`, commit, and push a `v*` tag; `ci.yml` builds the release from the tag.

The website in `site/` is published to GitHub Pages by `pages.yml` whenever `site/` changes on `main`. Its download
buttons read the latest release from the GitHub API, so releases need no website change.

## Architecture

| Project | Role |
|---|---|
| `CertMaster.Models` | Shared contracts: managed certificates, challenge, deployment and task configs, provider definitions, hub messages |
| `CertMaster.Core` | Engine: ACME (Certes), SQLite document store, encrypted credentials, http-01 listener, DNS providers, deployment tasks, IIS integration, renewal logic |
| `CertMaster.Server.Core` | Agent service: local REST API + SignalR status hub on `127.0.0.1:9696`, renewal and maintenance workers, outbound hub connection |
| `CertMaster.Client` | Typed client for the agent API |
| `CertMaster.UI.Desktop` | WPF + MahApps.Metro desktop app |
| `CertMaster.Server.Hub` | Management Hub service: auth, users and roles, joining keys, agent gateway (SignalR client results), hosts the web UI |
| `CertMaster.UI.Blazor` | Hub web UI (Blazor WebAssembly + MudBlazor) |
| `tests/CertMaster.Tests` | xUnit tests |

```
 Desktop app ──HTTP + SignalR (local API key)──> Agent service ──ACME──> Certificate authority
                                                     │  ▲
                              outbound SignalR        │  │ commands, progress, summaries
                                                     ▼  │
 Browser ──HTTPS (JWT)──> Management Hub (API + web UI)
```

The hub never stores provider secrets. It proxies commands to agents, and secrets stay encrypted on each agent.
Data lives in `C:\ProgramData\CertMaster` (agent) and `C:\ProgramData\CertMasterHub` (hub). Uninstalling asks before
removing it.

## License

MIT. See [LICENSE](LICENSE). Bundled third-party components keep their own licenses. Posh-ACME (MIT) is included
under `src/CertMaster.Core/Scripts/PoshAcme` with its license notice.
