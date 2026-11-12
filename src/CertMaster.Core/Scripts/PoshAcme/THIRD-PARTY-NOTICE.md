# Third-party notice: Posh-ACME

The `Posh-ACME` folder next to this file contains files from **Posh-ACME**, a PowerShell ACME client
by Ryan Bolger and contributors.

| | |
|---|---|
| Project | Posh-ACME |
| Version | 4.35.0 (git tag `v4.35.0`, released 2026-10-12) |
| Source | https://github.com/rmbolger/Posh-ACME (tagged source archive `v4.35.0.zip`) |
| License | MIT, see `Posh-ACME/LICENSE` |
| Copyright | Copyright (c) 2017 Ryan Bolger |

## What is included

Only the module files CertMaster needs at runtime, unmodified:

- `Posh-ACME/Posh-ACME.psd1`, `Posh-ACME/Posh-ACME.psm1`, `Posh-ACME/Posh-ACME.Format.ps1xml`
- `Posh-ACME/Private/`, `Posh-ACME/Public/`, `Posh-ACME/Plugins/`
- `Posh-ACME/LICENSE`

Not included: the `en-US` help files, docs, tests, and the `lib/` folder with the BouncyCastle
assembly (`BC.Crypto.*.dll`). Without `lib/`, CertMaster's bridge imports `Posh-ACME.psm1` directly; the
few plugins that rely on BouncyCastle (for example `GCloud`) will not work until that folder is copied
from the same Posh-ACME release. When `lib/*.dll` is present the bridge imports the module manifest instead.

## How CertMaster uses it

`Invoke-PoshAcmePlugin.ps1` (CertMaster's own script, not part of Posh-ACME) imports this module and
calls one plugin's `Add-DnsTxt` / `Remove-DnsTxt` / `Save-DnsTxt` functions inside the module scope.
CertMaster discovers the plugins at runtime and offers each as a DNS provider named
"<Plugin> (via Posh-ACME)".

## Updating

Download a newer tagged release from https://github.com/rmbolger/Posh-ACME, replace the files listed
above from its `Posh-ACME` folder, and update the version in this notice.

## License text

```
MIT License

Copyright (c) 2017 Ryan Bolger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
