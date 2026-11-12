using System.Text;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>
/// Windows DNS Server (local or remote) via the DnsServer PowerShell module (RSAT "DNS Server Tools" on a non-DNS
/// server). Values are passed to PowerShell through environment variables, never on the command line.
/// </summary>
public class MicrosoftDnsProvider : DnsProviderBase
{
    private const string Name = "Microsoft DNS";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.MSDNS",
        Title = "Microsoft DNS Server (Windows)",
        Description = "Updates a primary zone on a local or remote Windows DNS Server using the DnsServer PowerShell module (install RSAT DNS Server Tools when the agent is not on the DNS server). Runs as the agent service account unless Windows credentials are selected.",
        HelpUrl = "https://learn.microsoft.com/powershell/module/dnsserver/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = StandardCredentialTypes.Windows,
        ProviderParameters =
        {
            new ProviderParameter { Key = "dns_server", Name = "DNS Server (optional)", Description = "Host name of the Windows DNS Server. Blank = this machine." },
        }
    };

    // Fixed script; all inputs come from CM_* environment variables.
    private const string Script = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        try {
            Import-Module DnsServer -ErrorAction Stop
        } catch {
            [Console]::Error.WriteLine('The DnsServer PowerShell module is not installed. Install RSAT DNS Server Tools (Install-WindowsFeature RSAT-DNS-Server or Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0).')
            exit 3
        }
        $p = @{}
        $server = $env:CM_DNS_SERVER
        if ($env:CM_DNS_USER) {
            $sec = ConvertTo-SecureString $env:CM_DNS_PASS -AsPlainText -Force
            $user = $env:CM_DNS_USER
            if ($env:CM_DNS_DOMAIN -and $user -notmatch '[\\@]') { $user = "$($env:CM_DNS_DOMAIN)\$user" }
            $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
            $target = if ($server) { $server } else { 'localhost' }
            $p.CimSession = New-CimSession -ComputerName $target -Credential $cred
        } elseif ($server) {
            $p.ComputerName = $server
        }
        # Existing TXT values for the name. "Not found" means none; any other error (access denied, RPC, zone missing)
        # must fail the step rather than look like success.
        function Get-ExistingTxt {
            try { @(Get-DnsServerResourceRecord @p -ZoneName $env:CM_DNS_ZONE -Name $env:CM_DNS_NAME -RRType Txt -ErrorAction Stop) }
            catch [Microsoft.Management.Infrastructure.CimException] {
                if ($_.CategoryInfo.Category -eq 'ObjectNotFound' -or "$($_.Exception.MessageId)" -match '9714') { @() } else { throw }
            }
        }
        try {
            switch ($env:CM_DNS_ACTION) {
                'zones' {
                    Get-DnsServerZone @p | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and $_.ZoneName -ne 'TrustAnchors' } |
                        ForEach-Object { 'ZONE:' + $_.ZoneName }
                }
                'add' {
                    $existing = @(Get-ExistingTxt)
                    if ($existing | Where-Object { $_.RecordData.DescriptiveText -eq $env:CM_DNS_VALUE }) { 'EXISTS' }
                    else {
                        Add-DnsServerResourceRecord @p -ZoneName $env:CM_DNS_ZONE -Name $env:CM_DNS_NAME -Txt -DescriptiveText $env:CM_DNS_VALUE -TimeToLive (New-TimeSpan -Seconds 60)
                        'ADDED'
                    }
                }
                'remove' {
                    $ours = @(Get-ExistingTxt | Where-Object { $_.RecordData.DescriptiveText -eq $env:CM_DNS_VALUE })
                    foreach ($r in $ours) { Remove-DnsServerResourceRecord @p -ZoneName $env:CM_DNS_ZONE -InputObject $r -Force -ErrorAction Stop }
                    'REMOVED:' + $ours.Count
                }
                default { throw "Unknown action $($env:CM_DNS_ACTION)" }
            }
        } catch {
            [Console]::Error.WriteLine($_.Exception.Message)
            exit 2
        } finally {
            if ($p.CimSession) { Remove-CimSession $p.CimSession }
        }
        """;

    private static async Task<string> RunAsync(DnsProviderContext ctx, string action, string? zone = null, string? name = null, string? value = null)
    {
        if (!OperatingSystem.IsWindows()) throw new DnsProviderException("Microsoft DNS: this provider only runs on Windows.");
        var env = new Dictionary<string, string>
        {
            ["CM_DNS_ACTION"] = action,
            ["CM_DNS_SERVER"] = ctx.Param("dns_server") ?? "",
            ["CM_DNS_ZONE"] = zone ?? "",
            ["CM_DNS_NAME"] = name ?? "",
            ["CM_DNS_VALUE"] = value ?? "",
            ["CM_DNS_USER"] = ctx.Cred("username") ?? "",
            ["CM_DNS_PASS"] = ctx.Cred("password") ?? "",
            ["CM_DNS_DOMAIN"] = ctx.Cred("domain") ?? "",
        };
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));
        var exe = ProcessRunner.PowerShellExe; // full System32 path: no search-path lookup
        var r = await ProcessRunner.RunAsync(exe, new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded }, env, TimeSpan.FromMinutes(2));
        if (r.ExitCode != 0)
        {
            var err = string.IsNullOrWhiteSpace(r.Error) ? r.Output : r.Error;
            var hint = err.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) || err.Contains("WIN32 5", StringComparison.OrdinalIgnoreCase)
                ? " The account needs to be a member of DnsAdmins (or have rights on the zone) on the DNS server."
                : err.Contains("RPC server", StringComparison.OrdinalIgnoreCase) || err.Contains("WinRM", StringComparison.OrdinalIgnoreCase)
                    ? " Check the DNS server name, firewall (RPC/WinRM) and that the server is reachable."
                    : "";
            throw new DnsProviderException($"Microsoft DNS ({action}) failed: {DnsHttp.Truncate(CleanError(err), 600)}{hint}");
        }
        return r.Output;
    }

    private static string CleanError(string err) =>
        string.Join(" ", err.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#< CLIXML", StringComparison.Ordinal) && !l.StartsWith("<Objs", StringComparison.Ordinal)));

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var output = await RunAsync(ctx, "zones");
        return output.Split('\n').Select(l => l.Trim())
            .Where(l => l.StartsWith("ZONE:", StringComparison.Ordinal))
            .Select(l => l[5..]).Select(z => new DnsZone(z, z)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var output = await RunAsync(ctx, "add", zone.Name, rel, value);
        return ActionResult.Ok(output.Contains("EXISTS") ? $"TXT {rel} in {zone.Name} already has this value" : $"Added TXT {rel} to zone {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var output = await RunAsync(ctx, "remove", zone.Name, rel, value);
        return ActionResult.Ok($"Removed TXT {rel} from zone {zone.Name} ({output.Trim()})");
    });
}
