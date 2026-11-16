using Amazon;
using Amazon.Route53;
using Amazon.Route53.Model;
using Amazon.Runtime;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>AWS Route 53. TXT values are kept in one RRSet per name; we UPSERT the set with our value added/removed.</summary>
public class Route53DnsProvider : DnsProviderBase
{
    private const string Name = "Route 53";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Route53",
        Title = "Amazon Route 53 DNS API",
        Description = "Validates via AWS Route 53 using an IAM access key (needs route53:ListHostedZones, GetHostedZone, ListResourceRecordSets, ChangeResourceRecordSets and GetChange). Leave the credential empty to use the default AWS credential chain of the service account (environment, profile or EC2 instance role).",
        HelpUrl = "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/access-control-managing-permissions.html",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "AWSRoute53",
        ProviderParameters =
        {
            new ProviderParameter { Key = "access_key", Name = "Access Key ID", IsCredential = true },
            new ProviderParameter { Key = "secret_key", Name = "Secret Access Key", Type = OptionType.Password, IsCredential = true },
            new ProviderParameter { Key = "session_token", Name = "Session Token (optional, temporary credentials)", Type = OptionType.Password, IsCredential = true },
            new ProviderParameter { Key = "region", Name = "Region (optional)", Value = "us-east-1", Description = "AWS partition endpoint region, e.g. us-east-1 (commercial), cn-north-1 (China) or us-gov-west-1 (GovCloud)." },
            new ProviderParameter { Key = "wait_insync", Name = "Wait for change to be INSYNC", Type = OptionType.Boolean, Value = "true", Description = "Wait until Route 53 reports the change has reached all of its name servers." },
        },
        SetupGuide = SetupGuideContent,
    };

    /// <summary>Least-privilege IAM policy for this provider, shown in the setup guide (unit tested to stay valid JSON).</summary>
    public const string IamPolicyJson = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "CertMasterFindZonesAndChanges",
              "Effect": "Allow",
              "Action": ["route53:ListHostedZones", "route53:GetChange"],
              "Resource": "*"
            },
            {
              "Sid": "CertMasterEditTxtRecords",
              "Effect": "Allow",
              "Action": ["route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:ChangeResourceRecordSets"],
              "Resource": "arn:aws:route53:::hostedzone/*"
            }
          ]
        }
        """;

    private static readonly ProviderSetupGuide SetupGuideContent = new()
    {
        Title = "How to create an AWS IAM access key for Route 53",
        Intro = "CertMaster calls the Route 53 API directly, so the AWS CLI is not required. You only need an IAM access key that is allowed to edit TXT records in your hosted zones.",
        Steps =
        {
            "Sign in to the AWS console and open IAM > Policies > Create policy. Choose the JSON editor, paste the IAM policy below and name it CertMasterRoute53. To limit it to one domain, replace hostedzone/* with hostedzone/<your hosted zone id>.",
            "Open IAM > Users > Create user. Name it, for example, certmaster-dns, leave console access off, choose \"Attach policies directly\" and select CertMasterRoute53.",
            "Open the new user > Security credentials > Create access key. Choose \"Application running outside AWS\", then copy the Access key ID and the Secret access key (AWS shows the secret only once).",
            "Back here, click Add next to Credentials, paste both keys and save. The new credential is selected for you.",
            "Click Test to check that CertMaster can find your hosted zone. On an EC2 instance whose IAM role has this policy you can leave the credential empty instead.",
        },
        Snippets =
        {
            new() { Title = "IAM policy (JSON)", Text = IamPolicyJson },
            new()
            {
                Title = "Optional: install the latest AWS CLI v2",
                Description = "Only needed if you prefer to create the user from a terminal. Run in PowerShell, then run 'aws configure' with an administrator access key.",
                Text = """
                    winget install --exact --id Amazon.AWSCLI
                    aws --version
                    """,
            },
            new()
            {
                Title = "Optional: create the user with the AWS CLI (PowerShell)",
                Description = "Save the IAM policy above as certmaster-route53.json in the current folder first. The last command prints the new access key.",
                Text = """
                    $account = aws sts get-caller-identity --query Account --output text
                    aws iam create-policy --policy-name CertMasterRoute53 --policy-document file://certmaster-route53.json
                    aws iam create-user --user-name certmaster-dns
                    aws iam attach-user-policy --user-name certmaster-dns --policy-arn "arn:aws:iam::${account}:policy/CertMasterRoute53"
                    aws iam create-access-key --user-name certmaster-dns
                    """,
            },
        },
        Links =
        {
            new() { Title = "Download the latest AWS CLI for Windows", Url = "https://awscli.amazonaws.com/AWSCLIV2.msi" },
            new() { Title = "AWS CLI install guide", Url = "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html" },
            new() { Title = "Creating an IAM user", Url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html" },
            new() { Title = "Route 53 API permissions reference", Url = "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/r53-api-permissions-ref.html" },
        },
    };

    // ---------- pure helpers (unit tested) ----------

    /// <summary>RRSet values (quoted Route 53 strings) with <paramref name="value"/> added unless present; all other values are preserved.</summary>
    public static List<string> AddTxtValue(IEnumerable<string>? rrsetValues, string value) =>
        TxtValues.Add(rrsetValues, value, TxtValues.Quote);

    /// <summary>RRSet values without <paramref name="value"/>; all other values are preserved as they are.</summary>
    public static List<string> RemoveTxtValue(IEnumerable<string>? rrsetValues, string value) =>
        TxtValues.Remove(rrsetValues, value);

    /// <summary>Route 53 returns names with a trailing dot and octal escapes (\052 for '*').</summary>
    public static string DecodeName(string? name)
    {
        var n = (name ?? "").TrimEnd('.');
        return System.Text.RegularExpressions.Regex.Replace(n, @"\\(\d{3})", m => ((char)Convert.ToInt32(m.Groups[1].Value, 8)).ToString());
    }

    // ---------- client ----------

    private static AmazonRoute53Client CreateClient(DnsProviderContext ctx)
    {
        var config = new AmazonRoute53Config();
        var region = ctx.Param("region") ?? "us-east-1";
        try { config.RegionEndpoint = RegionEndpoint.GetBySystemName(region); }
        catch (Exception ex) { throw new DnsProviderException($"Route 53: '{region}' is not a valid AWS region name.", ex); }

        var ak = ctx.Cred("access_key");
        var sk = ctx.Cred("secret_key");
        var st = ctx.Cred("session_token");
        if (ak != null && sk != null)
            return st != null
                ? new AmazonRoute53Client(new SessionAWSCredentials(ak, sk, st), config)
                : new AmazonRoute53Client(new BasicAWSCredentials(ak, sk), config);
        if (ak != null || sk != null)
            throw new DnsProviderException("Route 53: both Access Key ID and Secret Access Key are required (or leave both blank to use the default AWS credential chain / instance role).");
        return new AmazonRoute53Client(config);
    }

    private static async Task<T> Call<T>(Func<Task<T>> f)
    {
        try { return await f(); }
        catch (AmazonServiceException ex)
        {
            var hint = ex.ErrorCode switch
            {
                "InvalidClientTokenId" or "SignatureDoesNotMatch" or "UnrecognizedClientException" => " Check the Access Key ID and Secret Access Key.",
                "AccessDenied" or "AccessDeniedException" => " The IAM user/role needs route53:ListHostedZones, route53:GetHostedZone, route53:ListResourceRecordSets, route53:ChangeResourceRecordSets and route53:GetChange (the setup guide has a ready-made policy).",
                "NoSuchHostedZone" => " The hosted zone id was not found; check the zone id or clear it to auto-detect.",
                "Throttling" or "PriorRequestNotComplete" => " Route 53 is throttling requests; retry shortly.",
                "ExpiredToken" => " The session token has expired.",
                _ => "",
            };
            throw new DnsProviderException($"Route 53 error {ex.ErrorCode}: {ex.Message}.{hint}", ex);
        }
        catch (AmazonClientException ex)
        {
            throw new DnsProviderException($"Route 53: {ex.Message}. If no access key is configured, make sure AWS credentials are available to the service account (environment, profile or instance role).", ex);
        }
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        using var client = CreateClient(ctx);
        var zones = new List<DnsZone>();
        string? marker = null;
        do
        {
            var resp = await Call(() => client.ListHostedZonesAsync(new ListHostedZonesRequest { Marker = marker }));
            foreach (var z in resp.HostedZones ?? new List<HostedZone>())
            {
                if (z.Config?.PrivateZone == true) continue; // public validation needs a public zone
                zones.Add(new DnsZone(z.Id.Replace("/hostedzone/", ""), DecodeName(z.Name)));
            }
            marker = resp.IsTruncated == true ? resp.NextMarker : null;
        } while (!string.IsNullOrEmpty(marker));
        return zones;
    }

    protected override async Task<DnsZone?> GetZoneByIdAsync(DnsProviderContext ctx, string zoneId)
    {
        if (zoneId.Contains('.')) return await base.GetZoneByIdAsync(ctx, zoneId); // a zone name was given
        using var client = CreateClient(ctx);
        var id = zoneId.Replace("/hostedzone/", "");
        var resp = await Call(() => client.GetHostedZoneAsync(new GetHostedZoneRequest { Id = id }));
        return resp.HostedZone == null ? null : new DnsZone(id, DecodeName(resp.HostedZone.Name));
    }

    private static async Task<ResourceRecordSet?> GetTxtSetAsync(AmazonRoute53Client client, string zoneId, string fqdn)
    {
        var resp = await Call(() => client.ListResourceRecordSetsAsync(new ListResourceRecordSetsRequest
        {
            HostedZoneId = zoneId, StartRecordName = fqdn, StartRecordType = RRType.TXT, MaxItems = "5",
        }));
        return resp.ResourceRecordSets?.FirstOrDefault(s =>
            s.Type == RRType.TXT && string.IsNullOrEmpty(s.SetIdentifier) &&
            DnsNames.Normalize(DecodeName(s.Name)) == DnsNames.Normalize(fqdn));
    }

    private static ResourceRecordSet BuildSet(string fqdn, long ttl, IEnumerable<string> values) => new()
    {
        Name = fqdn, Type = RRType.TXT, TTL = ttl,
        ResourceRecords = values.Select(v => new ResourceRecord { Value = v }).ToList(),
    };

    private static async Task<string> ChangeAsync(AmazonRoute53Client client, string zoneId, ChangeAction action, ResourceRecordSet set)
    {
        var resp = await Call(() => client.ChangeResourceRecordSetsAsync(new ChangeResourceRecordSetsRequest
        {
            HostedZoneId = zoneId,
            ChangeBatch = new ChangeBatch
            {
                Comment = "ACME dns-01 challenge (CertMaster)",
                Changes = new List<Change> { new() { Action = action, ResourceRecordSet = set } },
            },
        }));
        return resp.ChangeInfo.Id;
    }

    private static async Task WaitInSyncAsync(DnsProviderContext ctx, AmazonRoute53Client client, string changeId)
    {
        if (!ctx.Flag("wait_insync", true)) return;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var c = await Call(() => client.GetChangeAsync(new GetChangeRequest { Id = changeId }));
            if (c.ChangeInfo.Status == ChangeStatus.INSYNC) return;
            await Task.Delay(TimeSpan.FromSeconds(5));
        }
        ctx.Log?.Warn($"Route 53 change {changeId} was not INSYNC after 3 minutes; continuing.");
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        using var client = CreateClient(ctx);
        var fqdn = DnsNames.Normalize(recordName) + ".";
        var existing = await GetTxtSetAsync(client, zone.ZoneId, fqdn);
        var current = existing?.ResourceRecords?.Select(r => r.Value).ToList() ?? new List<string>();
        if (TxtValues.Contains(current, value))
            return ActionResult.Ok($"TXT {recordName} already has this value in hosted zone {zone.Name}");
        var values = AddTxtValue(current, value);
        var changeId = await ChangeAsync(client, zone.ZoneId, ChangeAction.UPSERT, BuildSet(fqdn, existing?.TTL ?? 60, values));
        await WaitInSyncAsync(ctx, client, changeId);
        return ActionResult.Ok($"Upserted TXT {recordName} in hosted zone {zone.Name} ({values.Count} value(s))");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        using var client = CreateClient(ctx);
        var fqdn = DnsNames.Normalize(recordName) + ".";
        var existing = await GetTxtSetAsync(client, zone.ZoneId, fqdn);
        var current = existing?.ResourceRecords?.Select(r => r.Value).ToList() ?? new List<string>();
        if (existing == null || !TxtValues.Contains(current, value))
            return ActionResult.Ok($"TXT {recordName} with this value was already absent");
        var remaining = RemoveTxtValue(current, value);
        if (remaining.Count == 0)
            await ChangeAsync(client, zone.ZoneId, ChangeAction.DELETE, existing); // DELETE must match the existing set exactly
        else
            await ChangeAsync(client, zone.ZoneId, ChangeAction.UPSERT, BuildSet(fqdn, existing.TTL ?? 60, remaining));
        return ActionResult.Ok($"Removed TXT value from {recordName} in hosted zone {zone.Name}");
    });
}
