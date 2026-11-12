using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using CertMaster.Core.Storage;
using DnsClient;
using DnsClient.Protocol;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Options for <see cref="DnsPropagationChecker"/>.</summary>
public sealed class DnsPropagationOptions
{
    /// <summary>Total time to wait for the value to appear.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Delay between polling rounds.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Per-query timeout.</summary>
    public TimeSpan QueryTimeout { get; set; } = TimeSpan.FromSeconds(4);
    /// <summary>Follow CNAMEs on the record name (delegated validation, acme-dns).</summary>
    public bool FollowCname { get; set; } = true;
    /// <summary>
    /// When true (default) every authoritative name server that answers must return the value, because the CA may query any of them.
    /// When false one server is enough.
    /// </summary>
    public bool RequireAllNameServers { get; set; } = true;
    /// <summary>Recursive resolvers used to follow CNAMEs and find the zone's name servers. Empty = system resolvers.</summary>
    public List<IPAddress> Resolvers { get; set; } = new();
}

/// <summary>What one authoritative name server returned for the TXT query.</summary>
public sealed record DnsTxtServerResult(string NameServer, string Address, bool Found, IReadOnlyList<string> Values, string? Error);

/// <summary>Outcome of a propagation check.</summary>
public sealed record DnsPropagationResult(
    bool IsVisible,
    string RecordName,
    string QueriedName,
    string? Zone,
    IReadOnlyList<DnsTxtServerResult> Servers,
    TimeSpan Elapsed,
    string Message);

/// <summary>
/// Checks that a TXT value is visible on the authoritative name servers of the zone that holds the record: follows
/// CNAMEs on the record name, finds the zone (SOA), resolves its NS set and queries each server directly (no recursion,
/// no cache) until the expected value is present or the timeout elapses.
/// </summary>
public static class DnsPropagationChecker
{
    /// <summary>
    /// Wait until <paramref name="value"/> is visible in the TXT record <paramref name="recordName"/> on the zone's
    /// authoritative name servers, or <paramref name="timeout"/> elapses. Never throws for DNS failures; check
    /// <see cref="DnsPropagationResult.IsVisible"/>. Throws <see cref="OperationCanceledException"/> when cancelled.
    /// </summary>
    public static Task<DnsPropagationResult> WaitForTxtAsync(string recordName, string value, TimeSpan timeout, ItemLog? log = null, CancellationToken ct = default) =>
        WaitForTxtAsync(recordName, value, new DnsPropagationOptions { Timeout = timeout }, log, ct);

    /// <inheritdoc cref="WaitForTxtAsync(string,string,TimeSpan,ItemLog?,CancellationToken)"/>
    public static async Task<DnsPropagationResult> WaitForTxtAsync(string recordName, string value, DnsPropagationOptions options, ItemLog? log = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var session = new Session(options);
        DnsPropagationResult? last = null;
        var round = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            round++;
            last = await session.CheckAsync(recordName, value, sw, ct);
            if (last.IsVisible)
            {
                log?.Info($"DNS propagation: {last.Message}");
                return last;
            }
            if (round == 1 || round % 6 == 0) log?.Info($"DNS propagation: waiting. {last.Message}");
            var remaining = options.Timeout - sw.Elapsed;
            if (remaining <= TimeSpan.Zero) break;
            await Task.Delay(remaining < options.PollInterval ? remaining : options.PollInterval, ct);
        }
        var timedOut = last with { Message = $"Timed out after {options.Timeout.TotalSeconds:0}s. {last.Message}", Elapsed = sw.Elapsed };
        log?.Warn($"DNS propagation: {timedOut.Message}");
        return timedOut;
    }

    /// <summary>A single check (no waiting).</summary>
    public static Task<DnsPropagationResult> CheckTxtAsync(string recordName, string value, DnsPropagationOptions? options = null, CancellationToken ct = default) =>
        new Session(options ?? new DnsPropagationOptions()).CheckAsync(recordName, value, Stopwatch.StartNew(), ct);

    /// <summary>
    /// Follows the CNAME chain (max 10 hops) starting at <paramref name="name"/> and returns the final name
    /// (the name itself when there is no CNAME).
    /// </summary>
    public static Task<string> ResolveCnameTargetAsync(string name, DnsPropagationOptions? options = null, CancellationToken ct = default) =>
        new Session(options ?? new DnsPropagationOptions()).ResolveCnameAsync(name, ct);

    /// <summary>True when any TXT record (its character-strings joined) equals <paramref name="value"/>.</summary>
    public static bool ContainsTxtValue(IEnumerable<IEnumerable<string>> txtRecords, string value) =>
        txtRecords.Any(r => string.Concat(r) == value);

    private static string Str(DnsString s) => s.Value.TrimEnd('.');

    private sealed class Session
    {
        private readonly DnsPropagationOptions _o;
        private readonly LookupClient _recursive;
        private string? _effectiveName;
        private string? _zone;
        private List<(string Host, IPAddress Ip)>? _servers;

        public Session(DnsPropagationOptions o)
        {
            _o = o;
            var opts = o.Resolvers.Count > 0 ? new LookupClientOptions(o.Resolvers.ToArray()) : new LookupClientOptions();
            opts.UseCache = false;
            opts.Timeout = o.QueryTimeout;
            opts.Retries = 2;
            opts.ContinueOnDnsError = true;
            opts.ThrowDnsErrors = false;
            opts.UseTcpFallback = true;
            _recursive = new LookupClient(opts);
        }

        public async Task<string> ResolveCnameAsync(string name, CancellationToken ct)
        {
            var current = DnsNames.Normalize(name);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };
            for (var i = 0; i < 10; i++)
            {
                var resp = await _recursive.QueryAsync(current, QueryType.CNAME, QueryClass.IN, ct);
                var cname = resp.Answers.CnameRecords().FirstOrDefault(c => DnsNames.Normalize(Str(c.DomainName)) == current);
                if (cname == null) return current;
                var next = DnsNames.Normalize(Str(cname.CanonicalName));
                if (!seen.Add(next)) throw new InvalidOperationException($"CNAME loop detected at {next}");
                current = next;
            }
            return current;
        }

        /// <summary>Zone apex holding <paramref name="name"/>, from the SOA in the answer or authority section.</summary>
        private async Task<string?> FindZoneAsync(string name, CancellationToken ct)
        {
            var resp = await _recursive.QueryAsync(name, QueryType.SOA, QueryClass.IN, ct);
            var soa = resp.Answers.SoaRecords().FirstOrDefault() ?? resp.Authorities.SoaRecords().FirstOrDefault();
            if (soa != null) return DnsNames.Normalize(Str(soa.DomainName));
            // Fall back to walking up the tree looking for an NS set.
            foreach (var candidate in DnsNames.CandidateZones(name))
            {
                var ns = await _recursive.QueryAsync(candidate, QueryType.NS, QueryClass.IN, ct);
                if (ns.Answers.NsRecords().Any()) return candidate;
            }
            return null;
        }

        private async Task<List<(string, IPAddress)>> FindServersAsync(string zone, CancellationToken ct)
        {
            var result = new List<(string, IPAddress)>();
            var ns = await _recursive.QueryAsync(zone, QueryType.NS, QueryClass.IN, ct);
            foreach (var host in ns.Answers.NsRecords().Select(n => Str(n.NSDName)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var ips = new List<IPAddress>();
                // Glue from the additional section when present.
                ips.AddRange(ns.Additionals.ARecords().Where(a => DnsNames.Normalize(Str(a.DomainName)) == DnsNames.Normalize(host)).Select(a => a.Address));
                if (ips.Count == 0)
                {
                    var a = await _recursive.QueryAsync(host, QueryType.A, QueryClass.IN, ct);
                    ips.AddRange(a.Answers.ARecords().Select(r => r.Address));
                }
                if (ips.Count == 0 && Socket.OSSupportsIPv6)
                {
                    var aaaa = await _recursive.QueryAsync(host, QueryType.AAAA, QueryClass.IN, ct);
                    ips.AddRange(aaaa.Answers.AaaaRecords().Select(r => r.Address));
                }
                // One address per server is enough to check what that server publishes.
                if (ips.Count > 0) result.Add((host, ips[0]));
            }
            return result;
        }

        private async Task<DnsTxtServerResult> QueryServerAsync(string host, IPAddress ip, string name, string value, CancellationToken ct)
        {
            try
            {
                var opts = new LookupClientOptions(new NameServer(ip))
                {
                    UseCache = false, Recursion = false, Timeout = _o.QueryTimeout, Retries = 1,
                    UseTcpFallback = true, ThrowDnsErrors = false, ContinueOnDnsError = false,
                };
                var client = new LookupClient(opts);
                var resp = await client.QueryAsync(name, QueryType.TXT, QueryClass.IN, ct);
                if (resp.HasError && resp.Header.ResponseCode != DnsHeaderResponseCode.NotExistentDomain)
                    return new DnsTxtServerResult(host, ip.ToString(), false, Array.Empty<string>(), resp.ErrorMessage);
                var txt = resp.Answers.TxtRecords()
                    .Where(t => DnsNames.Normalize(Str(t.DomainName)) == name)
                    .Select(t => (IEnumerable<string>)t.Text).ToList();
                var values = txt.Select(t => string.Concat(t)).ToList();
                return new DnsTxtServerResult(host, ip.ToString(), ContainsTxtValue(txt, value), values, null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                return new DnsTxtServerResult(host, ip.ToString(), false, Array.Empty<string>(), ex.Message);
            }
        }

        public async Task<DnsPropagationResult> CheckAsync(string recordName, string value, Stopwatch sw, CancellationToken ct)
        {
            var record = DnsNames.Normalize(recordName);
            try
            {
                _effectiveName ??= _o.FollowCname ? await ResolveCnameAsync(record, ct) : record;
                _zone ??= await FindZoneAsync(_effectiveName, ct);
                if (_zone == null)
                    return await RecursiveFallbackAsync(record, value, sw, $"could not determine the zone of {_effectiveName}", ct);
                if (_servers == null || _servers.Count == 0) _servers = await FindServersAsync(_zone, ct);
                if (_servers.Count == 0)
                    return await RecursiveFallbackAsync(record, value, sw, $"no name servers found for zone {_zone}", ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                return await RecursiveFallbackAsync(record, value, sw, ex.Message, ct);
            }

            var name = _effectiveName!;
            var results = await Task.WhenAll(_servers.Select(s => QueryServerAsync(s.Host, s.Ip, name, value, ct)));
            var answered = results.Where(r => r.Error == null).ToList();
            var found = answered.Count(r => r.Found);
            var visible = answered.Count > 0 && (_o.RequireAllNameServers ? found == answered.Count : found > 0);
            var via = name == record ? "" : $" (via CNAME {name})";
            var failed = results.Where(r => r.Error != null).Select(r => $"{r.NameServer}: {r.Error}").ToList();
            var msg = visible
                ? $"TXT {record}{via} is visible on {found}/{results.Length} authoritative name server(s) of {_zone}."
                : $"TXT {record}{via} found on {found}/{answered.Count} responding authoritative name server(s) of {_zone}" +
                  (results.Where(r => r.Error == null && !r.Found).Select(r => r.NameServer).ToList() is { Count: > 0 } missing ? $"; missing on {string.Join(", ", missing)}" : "") +
                  (failed.Count > 0 ? $"; no answer from {string.Join("; ", failed)}" : "") + ".";
            return new DnsPropagationResult(visible, record, name, _zone, results, sw.Elapsed, msg);
        }

        private async Task<DnsPropagationResult> RecursiveFallbackAsync(string record, string value, Stopwatch sw, string reason, CancellationToken ct)
        {
            var name = _effectiveName ?? record;
            try
            {
                var resp = await _recursive.QueryAsync(name, QueryType.TXT, QueryClass.IN, ct);
                var txt = resp.Answers.TxtRecords().Select(t => (IEnumerable<string>)t.Text).ToList();
                var ok = ContainsTxtValue(txt, value);
                var server = new DnsTxtServerResult(resp.NameServer?.ToString() ?? "recursive resolver", resp.NameServer?.Address ?? "", ok, txt.Select(t => string.Concat(t)).ToList(), null);
                return new DnsPropagationResult(ok, record, name, _zone, new[] { server }, sw.Elapsed,
                    $"{(ok ? "TXT value visible" : "TXT value not yet visible")} via recursive resolver (authoritative check unavailable: {reason}).");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                return new DnsPropagationResult(false, record, name, _zone, Array.Empty<DnsTxtServerResult>(), sw.Elapsed,
                    $"DNS lookups failed ({reason}; {ex.Message}).");
            }
        }
    }
}
