using System.Globalization;
using System.Net;

namespace CertMaster.Core.Iis;

/// <summary>TLS flags of an https binding (mirrors the IIS sslFlags attribute values used by the planner).</summary>
[Flags]
public enum BindingSslFlags
{
    None = 0,
    /// <summary>Server Name Indication: the certificate is selected per hostname:port.</summary>
    Sni = 1,
    /// <summary>Centralized Certificate Store: the certificate comes from a file share, not a thumbprint.</summary>
    CentralCertStore = 2,
}

/// <summary>A point-in-time copy of one web server binding, independent of the IIS API (used by the binding planner).</summary>
public class ServerBindingSnapshot
{
    public string Protocol { get; set; } = "https";
    /// <summary>"*" for all unassigned addresses, otherwise the IP (IPv6 in brackets, as IIS writes it).</summary>
    public string IP { get; set; } = "*";
    public int Port { get; set; } = 443;
    /// <summary>Host header; empty for "any hostname".</summary>
    public string Host { get; set; } = "";
    /// <summary>Thumbprint (hex) of the certificate currently bound, if any.</summary>
    public string? CertificateHash { get; set; }
    public string? CertificateStoreName { get; set; }
    public BindingSslFlags SslFlags { get; set; }

    public bool IsHttps => string.Equals(Protocol, "https", StringComparison.OrdinalIgnoreCase);
    public bool IsHttp => string.Equals(Protocol, "http", StringComparison.OrdinalIgnoreCase);
    public bool UsesSni => SslFlags.HasFlag(BindingSslFlags.Sni);
    public bool UsesCentralCertStore => SslFlags.HasFlag(BindingSslFlags.CentralCertStore);
    public string BindingInformation => BindingEndpoint.Format(IP, Port, Host);

    public override string ToString() => $"{Protocol}/{BindingInformation}";
}

/// <summary>A point-in-time copy of a web server site and its bindings.</summary>
public class ServerSiteSnapshot
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>Physical path of the root application ("/"), environment variables expanded.</summary>
    public string? PhysicalPath { get; set; }
    public bool IsStarted { get; set; } = true;
    public List<ServerBindingSnapshot> Bindings { get; set; } = new();

    public override string ToString() => $"{Id}: {Name}";
}

/// <summary>Parsing and comparison of IIS "ip:port:host" binding information strings.</summary>
public static class BindingEndpoint
{
    /// <summary>Parses "ip:port:host" (e.g. "*:443:www.example.com", "[::1]:443:", "10.0.0.5:8443:").</summary>
    public static bool TryParse(string? bindingInformation, out string ip, out int port, out string host)
    {
        ip = "*"; port = 0; host = "";
        if (string.IsNullOrWhiteSpace(bindingInformation)) return false;
        var lastColon = bindingInformation.LastIndexOf(':');
        if (lastColon <= 0) return false;
        host = bindingInformation[(lastColon + 1)..].Trim();
        var ipPort = bindingInformation[..lastColon];
        var portColon = ipPort.LastIndexOf(':');
        if (portColon < 0) return false;
        if (!int.TryParse(ipPort[(portColon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is <= 0 or > 65535)
            return false;
        ip = NormalizeIP(ipPort[..portColon]);
        return true;
    }

    public static string Format(string? ip, int port, string? host) =>
        $"{NormalizeIP(ip)}:{port.ToString(CultureInfo.InvariantCulture)}:{(host ?? "").Trim()}";

    /// <summary>"*", "", "0.0.0.0" all mean "All Unassigned" and normalise to "*". IPv6 addresses are bracketed.</summary>
    public static string NormalizeIP(string? ip)
    {
        var v = (ip ?? "").Trim();
        if (v.Length == 0 || v == "*" || v == "0.0.0.0") return "*";
        var unbracketed = v.Trim('[', ']');
        if (IPAddress.TryParse(unbracketed, out var addr))
        {
            if (addr.Equals(IPAddress.Any)) return "*";
            return addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{addr}]" : addr.ToString();
        }
        return v.ToLowerInvariant();
    }

    /// <summary>Key identifying a binding endpoint: normalised ip, port and lower-case host.</summary>
    public static string Key(string? ip, int port, string? host) => Format(ip, port, (host ?? "").Trim().ToLowerInvariant());

    /// <summary>Key identifying an ip:port pair (non-SNI https bindings share one certificate per ip:port).</summary>
    public static string IPPortKey(string? ip, int port) => $"{NormalizeIP(ip)}:{port.ToString(CultureInfo.InvariantCulture)}";

    public static bool SameEndpoint(string? bindingInformation, string? ip, int port, string? host) =>
        TryParse(bindingInformation, out var bIp, out var bPort, out var bHost) && Key(bIp, bPort, bHost) == Key(ip, port, host);
}
