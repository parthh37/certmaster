namespace CertMaster.Core.Updates;

/// <summary>
/// A release version such as "1.2.3", "v1.2.3" or "1.3.0-beta.2". Numeric parts compare numerically; a version with a
/// pre-release suffix is older than the same version without one (semver rules, simplified).
/// </summary>
public sealed record ReleaseVersion(Version Number, string? Prerelease) : IComparable<ReleaseVersion>
{
    public static ReleaseVersion? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        if (t.StartsWith('v') || t.StartsWith('V')) t = t[1..];
        var plus = t.IndexOf('+');
        if (plus >= 0) t = t[..plus];
        string? pre = null;
        var dash = t.IndexOf('-');
        if (dash >= 0) { pre = t[(dash + 1)..]; t = t[..dash]; if (pre.Length == 0) pre = null; }
        if (!Version.TryParse(t.Contains('.') ? t : t + ".0", out var v)) return null;
        // Normalise to major.minor.build so "1.2" equals "1.2.0".
        v = new Version(v.Major, v.Minor, Math.Max(v.Build, 0));
        return new ReleaseVersion(v, pre);
    }

    public int CompareTo(ReleaseVersion? other)
    {
        if (other is null) return 1;
        var c = Number.CompareTo(other.Number);
        if (c != 0) return c;
        if (Prerelease == null) return other.Prerelease == null ? 0 : 1;
        if (other.Prerelease == null) return -1;
        return ComparePrerelease(Prerelease, other.Prerelease);
    }

    private static int ComparePrerelease(string a, string b)
    {
        var pa = a.Split('.');
        var pb = b.Split('.');
        for (var i = 0; i < Math.Min(pa.Length, pb.Length); i++)
        {
            var na = int.TryParse(pa[i], out var ia);
            var nb = int.TryParse(pb[i], out var ib);
            var c = na && nb ? ia.CompareTo(ib) : na ? -1 : nb ? 1 : string.CompareOrdinal(pa[i], pb[i]);
            if (c != 0) return c;
        }
        return pa.Length.CompareTo(pb.Length);
    }

    public static bool operator >(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) > 0;
    public static bool operator <(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) < 0;

    public override string ToString() => Prerelease == null ? Number.ToString(3) : $"{Number.ToString(3)}-{Prerelease}";
}
