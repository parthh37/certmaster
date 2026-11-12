using System.Text.RegularExpressions;

namespace CertMaster.Core.Providers.Dns;

/// <summary>One [Parameter(...)] attribute on a plugin parameter: the parameter set it applies to (null = all) and whether it is mandatory there.</summary>
public sealed record PoshAcmeParameterUsage(string? SetName, bool Mandatory);

/// <summary>A parameter declared in a Posh-ACME plugin's Add-DnsTxt param block.</summary>
public sealed class PoshAcmeParameter
{
    public string Name { get; set; } = "";
    /// <summary>Normalised type: string, string[], securestring, pscredential, switch, bool, int, double, hashtable, or the raw lower-case type name.</summary>
    public string Type { get; set; } = "string";
    public List<PoshAcmeParameterUsage> Usages { get; } = new();
    public List<string> ValidateSet { get; } = new();
    /// <summary>Literal default value (string/number/bool) when the declaration has one.</summary>
    public string? DefaultValue { get; set; }
    public bool ValueFromRemainingArguments { get; set; }
    public string? Help { get; set; }

    public IEnumerable<string> SetNames => Usages.Where(u => u.SetName != null).Select(u => u.SetName!).Distinct(StringComparer.OrdinalIgnoreCase);
    /// <summary>True when the parameter has no set-specific [Parameter] attribute (it applies to every parameter set).</summary>
    public bool InAllSets => Usages.Count == 0 || Usages.Any(u => u.SetName == null);
    /// <summary>Mandatory in every parameter set.</summary>
    public bool MandatoryInAllSets => Usages.Any(u => u.SetName == null && u.Mandatory);
}

/// <summary>Everything CertMaster needs to know about a Posh-ACME plugin file.</summary>
public sealed class PoshAcmePluginInfo
{
    public string Name { get; set; } = "";
    public string? ChallengeType { get; set; }
    public string? Synopsis { get; set; }
    public List<PoshAcmeParameter> Parameters { get; } = new();
    public bool HasRemoveDnsTxt { get; set; }
    public bool HasSaveDnsTxt { get; set; }
    /// <summary>Uses Posh-ACME's BouncyCastle helpers (needs the module's lib folder).</summary>
    public bool RequiresBouncyCastle { get; set; }

    public static bool IsDeprecatedSet(string? set) => set != null && set.StartsWith("Deprecated", StringComparison.OrdinalIgnoreCase);

    /// <summary>Parameter sets that are not deprecated.</summary>
    public List<string> ActiveParameterSets =>
        Parameters.SelectMany(p => p.SetNames).Where(s => !IsDeprecatedSet(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>
/// A small PowerShell-aware parser for Posh-ACME plugin files: finds <c>function Add-DnsTxt</c>, its <c>param(...)</c>
/// block and the comment-based help, skipping strings, here-strings, comments and nested brackets. It does not execute
/// any PowerShell.
/// </summary>
public static class PoshAcmePluginParser
{
    private static readonly HashSet<string> SkippedParameters = new(StringComparer.OrdinalIgnoreCase) { "RecordName", "TxtValue", "ExtraParams" };

    /// <summary>Parses a plugin script. Returns null when it has no Add-DnsTxt function.</summary>
    public static PoshAcmePluginInfo? Parse(string pluginName, string script)
    {
        var info = new PoshAcmePluginInfo { Name = pluginName };
        var type = Regex.Match(script, @"function\s+Get-CurrentPluginType\s*\{\s*['""]([\w-]+)['""]", RegexOptions.IgnoreCase);
        info.ChallengeType = type.Success ? type.Groups[1].Value.ToLowerInvariant() : null;

        var body = ExtractFunctionBody(script, "Add-DnsTxt");
        if (body == null) return null;
        info.HasRemoveDnsTxt = ExtractFunctionBody(script, "Remove-DnsTxt") != null;
        info.HasSaveDnsTxt = ExtractFunctionBody(script, "Save-DnsTxt") != null;
        info.RequiresBouncyCastle = Regex.IsMatch(script, @"BouncyCastle|Import-Pem\b|ConvertFrom-BCKey\b", RegexOptions.IgnoreCase);

        var help = ParseHelp(body, out var synopsis);
        info.Synopsis = synopsis;

        var block = ExtractParamBlock(body);
        if (block == null) return info;
        foreach (var decl in SplitTopLevel(block))
        {
            var p = ParseDeclaration(decl);
            if (p == null) continue;
            if (help.TryGetValue(p.Name, out var h)) p.Help = h;
            info.Parameters.Add(p);
        }
        return info;
    }

    /// <summary>Parameters that should be exposed to the user (drops RecordName/TxtValue/ExtraParams and deprecated-only parameters).</summary>
    public static List<PoshAcmeParameter> UserParameters(PoshAcmePluginInfo info) =>
        info.Parameters.Where(p =>
                !SkippedParameters.Contains(p.Name) && !p.ValueFromRemainingArguments &&
                (p.InAllSets || p.SetNames.Any(s => !PoshAcmePluginInfo.IsDeprecatedSet(s))))
            .ToList();

    // ---------- scanning ----------

    /// <summary>
    /// If a string literal, here-string, comment or escape starts at <paramref name="i"/>, returns the index just after it; otherwise <paramref name="i"/>.
    /// </summary>
    internal static int SkipLiteral(string s, int i)
    {
        var c = s[i];
        var next = i + 1 < s.Length ? s[i + 1] : '\0';
        switch (c)
        {
            case '`':
                return Math.Min(i + 2, s.Length);
            case '#':
            {
                var nl = s.IndexOf('\n', i);
                return nl < 0 ? s.Length : nl;
            }
            case '<' when next == '#':
            {
                var end = s.IndexOf("#>", i + 2, StringComparison.Ordinal);
                return end < 0 ? s.Length : end + 2;
            }
            case '@' when next is '\'' or '"' && IsHereStringStart(s, i + 2):
            {
                var term = "\n" + next + "@";
                var end = s.IndexOf(term, i + 2, StringComparison.Ordinal);
                return end < 0 ? s.Length : end + term.Length;
            }
            case '\'':
            {
                for (var j = i + 1; j < s.Length; j++)
                {
                    if (s[j] != '\'') continue;
                    if (j + 1 < s.Length && s[j + 1] == '\'') { j++; continue; }
                    return j + 1;
                }
                return s.Length;
            }
            case '"':
            {
                for (var j = i + 1; j < s.Length; j++)
                {
                    var d = s[j];
                    if (d == '`') { j++; continue; }
                    if (d == '$' && j + 1 < s.Length && s[j + 1] == '(')
                    {
                        var close = FindClosing(s, j + 1);
                        if (close < 0) return s.Length;
                        j = close;
                        continue;
                    }
                    if (d == '"')
                    {
                        if (j + 1 < s.Length && s[j + 1] == '"') { j++; continue; }
                        return j + 1;
                    }
                }
                return s.Length;
            }
            default:
                return i;
        }
    }

    private static bool IsHereStringStart(string s, int i)
    {
        // A here-string opener must be followed only by whitespace up to the end of the line.
        for (; i < s.Length; i++)
        {
            if (s[i] == '\n') return true;
            if (!char.IsWhiteSpace(s[i])) return false;
        }
        return false;
    }

    /// <summary>Index of the bracket closing the one at <paramref name="open"/> ('(', '{' or '['), or -1.</summary>
    internal static int FindClosing(string s, int open)
    {
        var depth = 0;
        for (var i = open; i < s.Length; i++)
        {
            var skip = SkipLiteral(s, i);
            if (skip != i) { i = skip - 1; continue; }
            var c = s[i];
            if (c is '(' or '{' or '[') depth++;
            else if (c is ')' or '}' or ']')
            {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    /// <summary>Text between the braces of <c>function Name { ... }</c>, or null.</summary>
    internal static string? ExtractFunctionBody(string script, string functionName)
    {
        var rx = new Regex(@"(?im)^[ \t]*function[ \t]+" + Regex.Escape(functionName) + @"(?![\w-])\s*\{");
        foreach (Match m in rx.Matches(script))
        {
            var open = m.Index + m.Length - 1;
            var close = FindClosing(script, open);
            if (close > open) return script.Substring(open + 1, close - open - 1);
        }
        return null;
    }

    /// <summary>Contents of the top-level <c>param( ... )</c> in a function body, or null.</summary>
    internal static string? ExtractParamBlock(string body)
    {
        for (var i = 0; i < body.Length; i++)
        {
            var skip = SkipLiteral(body, i);
            if (skip != i) { i = skip - 1; continue; }
            var c = body[i];
            if (c is '[' or '{' or '(')
            {
                // attributes such as [CmdletBinding()] or nested blocks
                var close = FindClosing(body, i);
                if (close < 0) return null;
                i = close;
                continue;
            }
            if ((c == 'p' || c == 'P') && (i == 0 || !IsWordChar(body[i - 1])))
            {
                var m = Regex.Match(body.Substring(i, Math.Min(32, body.Length - i)), @"^param\s*\(", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var open = i + m.Length - 1;
                    var close = FindClosing(body, open);
                    return close > open ? body.Substring(open + 1, close - open - 1) : null;
                }
            }
        }
        return null;
    }

    private static bool IsWordChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '$';

    /// <summary>Splits on commas that are not inside brackets, strings or comments.</summary>
    internal static List<string> SplitTopLevel(string text)
    {
        var parts = new List<string>();
        var start = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var skip = SkipLiteral(text, i);
            if (skip != i) { i = skip - 1; continue; }
            var c = text[i];
            if (c is '(' or '{' or '[')
            {
                var close = FindClosing(text, i);
                if (close < 0) break;
                i = close;
                continue;
            }
            if (c == ',')
            {
                parts.Add(text[start..i]);
                start = i + 1;
            }
        }
        parts.Add(text[start..]);
        return parts.Where(p => !string.IsNullOrWhiteSpace(StripComments(p))).ToList();
    }

    private static string StripComments(string s)
    {
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '#' || (s[i] == '<' && i + 1 < s.Length && s[i + 1] == '#'))
            {
                var skip = SkipLiteral(s, i);
                i = skip - 1;
                continue;
            }
            var lit = SkipLiteral(s, i);
            if (lit != i) { sb.Append(s, i, lit - i); i = lit - 1; continue; }
            sb.Append(s[i]);
        }
        return sb.ToString();
    }

    /// <summary>Parses one parameter declaration such as <c>[Parameter(Mandatory)][securestring]$CFToken</c>.</summary>
    internal static PoshAcmeParameter? ParseDeclaration(string declaration)
    {
        var s = StripComments(declaration);
        var p = new PoshAcmeParameter();
        var i = 0;
        while (i < s.Length)
        {
            if (char.IsWhiteSpace(s[i])) { i++; continue; }
            if (s[i] == '[')
            {
                var close = FindClosing(s, i);
                if (close < 0) return null;
                ApplyAttribute(p, s.Substring(i + 1, close - i - 1).Trim());
                i = close + 1;
                continue;
            }
            if (s[i] == '$')
            {
                var m = Regex.Match(s[i..], @"^\$\{?([A-Za-z_][\w]*)\}?\s*(?:=\s*(.*))?$", RegexOptions.Singleline);
                if (!m.Success) return null;
                p.Name = m.Groups[1].Value;
                if (m.Groups[2].Success) p.DefaultValue = ParseLiteral(m.Groups[2].Value.Trim());
                return p;
            }
            return null; // unexpected token
        }
        return null;
    }

    private static void ApplyAttribute(PoshAcmeParameter p, string attr)
    {
        var paren = attr.IndexOf('(');
        if (paren < 0)
        {
            p.Type = NormalizeType(attr);
            return;
        }
        var name = attr[..paren].Trim();
        var close = FindClosing(attr, paren);
        var args = close > paren ? attr.Substring(paren + 1, close - paren - 1) : "";
        if (name.Equals("Parameter", StringComparison.OrdinalIgnoreCase))
        {
            string? set = null;
            var mandatory = false;
            foreach (var a in SplitTopLevel(args).Select(x => x.Trim()))
            {
                var kv = Regex.Match(a, @"^(\w+)\s*(?:=\s*(.+))?$", RegexOptions.Singleline);
                if (!kv.Success) continue;
                var key = kv.Groups[1].Value;
                var val = kv.Groups[2].Success ? kv.Groups[2].Value.Trim() : null;
                var isTrue = val == null || val.Equals("$true", StringComparison.OrdinalIgnoreCase);
                if (key.Equals("Mandatory", StringComparison.OrdinalIgnoreCase)) mandatory = isTrue;
                else if (key.Equals("ParameterSetName", StringComparison.OrdinalIgnoreCase)) set = ParseLiteral(val ?? "");
                else if (key.Equals("ValueFromRemainingArguments", StringComparison.OrdinalIgnoreCase)) p.ValueFromRemainingArguments = isTrue;
            }
            if (set != null && set.Equals("__AllParameterSets", StringComparison.OrdinalIgnoreCase)) set = null;
            p.Usages.Add(new PoshAcmeParameterUsage(set, mandatory));
        }
        else if (name.Equals("ValidateSet", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var a in SplitTopLevel(args))
            {
                var v = ParseLiteral(a.Trim());
                if (v != null && Regex.IsMatch(a.Trim(), "^['\"]")) p.ValidateSet.Add(v);
            }
        }
    }

    /// <summary>Maps PowerShell type literals to the small set of kinds the bridge understands.</summary>
    public static string NormalizeType(string type)
    {
        var t = Regex.Replace(type.Trim(), @"\s+", "").ToLowerInvariant();
        if (t.StartsWith("system.")) t = t[7..];
        return t switch
        {
            "security.securestring" or "securestring" => "securestring",
            "management.automation.pscredential" or "pscredential" => "pscredential",
            "management.automation.switchparameter" or "switchparameter" or "switch" => "switch",
            "boolean" or "bool" => "bool",
            "int" or "int32" or "int64" or "long" or "uint32" or "int16" or "byte" => "int",
            "double" or "single" or "float" or "decimal" => "double",
            "collections.hashtable" or "hashtable" or "collections.idictionary" => "hashtable",
            "string" => "string",
            "string[]" or "object[]" => "string[]",
            _ => t,
        };
    }

    /// <summary>Value of a literal ('x', "x", 123, $true/$false); null for anything that needs evaluation.</summary>
    internal static string? ParseLiteral(string text)
    {
        var t = text.Trim();
        if (t.Length >= 2 && t[0] == '\'' && t[^1] == '\'') return t[1..^1].Replace("''", "'");
        if (t.Length >= 2 && t[0] == '"' && t[^1] == '"')
        {
            var inner = t[1..^1];
            return inner.Contains('$') ? null : inner.Replace("`\"", "\"").Replace("\"\"", "\"");
        }
        if (t.Equals("$true", StringComparison.OrdinalIgnoreCase)) return "true";
        if (t.Equals("$false", StringComparison.OrdinalIgnoreCase)) return "false";
        if (Regex.IsMatch(t, @"^-?\d+(\.\d+)?$")) return t;
        return null;
    }

    /// <summary>.PARAMETER help text by parameter name from comment-based help blocks; also returns .SYNOPSIS.</summary>
    internal static Dictionary<string, string> ParseHelp(string body, out string? synopsis)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        synopsis = null;
        foreach (Match block in Regex.Matches(body, @"<#(.*?)#>", RegexOptions.Singleline))
        {
            var text = block.Groups[1].Value;
            foreach (Match m in Regex.Matches(text, @"^[ \t]*\.(\w+)[ \t]*([^\r\n]*)\r?\n(.*?)(?=^[ \t]*\.\w+|\z)", RegexOptions.Singleline | RegexOptions.Multiline))
            {
                var keyword = m.Groups[1].Value.ToUpperInvariant();
                var content = Regex.Replace(m.Groups[3].Value, @"\s+", " ").Trim();
                if (keyword == "PARAMETER" && m.Groups[2].Value.Trim() is { Length: > 0 } pname) result[pname] = content;
                else if (keyword == "SYNOPSIS" && synopsis == null && content.Length > 0) synopsis = content;
            }
        }
        return result;
    }
}
