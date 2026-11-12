using System.Text;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>One script argument: named (Name = value) or positional (Name is null).</summary>
public sealed record ScriptArgument(string? Name, string Value);

/// <summary>
/// Parses script arguments written as <c>arg1=value;arg2=value</c>. A backslash escapes a separator: <c>\;</c> is a literal
/// semicolon and <c>\=</c> a literal equals sign; any other backslash is kept as-is (so Windows paths need no escaping).
/// Entries without an unescaped '=' are positional. Only the first unescaped '=' splits name and value.
/// </summary>
public static class ScriptArguments
{
    public static List<ScriptArgument> Parse(string? text)
    {
        var result = new List<ScriptArgument>();
        if (string.IsNullOrWhiteSpace(text)) return result;

        var name = new StringBuilder();
        var value = new StringBuilder();
        var inValue = false;
        var hasEquals = false;

        void Flush()
        {
            var n = name.ToString().Trim();
            var v = value.ToString().Trim();
            if (!hasEquals)
            {
                if (n.Length > 0) result.Add(new ScriptArgument(null, n));
            }
            else
            {
                if (n.Length == 0) throw new FormatException($"Argument '={v}' has no name. Use name=value or escape '=' as \\=.");
                if (!IsValidName(n)) throw new FormatException($"Invalid argument name '{n}'. Use letters, digits, '_' or '-'.");
                result.Add(new ScriptArgument(n, v));
            }
            name.Clear(); value.Clear(); inValue = false; hasEquals = false;
        }

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] is ';' or '=')
            {
                (inValue ? value : name).Append(text[i + 1]);
                i++;
                continue;
            }
            if (c == ';') { Flush(); continue; }
            if (c == '=' && !inValue) { inValue = true; hasEquals = true; continue; }
            (inValue ? value : name).Append(c);
        }
        Flush();
        return result;
    }

    public static bool IsValidName(string name) =>
        name.Length > 0 && name.TrimStart('-').Length > 0 && name.TrimStart('-').All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '-');

    /// <summary>True when the text uses the name=value;... syntax (an unescaped '=' or ';' is present).</summary>
    public static bool UsesNamedSyntax(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\' && i + 1 < text.Length && text[i + 1] is ';' or '=') { i++; continue; }
            if (text[i] is '=' or ';') return true;
        }
        return false;
    }

    /// <summary>
    /// Converts parsed arguments into a plain argument list for non-PowerShell scripts: positional values as-is,
    /// named arguments as "-name value".
    /// </summary>
    public static List<string> ToArgumentList(IEnumerable<ScriptArgument> args)
    {
        var list = new List<string>();
        foreach (var a in args)
        {
            if (a.Name != null) list.Add(a.Name.StartsWith('-') ? a.Name : "-" + a.Name);
            list.Add(a.Value);
        }
        return list;
    }
}
