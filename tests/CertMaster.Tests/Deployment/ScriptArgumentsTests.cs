using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Util;

namespace CertMaster.Tests.Deployment;

public class ScriptArgumentsTests
{
    [Fact]
    public void Parses_named_pairs()
    {
        var args = ScriptArguments.Parse("arg1=value;arg2=value two");
        Assert.Equal(new[] { new ScriptArgument("arg1", "value"), new ScriptArgument("arg2", "value two") }, args);
    }

    [Fact]
    public void Escaped_separators_are_literal()
    {
        var args = ScriptArguments.Parse(@"conn=Server=x\;Db=y;eq=a\=b;path=C:\temp\certs");
        Assert.Equal(3, args.Count);
        Assert.Equal(new ScriptArgument("conn", "Server=x;Db=y"), args[0]);
        Assert.Equal(new ScriptArgument("eq", "a=b"), args[1]);
        Assert.Equal(new ScriptArgument("path", @"C:\temp\certs"), args[2]); // other backslashes are kept
    }

    [Fact]
    public void Only_first_equals_splits_and_values_may_contain_equals()
    {
        var args = ScriptArguments.Parse("token=abc==");
        Assert.Equal(new ScriptArgument("token", "abc=="), Assert.Single(args));
    }

    [Fact]
    public void Escaped_equals_in_name_and_positional_entries()
    {
        var args = ScriptArguments.Parse(@"plain;x=1;a\=b");
        Assert.Equal(new ScriptArgument(null, "plain"), args[0]);
        Assert.Equal(new ScriptArgument("x", "1"), args[1]);
        Assert.Equal(new ScriptArgument(null, "a=b"), args[2]);
    }

    [Fact]
    public void Empty_entries_and_whitespace_are_ignored()
    {
        var args = ScriptArguments.Parse(" a = 1 ;; ;b=2;");
        Assert.Equal(new[] { new ScriptArgument("a", "1"), new ScriptArgument("b", "2") }, args);
        Assert.Empty(ScriptArguments.Parse(null));
        Assert.Empty(ScriptArguments.Parse("   "));
    }

    [Fact]
    public void Empty_value_is_allowed()
    {
        Assert.Equal(new ScriptArgument("flag", ""), Assert.Single(ScriptArguments.Parse("flag=")));
    }

    [Theory]
    [InlineData("=value")]
    [InlineData("bad name=1")]
    [InlineData("a$b=1")]
    public void Invalid_names_throw(string text) => Assert.Throws<FormatException>(() => ScriptArguments.Parse(text));

    [Theory]
    [InlineData("a=1", true)]
    [InlineData("one;two", true)]
    [InlineData("-Force -Name x", false)]
    [InlineData(@"only\=escaped", false)]
    [InlineData(null, false)]
    public void Detects_named_syntax(string? text, bool expected) => Assert.Equal(expected, ScriptArguments.UsesNamedSyntax(text));

    [Fact]
    public void Converts_to_argument_list()
    {
        var list = ScriptArguments.ToArgumentList(ScriptArguments.Parse("pos;Name=v;-Dash=w"));
        Assert.Equal(new[] { "pos", "-Name", "v", "-Dash", "w" }, list);
    }

    [Theory]
    [InlineData("simple", "simple")]
    [InlineData("with space", "\"with space\"")]
    [InlineData("", "\"\"")]
    [InlineData("quote\"inside", "\"quote\\\"inside\"")]
    [InlineData(@"C:\path with space\", "\"C:\\path with space\\\\\"")]
    public void Quotes_windows_arguments(string arg, string expected) => Assert.Equal(expected, ProcessRunner.QuoteWindowsArgument(arg));

    [Fact]
    public void Posix_quoting_escapes_single_quotes() => Assert.Equal("'it'\\''s'", ProcessRunner.QuotePosixArgument("it's"));
}
