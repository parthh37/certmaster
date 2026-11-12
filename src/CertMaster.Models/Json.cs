using System.Text.Json;
using System.Text.Json.Serialization;

namespace CertMaster.Models;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = Create();

    public static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = false };
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }

    /// <summary>Applies CertMaster defaults to an existing options instance (e.g. ASP.NET Core / SignalR options).</summary>
    public static void Apply(JsonSerializerOptions o)
    {
        o.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        o.PropertyNameCaseInsensitive = true;
        if (!o.Converters.OfType<JsonStringEnumConverter>().Any()) o.Converters.Add(new JsonStringEnumConverter());
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T? Deserialize<T>(string? json) => string.IsNullOrEmpty(json) ? default : JsonSerializer.Deserialize<T>(json, Options);
    public static T Clone<T>(T value) => Deserialize<T>(Serialize(value))!;
}
