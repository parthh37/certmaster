using System.Threading.RateLimiting;
using CertMaster.Core.Storage;
using CertMaster.Hosting;
using CertMaster.Models;
using CertMaster.Server.Hub;
using CertMaster.Server.Hub.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Serilog;

const string ServiceName = "CertMaster Management Hub";

DataPaths paths;
try { paths = new DataPaths(Environment.GetEnvironmentVariable("CERTMASTER_HUB_DATA"), "CertMasterHub"); }
catch (Exception ex)
{
    ServiceHosting.ReportEarlyFailure(ServiceName, "CertMaster Management Hub could not create its data folder.", ex);
    return 1;
}

Log.Logger = ServiceHosting.CreateLogger(Path.Combine(paths.Logs, "hub.log"), ServiceName);
ServiceHosting.HookProcessErrors();

try
{
    try { paths.HardenPermissions(); }
    catch (Exception ex) { Log.Warning(ex, "Could not restrict permissions on the data folder {Path}", paths.Root); }

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") });
    builder.Host.UseWindowsService(o => o.ServiceName = ServiceName);
    builder.Host.UseSerilog();

    // The installer owns appsettings.Installer.json (port and bind address chosen in setup) and rewrites it on upgrade.
    // It is loaded right after appsettings.json, so anything an administrator puts in appsettings.Production.json
    // (HTTPS endpoints, certificates, URLs) still wins and survives upgrades.
    var sources = ((IConfigurationBuilder)builder.Configuration).Sources;
    var baseJson = sources.OfType<JsonConfigurationSource>().FirstOrDefault(s => string.Equals(s.Path, "appsettings.json", StringComparison.OrdinalIgnoreCase));
    var installerJson = new JsonConfigurationSource { Path = Path.Combine(AppContext.BaseDirectory, "appsettings.Installer.json"), Optional = true, ReloadOnChange = false };
    installerJson.ResolveFileProvider();
    if (baseJson != null) sources.Insert(sources.IndexOf(baseJson) + 1, installerJson);
    else sources.Insert(0, installerJson);

    if (builder.Configuration["Hub:Url"] is { Length: > 0 } url) builder.WebHost.UseUrls(url);
    else if (builder.Configuration["urls"] == null && builder.Configuration.GetSection("Kestrel:Endpoints").GetChildren().Any() == false)
        builder.WebHost.UseUrls("http://*:9697");

    var hubSettings = HubSettingsFile.LoadOrCreate(paths);
    builder.Services.AddSingleton(paths);
    builder.Services.AddSingleton(hubSettings);
    builder.Services.AddSingleton(sp => DocumentStore.OpenWithRecovery(Path.Combine(paths.Root, "hub.db"), paths.Combine("backups"), sp.GetRequiredService<ILogger<DocumentStore>>()));
    builder.Services.AddSingleton<AuthService>();
    builder.Services.AddSingleton<InstanceRegistry>();
    builder.Services.AddSingleton<InstanceGateway>();
    builder.Services.AddHostedService<HubMaintenanceService>();
    builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(30));

    builder.Services.ConfigureHttpJsonOptions(o => JsonDefaults.Apply(o.SerializerOptions));
    builder.Services.AddSignalR(o =>
    {
        o.MaximumReceiveMessageSize = 16 * 1024 * 1024; // agent command results (cert lists, downloads)
        o.ClientTimeoutInterval = TimeSpan.FromSeconds(60);
    }).AddJsonProtocol(o => JsonDefaults.Apply(o.PayloadSerializerOptions));

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = hubSettings.Issuer, ValidAudience = hubSettings.Issuer, IssuerSigningKey = hubSettings.SigningKey,
            ValidateIssuer = true, ValidateAudience = true, ValidateIssuerSigningKey = true, ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = System.Security.Claims.ClaimTypes.Role, NameClaimType = System.Security.Claims.ClaimTypes.Name,
        };
    });
    builder.Services.AddAuthorizationBuilder()
        .AddPolicy(HubPolicies.Admin, p => p.RequireRole(CertMaster.Models.Hub.HubRoles.Administrator))
        .AddPolicy(HubPolicies.Manage, p => p.RequireRole(CertMaster.Models.Hub.HubRoles.Administrator, CertMaster.Models.Hub.HubRoles.CertificateManager));

    // Per calling IP limits for unauthenticated endpoints.
    builder.Services.AddRateLimiter(o =>
    {
        o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(1) }));
        o.AddPolicy("refresh", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1) }));
    });
    builder.Services.AddOpenApi();

    var app = builder.Build();
    await app.Services.GetRequiredService<AuthService>().EnsureInitialAdminAsync(paths);

    // Unexpected errors become JSON problem responses (logged), never a leaked stack trace.
    app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
    {
        var ex = ctx.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
        Log.Error(ex, "Unhandled API error on {Path}", ctx.Request.Path);
        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await ctx.Response.WriteAsJsonAsync(new { title = "Request failed", status = ctx.Response.StatusCode });
    }));

    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapOpenApi("/openapi/{documentName}.json");
    app.MapScalarApiReference("/docs");

    // Join attempts are limited per IP inside InstanceHub.Register (failed attempts only), not per transport request.
    app.MapHub<InstanceHub>("/api/internal/instances").AllowAnonymous();
    app.MapHubApi();

    // Blazor WebAssembly UI
    app.UseBlazorFrameworkFiles();
    app.UseStaticFiles();
    app.MapFallbackToFile("index.html");

    Log.Information("CertMaster Management Hub starting as {Mode}. Data: {Path}",
        ServiceHosting.IsWindowsService ? "a Windows service" : "a console app", paths.Root);
    await app.RunAsync();

    if (ServiceHosting.AnyBackgroundServiceFaulted(app.Services)) return 1;
    Log.Information("CertMaster Management Hub stopped");
    return 0;
}
catch (Exception ex)
{
    // Typical causes: the port is already in use, a damaged database or hubservice.json with no usable backup.
    Log.Fatal(ex, "CertMaster Management Hub failed to start or stopped unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}
