using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Hosting;
using CertMaster.Models;
using CertMaster.Server.Core;
using Serilog;

const string ServiceName = "CertMaster Agent";

DataPaths paths;
try { paths = new DataPaths(); }
catch (Exception ex)
{
    ServiceHosting.ReportEarlyFailure(ServiceName, "CertMaster Agent could not create its data folder.", ex);
    return 1;
}

Log.Logger = ServiceHosting.CreateLogger(Path.Combine(paths.Logs, "service.log"), ServiceName);
ServiceHosting.HookProcessErrors();

try
{
    try { paths.HardenPermissions(); }
    catch (Exception ex) { Log.Warning(ex, "Could not restrict permissions on the data folder {Path}", paths.Root); }

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
    builder.Host.UseWindowsService(o => o.ServiceName = ServiceName);
    builder.Host.UseSerilog();
    builder.WebHost.UseUrls(builder.Configuration["Agent:Url"] ?? "http://127.0.0.1:9696");

    // Outbound proxy for the CA, DNS APIs, webhooks and the hub connection. LocalSystem does not use the machine WinHTTP
    // proxy, so servers behind a proxy set Agent:Proxy (appsettings.Production.json next to the service, or the machine
    // environment variable Agent__Proxy). HTTPS_PROXY / NO_PROXY machine environment variables also work.
    if (builder.Configuration["Agent:Proxy"] is { Length: > 0 } proxyUrl)
    {
        var bypass = (builder.Configuration["Agent:ProxyBypass"] ?? "")
            .Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => "^" + System.Text.RegularExpressions.Regex.Escape(p).Replace("\\*", ".*") + "$").ToArray();
        System.Net.Http.HttpClient.DefaultProxy = new System.Net.WebProxy(proxyUrl, BypassOnLocal: true, bypass);
        Log.Information("Using outbound HTTP proxy {Proxy} (bypass: local names{Bypass})", proxyUrl,
            bypass.Length > 0 ? ", " + builder.Configuration["Agent:ProxyBypass"] : "");
    }

    builder.Services.ConfigureHttpJsonOptions(o => JsonDefaults.Apply(o.SerializerOptions));
    builder.Services.AddSignalR().AddJsonProtocol(o => JsonDefaults.Apply(o.PayloadSerializerOptions));

    builder.Services.AddSingleton(paths);
    builder.Services.AddSingleton(sp => DocumentStore.OpenWithRecovery(paths.Database, paths.Combine("backups"), sp.GetRequiredService<ILogger<DocumentStore>>()));
    builder.Services.AddSingleton<SecretProtector>();
    builder.Services.AddSingleton<CredentialsManager>();
    builder.Services.AddSingleton<AcmeService>();
    builder.Services.AddSingleton(new ProviderRegistry());
    builder.Services.AddSingleton<HttpChallengeServer>();
    builder.Services.AddSingleton<AgentIdentity>();
    builder.Services.AddSingleton<CertManager>();
    builder.Services.AddSingleton<InstanceCommandHandler>();
    builder.Services.AddSingleton<HubClientService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<HubClientService>());
    builder.Services.AddHostedService<RenewalBackgroundService>();
    builder.Services.AddHostedService<MaintenanceService>();
    builder.Services.AddSingleton<SignalRProgressReporter>();
    builder.Services.AddProblemDetails();
    // Give running certificate requests time to finish cleanly when the service stops.
    builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(60));

    var app = builder.Build();

    // Unexpected errors become JSON problem responses (logged), never a crashed request or leaked stack trace.
    app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
    {
        var ex = ctx.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
        Log.Error(ex, "Unhandled API error on {Path}", ctx.Request.Path);
        ctx.Response.StatusCode = ex is ArgumentException or InvalidOperationException ? 400 : 500;
        await ctx.Response.WriteAsJsonAsync(new { title = "Request failed", detail = ex?.Message, status = ctx.Response.StatusCode });
    }));

    // wire progress reporting (SignalR + hub forwarding) into the engine
    app.Services.GetRequiredService<CertManager>().ProgressReporter = app.Services.GetRequiredService<SignalRProgressReporter>();
    var identity = app.Services.GetRequiredService<AgentIdentity>();

    // Local API authentication: every /api call needs the per-install API key (header, or access_token for SignalR websockets).
    app.Use(async (ctx, next) =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api") && !ctx.Request.Path.StartsWithSegments("/api/system/health"))
        {
            var key = ctx.Request.Headers[AgentIdentity.ApiKeyHeader].FirstOrDefault() ?? ctx.Request.Query["access_token"].FirstOrDefault();
            if (!identity.IsValidKey(key)) { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return; }
        }
        await next();
    });

    app.MapHub<StatusHub>(StatusHub.Path);
    app.MapAgentApi();

    Log.Information("CertMaster Agent {Version} starting as {Mode}. Data: {Path}", identity.Version,
        ServiceHosting.IsWindowsService ? "a Windows service" : "a console app", paths.Root);
    await app.RunAsync();

    if (ServiceHosting.AnyBackgroundServiceFaulted(app.Services)) return 1;
    Log.Information("CertMaster Agent stopped");
    return 0;
}
catch (Exception ex)
{
    // Typical causes: port 9696 already in use, a damaged database with no usable backup, an unreadable key file.
    Log.Fatal(ex, "CertMaster Agent failed to start or stopped unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}
