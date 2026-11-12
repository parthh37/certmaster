using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Server.Core;
using Serilog;

var paths = new DataPaths();
try { paths.HardenPermissions(); } catch (Exception ex) { Console.Error.WriteLine("Could not restrict data folder permissions: " + ex.Message); }

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
    .WriteTo.Console()
    .WriteTo.File(Path.Combine(paths.Logs, "service.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Host.UseWindowsService(o => o.ServiceName = "CertMaster Agent");
builder.Host.UseSerilog();
builder.WebHost.UseUrls(builder.Configuration["Agent:Url"] ?? "http://127.0.0.1:9696");

builder.Services.ConfigureHttpJsonOptions(o => JsonDefaults.Apply(o.SerializerOptions));
builder.Services.AddSignalR().AddJsonProtocol(o => JsonDefaults.Apply(o.PayloadSerializerOptions));

builder.Services.AddSingleton(paths);
builder.Services.AddSingleton(sp => new DocumentStore(paths.Database));
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
builder.Services.AddSingleton<SignalRProgressReporter>();

var app = builder.Build();

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

Log.Information("CertMaster Agent {Version} starting. Data: {Path}", identity.Version, paths.Root);
app.Run();
