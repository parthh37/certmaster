using System.Threading.RateLimiting;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Server.Hub;
using CertMaster.Server.Hub.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Serilog;

var paths = new DataPaths(Environment.GetEnvironmentVariable("CERTMASTER_HUB_DATA"), "CertMasterHub");
try { paths.HardenPermissions(); } catch (Exception ex) { Console.Error.WriteLine("Could not restrict data folder permissions: " + ex.Message); }

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
    .WriteTo.Console()
    .WriteTo.File(Path.Combine(paths.Logs, "hub.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") });
builder.Host.UseWindowsService(o => o.ServiceName = "CertMaster Management Hub");
builder.Host.UseSerilog();
if (builder.Configuration["Hub:Url"] is { } url) builder.WebHost.UseUrls(url);
else if (builder.Configuration["ASPNETCORE_URLS"] == null && builder.Configuration["urls"] == null) builder.WebHost.UseUrls("http://0.0.0.0:9697");

var hubSettings = HubSettingsFile.LoadOrCreate(paths);
builder.Services.AddSingleton(paths);
builder.Services.AddSingleton(hubSettings);
builder.Services.AddSingleton(_ => new DocumentStore(Path.Combine(paths.Root, "hub.db")));
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<InstanceRegistry>();
builder.Services.AddSingleton<InstanceGateway>();

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

Log.Information("CertMaster Management Hub starting. Data: {Path}", paths.Root);
app.Run();
