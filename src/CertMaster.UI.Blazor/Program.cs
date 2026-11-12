using CertMaster.UI.Blazor;
using CertMaster.UI.Blazor.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(_ => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped<HubSession>();
builder.Services.AddScoped<HubClient>();
builder.Services.AddMudServices(c =>
{
    c.SnackbarConfiguration.PositionClass = MudBlazor.Defaults.Classes.Position.BottomRight;
    c.SnackbarConfiguration.VisibleStateDuration = 5000;
});

await builder.Build().RunAsync();
