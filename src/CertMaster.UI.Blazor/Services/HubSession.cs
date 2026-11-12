using CertMaster.Models;
using CertMaster.Models.Hub;
using Microsoft.JSInterop;

namespace CertMaster.UI.Blazor.Services;

/// <summary>Holds the signed-in user's tokens (persisted in localStorage).</summary>
public class HubSession
{
    private const string StorageKey = "certmaster.auth";
    private readonly IJSRuntime _js;
    private bool _loaded;

    public HubSession(IJSRuntime js) => _js = js;

    public AuthResponse? Current { get; private set; }
    public bool IsAuthenticated => Current != null;
    public string? Username => Current?.Username;
    public event Action? Changed;

    public bool IsAdmin => Current?.Roles.Contains(HubRoles.Administrator) == true;
    public bool CanManage => IsAdmin || Current?.Roles.Contains(HubRoles.CertificateManager) == true;

    public async Task EnsureLoadedAsync()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            var json = await _js.InvokeAsync<string?>("localStorage.getItem", StorageKey);
            Current = JsonDefaults.Deserialize<AuthResponse>(json);
        }
        catch { Current = null; }
    }

    public async Task SetAsync(AuthResponse? auth)
    {
        Current = auth;
        if (auth == null) await _js.InvokeVoidAsync("localStorage.removeItem", StorageKey);
        else await _js.InvokeVoidAsync("localStorage.setItem", StorageKey, JsonDefaults.Serialize(auth));
        Changed?.Invoke();
    }
}
