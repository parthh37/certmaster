using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CertMaster.Core.Storage;
using CertMaster.Core.Util;
using CertMaster.Models;
using CertMaster.Models.Hub;
using Microsoft.IdentityModel.Tokens;

namespace CertMaster.Server.Hub.Services;

public static class SecretHash
{
    /// <summary>PBKDF2-SHA256 password hash: "pbkdf2$iterations$salt$hash".</summary>
    public static string HashPassword(string password)
    {
        const int iterations = 210_000;
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return false;
        var p = stored.Split('$');
        if (p.Length != 4 || p[0] != "pbkdf2") return false;
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(p[2]), int.Parse(p[1]), HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(p[3]));
    }

    /// <summary>Random high-entropy token (joining keys, instance secrets, refresh tokens).</summary>
    public static string NewToken(string prefix) => prefix + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    /// <summary>SHA-256 is sufficient for high-entropy random tokens.</summary>
    public static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static bool VerifyToken(string token, string? hash) =>
        hash != null && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(HashToken(token)), Encoding.ASCII.GetBytes(hash));
}

public class HubSettingsFile
{
    public string JwtSecret { get; set; } = "";
    public string Issuer { get; set; } = "CertMaster.Hub";
    public int AuthTokenExpirationMinutes { get; set; } = 60;
    public int RefreshTokenExpirationMinutes { get; set; } = 1440;

    /// <summary>
    /// JWT secret is generated per install (never shipped in appsettings) and stored in hubservice.json. A damaged file is
    /// recovered from its backup; if neither copy can be read, startup fails rather than overwriting the file with defaults.
    /// </summary>
    public static HubSettingsFile LoadOrCreate(DataPaths paths) => LoadOrCreate(paths.Combine("hubservice.json"));

    public static HubSettingsFile LoadOrCreate(string file)
    {
        var s = AtomicFile.Read(file, JsonDefaults.Deserialize<HubSettingsFile>, out var fromBackup);
        if (s == null && AtomicFile.Exists(file))
            throw new InvalidOperationException(
                $"The hub settings file {file} could not be read and has no usable backup. Fix or restore it, or delete it to " +
                "create new settings (everyone will need to sign in again).");
        if (s == null || string.IsNullOrEmpty(s.JwtSecret))
        {
            s ??= new HubSettingsFile();
            s.JwtSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            AtomicFile.WriteAllText(file, JsonDefaults.Serialize(s));
        }
        else if (fromBackup) AtomicFile.WriteAllText(file, JsonDefaults.Serialize(s));
        return s;
    }

    public SymmetricSecurityKey SigningKey => new(Convert.FromBase64String(JwtSecret));
}

internal class StoredUser
{
    public string Id { get; set; } = "";
    public string Username { get; set; } = "";
    public string? Email { get; set; }
    public string? Description { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool IsEnabled { get; set; } = true;
    public DateTimeOffset DateCreated { get; set; }
    public string PasswordHash { get; set; } = "";

    public HubUser ToPublic() => new() { Id = Id, Username = Username, Email = Email, Description = Description, Roles = Roles, IsEnabled = IsEnabled, DateCreated = DateCreated };
}

internal class StoredRefreshToken
{
    public string Id { get; set; } = "";
    public string UserId { get; set; } = "";
    public DateTimeOffset Expiry { get; set; }
}

/// <summary>Users, password login, JWT access tokens and rotating refresh tokens.</summary>
public class AuthService
{
    private const string Users = "users";
    private const string RefreshTokens = "refreshtokens";
    private readonly DocumentStore _store;
    private readonly HubSettingsFile _settings;
    private readonly ILogger<AuthService> _logger;

    public AuthService(DocumentStore store, HubSettingsFile settings, ILogger<AuthService> logger)
    {
        _store = store; _settings = settings; _logger = logger;
    }

    /// <summary>Creates the initial "admin" account on first run and writes its random password to a file in the data folder.</summary>
    public async Task EnsureInitialAdminAsync(DataPaths paths)
    {
        if ((await _store.GetAllAsync<StoredUser>(Users)).Count > 0) return;
        var password = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(12));
        await _store.UpsertAsync(Users, "admin", new StoredUser
        {
            Id = "admin", Username = "admin", Roles = { HubRoles.Administrator }, DateCreated = DateTimeOffset.UtcNow,
            PasswordHash = SecretHash.HashPassword(password), Description = "Initial administrator",
        });
        var file = paths.Combine("initial-admin-password.txt");
        await File.WriteAllTextAsync(file, $"username: admin\npassword: {password}\n\nChange this password after first sign in, then delete this file.\n");
        _logger.LogWarning("Created initial hub administrator 'admin'. Password written to {File}", file);
    }

    public async Task<AuthResponse?> LoginAsync(LoginRequest req)
    {
        var user = (await _store.GetAllAsync<StoredUser>(Users))
            .FirstOrDefault(u => u.Username.Equals(req.Username.Trim(), StringComparison.OrdinalIgnoreCase));
        if (user == null || !user.IsEnabled || !SecretHash.VerifyPassword(req.Password, user.PasswordHash))
        {
            _logger.LogWarning("Failed sign in for {User}", req.Username);
            return null;
        }
        return await IssueAsync(user);
    }

    public async Task<AuthResponse?> RefreshAsync(string refreshToken)
    {
        var id = SecretHash.HashToken(refreshToken);
        var stored = await _store.GetAsync<StoredRefreshToken>(RefreshTokens, id);
        if (stored == null) return null;
        await _store.DeleteAsync(RefreshTokens, id); // rotate: one use only
        if (stored.Expiry < DateTimeOffset.UtcNow) return null;
        var user = await _store.GetAsync<StoredUser>(Users, stored.UserId);
        return user is { IsEnabled: true } ? await IssueAsync(user) : null;
    }

    public Task LogoutAsync(string refreshToken) => _store.DeleteAsync(RefreshTokens, SecretHash.HashToken(refreshToken));

    private async Task<AuthResponse> IssueAsync(StoredUser user)
    {
        var expiry = DateTimeOffset.UtcNow.AddMinutes(_settings.AuthTokenExpirationMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.UniqueName, user.Username),
            new(ClaimTypes.Name, user.Username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        claims.AddRange(user.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
        var token = new JwtSecurityToken(_settings.Issuer, _settings.Issuer, claims, expires: expiry.UtcDateTime,
            signingCredentials: new SigningCredentials(_settings.SigningKey, SecurityAlgorithms.HmacSha256));

        var refresh = SecretHash.NewToken("cmrt_");
        await _store.UpsertAsync(RefreshTokens, SecretHash.HashToken(refresh), new StoredRefreshToken
        {
            Id = SecretHash.HashToken(refresh), UserId = user.Id, Expiry = DateTimeOffset.UtcNow.AddMinutes(_settings.RefreshTokenExpirationMinutes),
        });
        return new AuthResponse
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token), RefreshToken = refresh,
            AccessTokenExpiry = expiry, Username = user.Username, Roles = user.Roles,
        };
    }

    // ---- user management ----

    public async Task<List<HubUser>> GetUsersAsync() => (await _store.GetAllAsync<StoredUser>(Users)).Select(u => u.ToPublic()).ToList();

    public async Task<ActionResult> UpdateUserAsync(HubUser user)
    {
        if (string.IsNullOrWhiteSpace(user.Username)) return ActionResult.Fail("Username is required");
        if (user.Roles.Any(r => !HubRoles.All.Contains(r))) return ActionResult.Fail("Unknown role");
        var all = await _store.GetAllAsync<StoredUser>(Users);
        if (all.Any(u => u.Id != user.Id && u.Username.Equals(user.Username, StringComparison.OrdinalIgnoreCase)))
            return ActionResult.Fail("Username already exists");
        var existing = all.FirstOrDefault(u => u.Id == user.Id);
        if (existing == null && string.IsNullOrEmpty(user.Password)) return ActionResult.Fail("Password is required for new users");
        if (!string.IsNullOrEmpty(user.Password) && user.Password.Length < 10) return ActionResult.Fail("Password must be at least 10 characters");
        if (existing != null && existing.Roles.Contains(HubRoles.Administrator) && !user.Roles.Contains(HubRoles.Administrator)
            && all.Count(u => u.Roles.Contains(HubRoles.Administrator) && u.IsEnabled) <= 1)
            return ActionResult.Fail("Cannot remove the last administrator");

        var stored = existing ?? new StoredUser { Id = string.IsNullOrEmpty(user.Id) ? Guid.NewGuid().ToString() : user.Id, DateCreated = DateTimeOffset.UtcNow };
        stored.Username = user.Username.Trim(); stored.Email = user.Email; stored.Description = user.Description;
        stored.Roles = user.Roles.Distinct().ToList(); stored.IsEnabled = user.IsEnabled;
        if (!string.IsNullOrEmpty(user.Password)) stored.PasswordHash = SecretHash.HashPassword(user.Password);
        await _store.UpsertAsync(Users, stored.Id, stored);
        return ActionResult.Ok("User saved");
    }

    public async Task<ActionResult> DeleteUserAsync(string id, string currentUserId)
    {
        if (id == currentUserId) return ActionResult.Fail("You cannot delete your own account");
        var all = await _store.GetAllAsync<StoredUser>(Users);
        var u = all.FirstOrDefault(x => x.Id == id);
        if (u == null) return ActionResult.Fail("User not found");
        if (u.Roles.Contains(HubRoles.Administrator) && all.Count(x => x.Roles.Contains(HubRoles.Administrator)) <= 1)
            return ActionResult.Fail("Cannot delete the last administrator");
        await _store.DeleteAsync(Users, id);
        return ActionResult.Ok("User deleted");
    }

    public async Task<ActionResult> ChangePasswordAsync(string userId, ChangePasswordRequest req)
    {
        var u = await _store.GetAsync<StoredUser>(Users, userId);
        if (u == null || !SecretHash.VerifyPassword(req.CurrentPassword, u.PasswordHash)) return ActionResult.Fail("Current password is incorrect");
        if (req.NewPassword.Length < 10) return ActionResult.Fail("New password must be at least 10 characters");
        u.PasswordHash = SecretHash.HashPassword(req.NewPassword);
        await _store.UpsertAsync(Users, u.Id, u);
        return ActionResult.Ok("Password changed");
    }
}
