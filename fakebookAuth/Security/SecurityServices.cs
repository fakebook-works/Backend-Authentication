using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

namespace fakebookAuth;

public interface IPasswordHasher
{
    Task<string> HashAsync(string password, CancellationToken cancellationToken);
    Task<bool> VerifyAsync(string password, string passwordHash, CancellationToken cancellationToken);
}

public sealed class PasswordHashingCapacityException : Exception
{
    public PasswordHashingCapacityException()
        : base("The password hashing worker pool is at capacity.")
    {
    }
}

public sealed class BCryptPasswordHasher : IPasswordHasher, IDisposable
{
    private readonly ConcurrencyLimiter _limiter;
    private readonly int _workFactor;
    private readonly TimeSpan _queueTimeout;

    public BCryptPasswordHasher(IOptions<AuthOptions> options)
    {
        var configured = options.Value;
        _workFactor = configured.PasswordHashWorkFactor;
        _queueTimeout = TimeSpan.FromSeconds(configured.PasswordHashQueueTimeoutSeconds);
        _limiter = new ConcurrencyLimiter(new ConcurrencyLimiterOptions
        {
            PermitLimit = configured.PasswordHashMaxConcurrency,
            QueueLimit = configured.PasswordHashQueueLimit,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    }

    public Task<string> HashAsync(string password, CancellationToken cancellationToken) =>
        RunBoundedAsync(() => BCrypt.Net.BCrypt.HashPassword(password, _workFactor), cancellationToken);

    public async Task<bool> VerifyAsync(
        string password,
        string passwordHash,
        CancellationToken cancellationToken)
    {
        try
        {
            return await RunBoundedAsync(
                () => BCrypt.Net.BCrypt.Verify(password, passwordHash),
                cancellationToken);
        }
        catch (PasswordHashingCapacityException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async Task<T> RunBoundedAsync<T>(Func<T> work, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_queueTimeout);

        RateLimitLease lease;
        try
        {
            lease = await _limiter.AcquireAsync(1, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new PasswordHashingCapacityException();
        }

        using (lease)
        {
            if (!lease.IsAcquired)
            {
                throw new PasswordHashingCapacityException();
            }

            // BCrypt is CPU-bound and synchronous. Keep it off request threads while
            // retaining the limiter lease until the native work has actually ended.
            return await Task.Run(work, CancellationToken.None);
        }
    }

    public void Dispose() => _limiter.Dispose();
}

public interface ITokenService
{
    string CreateAccessToken(IdentityUser user, long? sessionId = null);
    string CreateRefreshToken();
    bool TryValidateAccessToken(string token, out AccessTokenPrincipal? principal);
}

public sealed record AccessTokenPrincipal(long UserId, long? SessionId);

public static class JwtKeyMaterial
{
    public static RSA ImportPrivateKey(string value)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(value), out var bytesRead);
            if (bytesRead == 0 || rsa.KeySize < 2048)
            {
                throw new CryptographicException("RSA private key is too small.");
            }

            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public static bool IsValidPrivateKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            using var rsa = ImportPrivateKey(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static bool IsValidKeyId(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 64 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

public sealed class TokenService : ITokenService, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly JwtOptions _options;
    private readonly RSA _privateKey;
    private readonly RSA _publicKey;

    public TokenService(IOptions<JwtOptions> options)
    {
        _options = options.Value;
        _privateKey = JwtKeyMaterial.ImportPrivateKey(_options.PrivateKeyBase64);
        _publicKey = RSA.Create();
        _publicKey.ImportParameters(_privateKey.ExportParameters(includePrivateParameters: false));
    }

    public string CreateAccessToken(IdentityUser user, long? sessionId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(_options.AccessTokenMinutes);

        var header = new Dictionary<string, object?>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["kid"] = _options.KeyId
        };

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["sub"] = user.UserId.ToString(CultureInfo.InvariantCulture),
            ["user_id"] = user.UserId,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N")
        };

        if (sessionId is not null)
        {
            payload["sid"] = sessionId.Value;
        }

        var unsignedToken = $"{EncodeJson(header)}.{EncodeJson(payload)}";
        var signature = WebEncoders.Base64UrlEncode(_privateKey.SignData(
            Encoding.ASCII.GetBytes(unsignedToken),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

        return $"{unsignedToken}.{signature}";
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    public bool TryValidateAccessToken(string token, out AccessTokenPrincipal? principal)
    {
        principal = null;

        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                return false;
            }

            using var header = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[0]));
            if (!header.RootElement.TryGetProperty("alg", out var alg))
            {
                return false;
            }

            var unsignedToken = $"{parts[0]}.{parts[1]}";
            var signature = WebEncoders.Base64UrlDecode(parts[2]);
            var algorithm = alg.GetString();
            var signatureIsValid = algorithm switch
            {
                "RS256" =>
                    header.RootElement.TryGetProperty("kid", out var keyId) &&
                    keyId.GetString() == _options.KeyId &&
                    _publicKey.VerifyData(
                        Encoding.ASCII.GetBytes(unsignedToken),
                        signature,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1),
                "HS256" when !string.IsNullOrEmpty(_options.LegacySigningKey) =>
                    VerifyLegacySignature(unsignedToken, signature, _options.LegacySigningKey),
                _ => false
            };
            if (!signatureIsValid)
            {
                return false;
            }

            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[1]));
            var root = payload.RootElement;

            if (!root.TryGetProperty("iss", out var issuer) ||
                issuer.GetString() != _options.Issuer ||
                !root.TryGetProperty("aud", out var audience) ||
                audience.GetString() != _options.Audience)
            {
                return false;
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!root.TryGetProperty("exp", out var expiresAt) ||
                expiresAt.GetInt64() <= now)
            {
                return false;
            }

            if (root.TryGetProperty("nbf", out var notBefore) &&
                notBefore.GetInt64() > now)
            {
                return false;
            }

            if (!root.TryGetProperty("user_id", out var userIdElement) ||
                !userIdElement.TryGetInt64(out var userId))
            {
                return false;
            }

            long? sessionId = null;
            if (root.TryGetProperty("sid", out var sessionElement) &&
                sessionElement.TryGetInt64(out var parsedSessionId))
            {
                sessionId = parsedSessionId;
            }

            principal = new AccessTokenPrincipal(userId, sessionId);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string EncodeJson(object value)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WebEncoders.Base64UrlEncode(json);
    }

    private static bool VerifyLegacySignature(string token, byte[] signature, string signingKey)
    {
        var expected = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(signingKey),
            Encoding.ASCII.GetBytes(token));
        return expected.Length == signature.Length &&
               CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    public void Dispose()
    {
        _privateKey.Dispose();
        _publicKey.Dispose();
    }
}

public interface ISnowflakeIdGenerator
{
    long NewId();
}

public sealed class SnowflakeIdGenerator(IOptions<SnowflakeOptions> options) : ISnowflakeIdGenerator
{
    private const long EpochMilliseconds = 1704067200000L;
    private const int WorkerIdShift = 12;
    private const int TimestampShift = 22;
    private const long SequenceMask = 4095L;

    private readonly object _sync = new();
    private readonly long _workerId = options.Value.WorkerId;
    private long _lastTimestamp = -1L;
    private long _sequence;

    public long NewId()
    {
        lock (_sync)
        {
            var timestamp = CurrentMilliseconds();

            if (timestamp < _lastTimestamp)
            {
                throw new InvalidOperationException("System clock moved backwards while generating a Snowflake ID.");
            }

            if (timestamp == _lastTimestamp)
            {
                _sequence = (_sequence + 1) & SequenceMask;
                if (_sequence == 0)
                {
                    timestamp = WaitForNextMillisecond(_lastTimestamp);
                }
            }
            else
            {
                _sequence = 0;
            }

            _lastTimestamp = timestamp;

            return ((timestamp - EpochMilliseconds) << TimestampShift) |
                   (_workerId << WorkerIdShift) |
                   _sequence;
        }
    }

    private static long WaitForNextMillisecond(long lastTimestamp)
    {
        var timestamp = CurrentMilliseconds();
        while (timestamp <= lastTimestamp)
        {
            Thread.SpinWait(128);
            timestamp = CurrentMilliseconds();
        }

        return timestamp;
    }

    private static long CurrentMilliseconds() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

public static class TokenHashing
{
    public static string Sha256Hex(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

public static class SessionLifetime
{
    public static DateTimeOffset CapRefreshExpiry(
        DateTimeOffset now,
        int refreshTokenDays,
        DateTimeOffset absoluteExpiresAt)
    {
        var slidingExpiry = now.AddDays(refreshTokenDays);
        return slidingExpiry < absoluteExpiresAt ? slidingExpiry : absoluteExpiresAt;
    }
}

public static class InternalSecretComparer
{
    public static bool FixedTimeEquals(string expected, string provided)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);
        return expectedBytes.Length == providedBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}

public static class OtpGenerator
{
    public static string SixDigitCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
}
