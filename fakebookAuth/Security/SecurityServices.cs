using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
    private const int MaximumTokenSizeInBytes = 16 * 1024;
    private readonly JwtOptions _options;
    private readonly RSA _privateKey;
    private readonly RSA _publicKey;
    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _validationKey;
    private readonly SymmetricSecurityKey? _legacyValidationKey;
    private readonly JwtSecurityTokenHandler _handler;
    private readonly TokenValidationParameters _validationParameters;

    public TokenService(IOptions<JwtOptions> options)
    {
        _options = options.Value;
        _privateKey = JwtKeyMaterial.ImportPrivateKey(_options.PrivateKeyBase64);
        _publicKey = RSA.Create();
        _publicKey.ImportParameters(_privateKey.ExportParameters(includePrivateParameters: false));
        _signingKey = new RsaSecurityKey(_privateKey) { KeyId = _options.KeyId };
        _validationKey = new RsaSecurityKey(_publicKey) { KeyId = _options.KeyId };
        _legacyValidationKey = string.IsNullOrEmpty(_options.LegacySigningKey)
            ? null
            : new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.LegacySigningKey))
            {
                KeyId = "legacy-hs256"
            };
        _handler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false,
            MaximumTokenSizeInBytes = MaximumTokenSizeInBytes,
            SetDefaultTimesOnTokenCreation = false
        };

        var validationKeys = _legacyValidationKey is null
            ? new SecurityKey[] { _validationKey }
            : new SecurityKey[] { _validationKey, _legacyValidationKey };
        var validAlgorithms = _legacyValidationKey is null
            ? new[] { SecurityAlgorithms.RsaSha256 }
            : new[] { SecurityAlgorithms.RsaSha256, SecurityAlgorithms.HmacSha256 };

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = validationKeys,
            ValidAlgorithms = validAlgorithms,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            TryAllIssuerSigningKeys = _legacyValidationKey is not null,
            AlgorithmValidator = ValidateAlgorithm
        };
    }

    public string CreateAccessToken(IdentityUser user, long? sessionId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(_options.AccessTokenMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.UserId.ToString(CultureInfo.InvariantCulture)),
            new("user_id", user.UserId.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        if (sessionId is not null)
        {
            claims.Add(new Claim(
                "sid",
                sessionId.Value.ToString(CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64));
        }

        return _handler.CreateEncodedJwt(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256)
        });
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    public bool TryValidateAccessToken(string token, out AccessTokenPrincipal? principal)
    {
        principal = null;
        if (string.IsNullOrWhiteSpace(token) ||
            Encoding.UTF8.GetByteCount(token) > MaximumTokenSizeInBytes)
        {
            return false;
        }

        try
        {
            var claims = _handler.ValidateToken(token, _validationParameters, out var validatedToken);
            if (validatedToken is not JwtSecurityToken ||
                !long.TryParse(
                    claims.FindFirst("user_id")?.Value,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var userId) ||
                userId <= 0)
            {
                return false;
            }

            long? sessionId = null;
            var sessionClaim = claims.FindFirst("sid")?.Value;
            if (sessionClaim is not null)
            {
                if (!long.TryParse(
                        sessionClaim,
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out var parsedSessionId) ||
                    parsedSessionId <= 0)
                {
                    return false;
                }

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

    private bool ValidateAlgorithm(
        string algorithm,
        SecurityKey securityKey,
        SecurityToken _,
        TokenValidationParameters __) =>
        algorithm switch
        {
            SecurityAlgorithms.RsaSha256 =>
                securityKey is RsaSecurityKey rsaKey &&
                rsaKey.KeyId == _options.KeyId,
            SecurityAlgorithms.HmacSha256 =>
                _legacyValidationKey is not null &&
                ReferenceEquals(securityKey, _legacyValidationKey),
            _ => false
        };

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
