using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace fakebookAuth;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string passwordHash);
}

public sealed class BCryptPasswordHasher : IPasswordHasher
{
    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password);

    public bool Verify(string password, string passwordHash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch (Exception)
        {
            return false;
        }
    }
}

public interface ITokenService
{
    string CreateAccessToken(IdentityUser user);
    string CreateRefreshToken();
}

public sealed class TokenService(IOptions<JwtOptions> options) : ITokenService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly JwtOptions _options = options.Value;

    public string CreateAccessToken(IdentityUser user)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(_options.AccessTokenMinutes);

        var header = new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT"
        };

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["sub"] = user.UserId.ToString(CultureInfo.InvariantCulture),
            ["user_id"] = user.UserId,
            ["username"] = user.Username,
            ["name"] = user.DisplayName,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N")
        };

        var unsignedToken = $"{EncodeJson(header)}.{EncodeJson(payload)}";
        var signature = Sign(unsignedToken, _options.SigningKey);

        return $"{unsignedToken}.{signature}";
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    private static string EncodeJson(object value)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WebEncoders.Base64UrlEncode(json);
    }

    private static string Sign(string token, string signingKey)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(signingKey));
        var signature = hmac.ComputeHash(Encoding.ASCII.GetBytes(token));
        return WebEncoders.Base64UrlEncode(signature);
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

public static class OtpGenerator
{
    public static string SixDigitCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
}
