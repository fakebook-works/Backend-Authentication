using System.Text;

namespace fakebookAuth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; init; } = "fakebook-auth";
    public string Audience { get; init; } = "fakebook";
    public string SigningKey { get; init; } = string.Empty;
    public int AccessTokenMinutes { get; init; } = 15;

    public int SigningKeyBytes => Encoding.UTF8.GetByteCount(SigningKey);
}

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    public int RefreshTokenDays { get; init; } = 30;
}

public sealed class SnowflakeOptions
{
    public const string SectionName = "Snowflake";

    public int WorkerId { get; init; }
}
