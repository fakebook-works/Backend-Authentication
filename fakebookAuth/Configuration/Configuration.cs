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
    public int EmailVerificationMinutes { get; init; } = 15;
    public int PasswordResetMinutes { get; init; } = 15;
    public int OtpCooldownSeconds { get; init; } = 60;
    public int OtpFailureLimit { get; init; } = 5;
    public int OtpFailureWindowMinutes { get; init; } = 15;
    public int OtpResendLimit { get; init; } = 3;
    public int OtpResendWindowMinutes { get; init; } = 15;
    public int LoginFailureLimit { get; init; } = 5;
    public int LoginFailureWindowMinutes { get; init; } = 15;
    public int PasswordHashWorkFactor { get; init; } = 11;
    public int PasswordHashMaxConcurrency { get; init; } = 2;
    public int PasswordHashQueueLimit { get; init; } = 16;
    public int PasswordHashQueueTimeoutSeconds { get; init; } = 5;
    public string RefreshTokenCookieName { get; init; } = "fb_refresh";
    // Scoped to the Gateway GraphQL endpoint, the only path that reads this cookie. At "/" the
    // browser also attached this 30-day credential to every /media request, sending it to the
    // Upload server on the same edge origin.
    public string RefreshTokenCookiePath { get; init; } = "/graphql";
    public string RefreshTokenCookieSameSite { get; init; } = "Lax";
    public bool RefreshTokenCookieHttpOnly { get; init; } = true;
    public bool RefreshTokenCookieSecure { get; init; } = true;

    public int RefreshTokenCookieMaxAgeSeconds =>
        checked(RefreshTokenDays * 24 * 60 * 60);
}

public sealed class GatewayOptions
{
    public const string SectionName = "Gateway";

    public string InternalSharedSecret { get; init; } = string.Empty;

    public string AuthenticationServiceSharedSecret { get; init; } = string.Empty;

    public int InternalSharedSecretBytes => Encoding.UTF8.GetByteCount(InternalSharedSecret);

    public int AuthenticationServiceSharedSecretBytes =>
        Encoding.UTF8.GetByteCount(AuthenticationServiceSharedSecret);

    public string ResolvedAuthenticationServiceSharedSecret =>
        AuthenticationServiceSharedSecret;
}

public sealed class PaymentOptions
{
    public const string SectionName = "Payment";

    public string InternalSharedSecret { get; init; } = string.Empty;

    public int InternalSharedSecretBytes => Encoding.UTF8.GetByteCount(InternalSharedSecret);
}

public sealed class SmtpOptions
{
    public const string SectionName = "Smtp";

    public bool Enabled { get; init; }
    public string Host { get; init; } = "smtp.gmail.com";
    public int Port { get; init; } = 587;
    public bool EnableSsl { get; init; } = true;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string FromEmail { get; init; } = string.Empty;
    public string FromName { get; init; } = "Fakebook";

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host) &&
        Port > 0 &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Password) &&
        !string.IsNullOrWhiteSpace(FromEmail);
}

public sealed class SnowflakeOptions
{
    public const string SectionName = "Snowflake";

    public int WorkerId { get; init; }
}
