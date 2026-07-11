using HotChocolate.Types;

namespace fakebookAuth;

public sealed record RegisterInput(
    string DisplayName,
    [property: GraphQLType(typeof(DateType))]
    DateOnly Dob,
    string Email,
    string Username,
    string Password);

public sealed record RegisterPayload(bool Success, string? Message);

public sealed record CreateUserIdentityInput(
    long UserId,
    string Email,
    string Password,
    string DisplayName,
    [property: GraphQLType(typeof(DateType))]
    DateOnly Dob,
    string? Username = null);

public sealed record VerifyEmailInput(string Identifier, string Otp);

public sealed record VerifyEmailPayload(bool Success, string? Message);

public sealed record LoginInput(string Identifier, string Password);

public sealed record RefreshTokenInput(string? RefreshToken);

public sealed record LogoutInput(string? RefreshToken);

public sealed record LogoutSessionInput(long SessionId);

public sealed record ResendEmailVerificationInput(string Identifier);

public sealed record RequestPasswordResetInput(string Identifier);

public sealed record ResetPasswordInput(string Identifier, string Otp, string NewPassword);

public sealed record ChangePasswordInput(string CurrentPassword, string NewPassword);

public sealed record GatewaySessionValidationInput(long UserId, long SessionId);

public sealed record GatewaySessionValidationPayload(
    bool IsValid,
    long? UserId,
    long? SessionId,
    string? Username,
    short? Status,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset? ExpiresAt);

public sealed record GatewayCookieInstruction(
    string Operation,
    string Name,
    string? Value,
    string Path,
    string SameSite,
    bool HttpOnly,
    bool Secure,
    int MaxAgeSeconds,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset? ExpiresAt);

public sealed record AuthActionPayload(
    bool Success,
    string? Message,
    GatewayCookieInstruction? RefreshTokenCookie = null);

public sealed record LoginPayload(
    string AccessToken,
    string RefreshToken,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset RefreshTokenExpiresAt,
    GatewayCookieInstruction RefreshTokenCookie,
    UserType User);

public sealed record UserType(
    long UserId,
    string Email,
    string Username,
    [property: GraphQLType(typeof(DateType))]
    DateOnly? Dob,
    string DisplayName,
    short Status);

public sealed record SessionType(
    long SessionId,
    string? DeviceName,
    string? Os,
    string? Browser,
    string? IpAddress,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset ExpiresAt,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset CreatedAt,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset? LastSeenAt,
    string? RevocationReason,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset? RevokedAt,
    bool IsCurrent);
