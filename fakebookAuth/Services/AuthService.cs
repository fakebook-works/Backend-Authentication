using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace fakebookAuth;

public interface IAuthService
{
    Task<RegisterPayload> RegisterAsync(RegisterInput input, CancellationToken cancellationToken);
    Task<VerifyEmailPayload> VerifyEmailAsync(VerifyEmailInput input, CancellationToken cancellationToken);
    Task<LoginPayload> LoginAsync(LoginInput input, CancellationToken cancellationToken);
    Task<LoginPayload> RefreshTokenAsync(RefreshTokenInput? input, CancellationToken cancellationToken);
    Task<AuthActionPayload> LogoutAsync(LogoutInput? input, CancellationToken cancellationToken);
    Task<AuthActionPayload> LogoutAllAsync(CancellationToken cancellationToken);
    Task<AuthActionPayload> LogoutSessionAsync(LogoutSessionInput input, CancellationToken cancellationToken);
    Task<IReadOnlyList<SessionType>> MySessionsAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<SessionType>> MySessionHistoryAsync(CancellationToken cancellationToken);
    Task<AuthActionPayload> ResendEmailVerificationAsync(ResendEmailVerificationInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> RequestPasswordResetAsync(RequestPasswordResetInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> ResetPasswordAsync(ResetPasswordInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> ChangePasswordAsync(ChangePasswordInput input, CancellationToken cancellationToken);
    Task<UserType> MeAsync(CancellationToken cancellationToken);
    Task<GatewaySessionValidationPayload> ValidateGatewaySessionAsync(
        GatewaySessionValidationInput input,
        CancellationToken cancellationToken);
}

public sealed class AuthService(
    NpgsqlDataSource dataSource,
    IUserRepository users,
    ICredentialRepository credentials,
    IVerificationRepository verifications,
    ISessionRepository sessions,
    IAuditLogRepository auditLogs,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    IEmailSender emailSender,
    ISnowflakeIdGenerator ids,
    IHttpContextAccessor httpContextAccessor,
    ILogger<AuthService> logger,
    Microsoft.Extensions.Options.IOptions<AuthOptions> authOptions,
    Microsoft.Extensions.Options.IOptions<GatewayOptions> gatewayOptions,
    Microsoft.Extensions.Options.IOptions<SmtpOptions> smtpOptions) : IAuthService
{
    private const string GatewaySecretHeaderName = "X-Gateway-Secret";
    private const string GatewayRefreshTokenHeaderName = "X-Refresh-Token";
    private const string GatewayCookieInstructionHeaderName = "X-Fakebook-Refresh-Cookie-Instruction";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly AuthOptions _authOptions = authOptions.Value;
    private readonly GatewayOptions _gatewayOptions = gatewayOptions.Value;
    private readonly SmtpOptions _smtpOptions = smtpOptions.Value;

    public async Task<RegisterPayload> RegisterAsync(RegisterInput input, CancellationToken cancellationToken)
    {
        var register = NormalizeAndValidate(input);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            if (await users.IdentifierExistsAsync(
                    connection,
                    transaction,
                    register.Email,
                    register.Username,
                    cancellationToken))
            {
                throw GraphQlError("Email or username already exists.", "IDENTIFIER_EXISTS");
            }

            var userId = ids.NewId();
            await users.InsertAsync(
                connection,
                transaction,
                new IdentityUser
                {
                    UserId = userId,
                    Email = register.Email,
                    Username = register.Username,
                    Dob = register.Dob,
                    DisplayName = register.DisplayName,
                    Status = AuthConstants.StatusUnverified
                },
                cancellationToken);

            await credentials.InsertPasswordCredentialAsync(
                connection,
                transaction,
                ids.NewId(),
                userId,
                passwordHasher.Hash(register.Password),
                cancellationToken);

            var otp = OtpGenerator.SixDigitCode();
            await verifications.InsertEmailVerificationAsync(
                connection,
                transaction,
                ids.NewId(),
                userId,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow.AddMinutes(_authOptions.EmailVerificationMinutes),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            if (_smtpOptions.Enabled)
            {
                await emailSender.SendVerificationOtpAsync(
                    register.Email,
                    register.DisplayName,
                    otp,
                    cancellationToken);

                return new RegisterPayload(true, "Registration successful. Please check your email for the verification code.");
            }

            return new RegisterPayload(true, "Registration successful. Email delivery is disabled; verify manually before signing in.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw GraphQlError("Email or username already exists.", "IDENTIFIER_EXISTS");
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<VerifyEmailPayload> VerifyEmailAsync(VerifyEmailInput input, CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var otp = NormalizeOtp(input.Otp);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null)
            {
                throw GraphQlError("Verification code is invalid or expired.", "INVALID_OR_EXPIRED_VERIFICATION_CODE");
            }

            if (user.Status == AuthConstants.StatusActive)
            {
                await transaction.CommitAsync(cancellationToken);
                return new VerifyEmailPayload(true, "Email is already verified.");
            }

            if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            await EnsureOtpVerificationNotRateLimitedAsync(
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            var verificationId = await verifications.FindValidEmailVerificationIdAsync(
                connection,
                transaction,
                user.UserId,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (verificationId is null)
            {
                await auditLogs.InsertAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    "OTP_VERIFICATION_FAILURE",
                    metadata,
                    new { Type = AuthConstants.EmailVerificationType, Purpose = "EMAIL_VERIFICATION" },
                    cancellationToken);

                await transaction.CommitAsync(cancellationToken);

                logger.LogWarning(
                    "Email verification OTP failed for user {UserId}.",
                    user.UserId);

                throw GraphQlError("Verification code is invalid or expired.", "INVALID_OR_EXPIRED_VERIFICATION_CODE");
            }

            await users.ActivateAsync(connection, transaction, user.UserId, cancellationToken);
            await verifications.MarkUsedAsync(connection, transaction, verificationId.Value, cancellationToken);
            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "OTP_VERIFIED",
                metadata,
                new { Type = AuthConstants.EmailVerificationType, Purpose = "EMAIL_VERIFICATION" },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation("Email verified for user {UserId}.", user.UserId);

            return new VerifyEmailPayload(true, "Email verified successfully.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<LoginPayload> LoginAsync(LoginInput input, CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrWhiteSpace(input.Password))
        {
            throw InvalidCredentials();
        }

        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);
        await EnsureLoginNotRateLimitedAsync(identifier, metadata, cancellationToken);

        var user = await users.FindByIdentifierAsync(identifier, cancellationToken);
        if (user is null)
        {
            await RecordLoginFailureAsync(identifier, null, "USER_NOT_FOUND", metadata, cancellationToken);
            throw InvalidCredentials();
        }

        if (user.Status == AuthConstants.StatusUnverified)
        {
            throw GraphQlError("Please verify your email before signing in.", "EMAIL_UNVERIFIED");
        }

        if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
        {
            throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
        }

        var credential = await credentials.FindPasswordCredentialAsync(user.UserId, cancellationToken);
        if (credential?.SecretHash is null || !passwordHasher.Verify(input.Password, credential.SecretHash))
        {
            await RecordLoginFailureAsync(identifier, user.UserId, "INVALID_PASSWORD", metadata, cancellationToken);
            throw InvalidCredentials();
        }

        var refreshToken = tokenService.CreateRefreshToken();
        var refreshExpiresAt = DateTimeOffset.UtcNow.AddDays(_authOptions.RefreshTokenDays);
        var sessionId = ids.NewId();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await sessions.InsertAsync(
                connection,
                transaction,
                sessionId,
                user.UserId,
                TokenHashing.Sha256Hex(refreshToken),
                metadata,
                refreshExpiresAt,
                cancellationToken);

            await credentials.MarkUsedAsync(connection, transaction, credential.CredentialId, cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "LOGIN_SUCCESS",
                metadata,
                new { sessionId, identifier },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "User {UserId} logged in with session {SessionId}.",
                user.UserId,
                sessionId);
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }

        return new LoginPayload(
            tokenService.CreateAccessToken(user, sessionId),
            refreshToken,
            refreshExpiresAt,
            CreateSetRefreshTokenCookie(refreshToken, refreshExpiresAt),
            user.ToGraphQl());
    }

    public async Task<LoginPayload> RefreshTokenAsync(RefreshTokenInput? input, CancellationToken cancellationToken)
    {
        var refreshToken = ResolveRefreshToken(input?.RefreshToken);
        var refreshTokenHash = TokenHashing.Sha256Hex(refreshToken);
        var now = DateTimeOffset.UtcNow;
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var session = await sessions.FindActiveByRefreshTokenHashAsync(
                connection,
                transaction,
                refreshTokenHash,
                now,
                cancellationToken);

            if (session is null)
            {
                var replacedToken = await sessions.FindReplacedRefreshTokenAsync(
                    connection,
                    transaction,
                    refreshTokenHash,
                    cancellationToken);

                if (replacedToken is not null)
                {
                    if (replacedToken.SessionRevokedAt is not null ||
                        replacedToken.SessionExpiresAt <= now)
                    {
                        await auditLogs.InsertAsync(
                            connection,
                            transaction,
                            ids.NewId(),
                            replacedToken.UserId,
                            "REVOKED_REFRESH_TOKEN_USED",
                            metadata,
                            new
                            {
                                replacedToken.SessionId,
                                replacedToken.SessionRevocationReason
                            },
                            cancellationToken);

                        await transaction.CommitAsync(cancellationToken);

                        logger.LogWarning(
                            "Rejected refresh token for revoked or expired session {SessionId} of user {UserId}.",
                            replacedToken.SessionId,
                            replacedToken.UserId);

                        throw GraphQlError("Refresh token is invalid or expired.", "INVALID_REFRESH_TOKEN");
                    }

                    await sessions.MarkRefreshTokenReuseDetectedAsync(
                        connection,
                        transaction,
                        refreshTokenHash,
                        cancellationToken);

                    await sessions.RevokeAllByUserIdAsync(
                        connection,
                        transaction,
                        replacedToken.UserId,
                        "REFRESH_TOKEN_REUSE",
                        cancellationToken);

                    await auditLogs.InsertAsync(
                        connection,
                        transaction,
                        ids.NewId(),
                        replacedToken.UserId,
                        "REFRESH_TOKEN_REUSE_DETECTED",
                        metadata,
                        new { replacedToken.SessionId },
                        cancellationToken);

                    await transaction.CommitAsync(cancellationToken);

                    logger.LogWarning(
                        "Refresh token reuse detected for user {UserId}, session {SessionId}.",
                        replacedToken.UserId,
                        replacedToken.SessionId);

                    throw GraphQlError("Refresh token reuse was detected. Please sign in again.", "REFRESH_TOKEN_REUSE_DETECTED");
                }

                throw GraphQlError("Refresh token is invalid or expired.", "INVALID_REFRESH_TOKEN");
            }

            var user = await users.FindByIdAsync(connection, transaction, session.UserId, cancellationToken);
            if (user is null || user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                await sessions.RevokeAsync(
                    connection,
                    transaction,
                    session.SessionId,
                    "ACCOUNT_UNAVAILABLE",
                    cancellationToken);
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            if (user.Status == AuthConstants.StatusUnverified)
            {
                throw GraphQlError("Please verify your email before signing in.", "EMAIL_UNVERIFIED");
            }

            var newRefreshToken = tokenService.CreateRefreshToken();
            var refreshExpiresAt = now.AddDays(_authOptions.RefreshTokenDays);

            await sessions.RotateRefreshTokenAsync(
                connection,
                transaction,
                session.SessionId,
                TokenHashing.Sha256Hex(newRefreshToken),
                refreshExpiresAt,
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "REFRESH_TOKEN_ROTATED",
                metadata,
                new { session.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Refresh token rotated for user {UserId}, session {SessionId}.",
                user.UserId,
                session.SessionId);

            return new LoginPayload(
                tokenService.CreateAccessToken(user, session.SessionId),
                newRefreshToken,
                refreshExpiresAt,
                CreateSetRefreshTokenCookie(newRefreshToken, refreshExpiresAt),
                user.ToGraphQl());
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> LogoutAsync(LogoutInput? input, CancellationToken cancellationToken)
    {
        var refreshToken = ResolveRefreshToken(input?.RefreshToken, allowMissing: true);
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return new AuthActionPayload(true, "Logged out.", CreateClearRefreshTokenCookie());
        }

        var refreshTokenHash = TokenHashing.Sha256Hex(refreshToken);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var session = await sessions.FindActiveByRefreshTokenHashAsync(
                connection,
                transaction,
                refreshTokenHash,
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (session is not null)
            {
                await sessions.RevokeAsync(
                    connection,
                    transaction,
                    session.SessionId,
                    "LOGOUT",
                    cancellationToken);

                await auditLogs.InsertAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    session.UserId,
                    "LOGOUT",
                    metadata,
                    new { session.SessionId },
                    cancellationToken);

                logger.LogInformation(
                    "User {UserId} logged out from session {SessionId}.",
                    session.UserId,
                    session.SessionId);
            }

            await transaction.CommitAsync(cancellationToken);
            return new AuthActionPayload(true, "Logged out.", CreateClearRefreshTokenCookie());
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> LogoutAllAsync(CancellationToken cancellationToken)
    {
        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await sessions.RevokeAllByUserIdAsync(
                connection,
                transaction,
                user.UserId,
                "LOGOUT_ALL",
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "LOGOUT_ALL",
                metadata,
                new { principal.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            logger.LogInformation("User {UserId} logged out all sessions.", user.UserId);
            return new AuthActionPayload(true, "All sessions have been logged out.", CreateClearRefreshTokenCookie());
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> LogoutSessionAsync(
        LogoutSessionInput input,
        CancellationToken cancellationToken)
    {
        if (input.SessionId <= 0)
        {
            throw GraphQlError("Session id is invalid.", "INVALID_SESSION_ID");
        }

        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var revoked = await sessions.RevokeByUserIdAndSessionIdAsync(
                connection,
                transaction,
                user.UserId,
                input.SessionId,
                "SESSION_REVOKED_BY_USER",
                cancellationToken);

            if (revoked == 0)
            {
                throw GraphQlError("Session was not found or is already revoked.", "SESSION_NOT_FOUND");
            }

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "SESSION_REVOKED",
                metadata,
                new { input.SessionId, IsCurrentSession = principal.SessionId == input.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "User {UserId} revoked session {SessionId}.",
                user.UserId,
                input.SessionId);

            var clearCookie = principal.SessionId == input.SessionId
                ? CreateClearRefreshTokenCookie()
                : null;

            return new AuthActionPayload(true, "Session has been logged out.", clearCookie);
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<IReadOnlyList<SessionType>> MySessionsAsync(CancellationToken cancellationToken)
    {
        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var activeSessions = await sessions.ListActiveByUserIdAsync(
            user.UserId,
            DateTimeOffset.UtcNow,
            cancellationToken);

        return activeSessions
            .Select(session => session.ToGraphQl(principal.SessionId))
            .ToList();
    }

    public async Task<IReadOnlyList<SessionType>> MySessionHistoryAsync(CancellationToken cancellationToken)
    {
        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var userSessions = await sessions.ListByUserIdAsync(
            user.UserId,
            cancellationToken);

        return userSessions
            .Select(session => session.ToGraphQl(principal.SessionId))
            .ToList();
    }

    public async Task<AuthActionPayload> ResendEmailVerificationAsync(
        ResendEmailVerificationInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null)
            {
                throw GraphQlError("Account was not found.", "ACCOUNT_NOT_FOUND");
            }

            if (user.Status == AuthConstants.StatusActive)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AuthActionPayload(true, "Email is already verified.");
            }

            if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            await EnsureOtpCooldownAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            await EnsureOtpResendNotRateLimitedAsync(
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            await verifications.MarkUnusedByUserAndTypeAsUsedAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            var otp = OtpGenerator.SixDigitCode();
            await verifications.InsertVerificationAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                AuthConstants.EmailVerificationType,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow.AddMinutes(_authOptions.EmailVerificationMinutes),
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "OTP_RESENT",
                metadata,
                new { Type = AuthConstants.EmailVerificationType, Purpose = "EMAIL_VERIFICATION" },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            await emailSender.SendVerificationOtpAsync(user.Email, user.DisplayName, otp, cancellationToken);
            logger.LogInformation("Email verification OTP resent for user {UserId}.", user.UserId);
            return new AuthActionPayload(true, "Verification code sent. Please check your email.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> RequestPasswordResetAsync(
        RequestPasswordResetInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);
        IdentityUser? userToEmail = null;
        string? otpToEmail = null;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is not null &&
                user.Status == AuthConstants.StatusActive)
            {
                await EnsureOtpCooldownAsync(
                    connection,
                    transaction,
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    cancellationToken);

                await EnsureOtpResendNotRateLimitedAsync(
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    cancellationToken);

                await verifications.MarkUnusedByUserAndTypeAsUsedAsync(
                    connection,
                    transaction,
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    cancellationToken);

                var otp = OtpGenerator.SixDigitCode();
                await verifications.InsertVerificationAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    TokenHashing.Sha256Hex(otp),
                    DateTimeOffset.UtcNow.AddMinutes(_authOptions.PasswordResetMinutes),
                    cancellationToken);

                await auditLogs.InsertAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    "OTP_RESENT",
                    metadata,
                    new { Type = AuthConstants.PasswordResetVerificationType, Purpose = "PASSWORD_RESET" },
                    cancellationToken);

                userToEmail = user;
                otpToEmail = otp;
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }

        if (userToEmail is not null && otpToEmail is not null)
        {
            await emailSender.SendPasswordResetOtpAsync(
                userToEmail.Email,
                userToEmail.DisplayName,
                otpToEmail,
                cancellationToken);

            logger.LogInformation("Password reset OTP sent for user {UserId}.", userToEmail.UserId);
        }

        return new AuthActionPayload(true, "If the account exists, a password reset code has been sent.");
    }

    public async Task<AuthActionPayload> ResetPasswordAsync(
        ResetPasswordInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var otp = NormalizeOtp(input.Otp);
        ValidatePassword(input.NewPassword);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null || user.Status != AuthConstants.StatusActive)
            {
                throw GraphQlError("Password reset code is invalid or expired.", "INVALID_OR_EXPIRED_PASSWORD_RESET_CODE");
            }

            await EnsureOtpVerificationNotRateLimitedAsync(
                user.UserId,
                AuthConstants.PasswordResetVerificationType,
                cancellationToken);

            var verificationId = await verifications.FindValidVerificationIdAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.PasswordResetVerificationType,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (verificationId is null)
            {
                await auditLogs.InsertAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    "OTP_VERIFICATION_FAILURE",
                    metadata,
                    new { Type = AuthConstants.PasswordResetVerificationType, Purpose = "PASSWORD_RESET" },
                    cancellationToken);

                await transaction.CommitAsync(cancellationToken);

                logger.LogWarning(
                    "Password reset OTP failed for user {UserId}.",
                    user.UserId);

                throw GraphQlError("Password reset code is invalid or expired.", "INVALID_OR_EXPIRED_PASSWORD_RESET_CODE");
            }

            var secretHash = passwordHasher.Hash(input.NewPassword);
            var updated = await credentials.UpdatePasswordCredentialAsync(
                connection,
                transaction,
                user.UserId,
                secretHash,
                cancellationToken);

            if (updated == 0)
            {
                await credentials.InsertPasswordCredentialAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    secretHash,
                    cancellationToken);
            }

            await verifications.MarkUsedAsync(connection, transaction, verificationId.Value, cancellationToken);
            await sessions.RevokeAllByUserIdAsync(
                connection,
                transaction,
                user.UserId,
                "PASSWORD_RESET",
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "OTP_VERIFIED",
                metadata,
                new { Type = AuthConstants.PasswordResetVerificationType, Purpose = "PASSWORD_RESET" },
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "PASSWORD_RESET",
                metadata,
                new { },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            logger.LogInformation("Password reset completed for user {UserId}.", user.UserId);
            return new AuthActionPayload(true, "Password has been reset.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> ChangePasswordAsync(
        ChangePasswordInput input,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(input.CurrentPassword))
        {
            throw InvalidCredentials();
        }

        ValidatePassword(input.NewPassword);

        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var credential = await credentials.FindPasswordCredentialAsync(user.UserId, cancellationToken);
        if (credential?.SecretHash is null || !passwordHasher.Verify(input.CurrentPassword, credential.SecretHash))
        {
            throw InvalidCredentials();
        }

        if (passwordHasher.Verify(input.NewPassword, credential.SecretHash))
        {
            throw GraphQlError("New password must be different from the current password.", "PASSWORD_UNCHANGED");
        }

        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await credentials.UpdatePasswordCredentialAsync(
                connection,
                transaction,
                user.UserId,
                passwordHasher.Hash(input.NewPassword),
                cancellationToken);

            await sessions.RevokeAllByUserIdExceptAsync(
                connection,
                transaction,
                user.UserId,
                principal.SessionId,
                "PASSWORD_CHANGED",
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "PASSWORD_CHANGED",
                metadata,
                new { principal.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            logger.LogInformation("Password changed for user {UserId}.", user.UserId);
            return new AuthActionPayload(true, "Password has been changed.");
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<UserType> MeAsync(CancellationToken cancellationToken)
    {
        var (user, _) = await GetCurrentUserAsync(cancellationToken);
        return user.ToGraphQl();
    }

    public async Task<GatewaySessionValidationPayload> ValidateGatewaySessionAsync(
        GatewaySessionValidationInput input,
        CancellationToken cancellationToken)
    {
        EnsureGatewaySecret();

        if (input.UserId <= 0 || input.SessionId <= 0)
        {
            return InvalidGatewaySession(input.UserId, input.SessionId);
        }

        var user = await users.FindByIdAsync(input.UserId, cancellationToken);
        if (user is null)
        {
            return InvalidGatewaySession(input.UserId, input.SessionId);
        }

        if (user.Status != AuthConstants.StatusActive)
        {
            return new GatewaySessionValidationPayload(
                false,
                user.UserId,
                input.SessionId,
                user.Username,
                user.Status,
                null);
        }

        var session = await sessions.FindActiveSessionAsync(
            user.UserId,
            input.SessionId,
            DateTimeOffset.UtcNow,
            cancellationToken);

        if (session is null)
        {
            return new GatewaySessionValidationPayload(
                false,
                user.UserId,
                input.SessionId,
                user.Username,
                user.Status,
                null);
        }

        return new GatewaySessionValidationPayload(
            true,
            user.UserId,
            session.SessionId,
            user.Username,
            user.Status,
            session.ExpiresAt);
    }

    private static NormalizedRegisterInput NormalizeAndValidate(RegisterInput input)
    {
        var email = NormalizeIdentifier(input.Email);
        var username = NormalizeIdentifier(input.Username);
        var displayName = input.DisplayName.Trim();

        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw GraphQlError("Display name is required.", "INVALID_DISPLAY_NAME");
        }

        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw GraphQlError("Email is invalid.", "INVALID_EMAIL");
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            throw GraphQlError("Username is required.", "INVALID_USERNAME");
        }

        ValidatePassword(input.Password);

        if (input.Dob > DateOnly.FromDateTime(DateTime.UtcNow))
        {
            throw GraphQlError("Date of birth is invalid.", "INVALID_DOB");
        }

        return new NormalizedRegisterInput(displayName, input.Dob, email, username, input.Password);
    }

    private static string NormalizeIdentifier(string value) => value.Trim().ToLowerInvariant();

    private string ResolveRefreshToken(string? value, bool allowMissing = false)
    {
        var refreshToken = value?.Trim();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            refreshToken = httpContextAccessor.HttpContext
                ?.Request
                .Headers[GatewayRefreshTokenHeaderName]
                .ToString()
                .Trim();
        }

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            if (allowMissing)
            {
                return string.Empty;
            }

            throw GraphQlError("Refresh token is required.", "INVALID_REFRESH_TOKEN");
        }

        return refreshToken;
    }

    private void EnsureGatewaySecret()
    {
        var expected = _gatewayOptions.InternalSharedSecret;
        var provided = httpContextAccessor.HttpContext
            ?.Request
            .Headers[GatewaySecretHeaderName]
            .ToString();

        if (string.IsNullOrWhiteSpace(expected) ||
            string.IsNullOrWhiteSpace(provided) ||
            !FixedTimeEquals(expected, provided))
        {
            throw GraphQlError("Gateway authentication failed.", "FORBIDDEN");
        }
    }

    private static bool FixedTimeEquals(string expected, string provided)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);

        return expectedBytes.Length == providedBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }

    private static GatewaySessionValidationPayload InvalidGatewaySession(long userId, long sessionId) =>
        new(false, userId, sessionId, null, null, null);

    private static void ValidatePassword(string password)
    {
        if (password.Length < 8)
        {
            throw GraphQlError("Password must be at least 8 characters long.", "WEAK_PASSWORD");
        }
    }

    private static string NormalizeOtp(string value)
    {
        var otp = value.Trim();
        if (otp.Length != 6 || otp.Any(character => !char.IsDigit(character)))
        {
            throw GraphQlError("Verification code must be 6 digits.", "INVALID_VERIFICATION_CODE");
        }

        return otp;
    }

    private async Task EnsureOtpCooldownAsync(
        System.Data.Common.DbConnection connection,
        System.Data.Common.DbTransaction transaction,
        long userId,
        short type,
        CancellationToken cancellationToken)
    {
        if (_authOptions.OtpCooldownSeconds == 0)
        {
            return;
        }

        var latestCreatedAt = await verifications.FindLatestCreatedAtAsync(
            connection,
            transaction,
            userId,
            type,
            cancellationToken);

        if (latestCreatedAt is null)
        {
            return;
        }

        var nextAllowedAt = latestCreatedAt.Value.AddSeconds(_authOptions.OtpCooldownSeconds);
        if (nextAllowedAt > DateTimeOffset.UtcNow)
        {
            throw GraphQlError("Please wait before requesting another code.", "OTP_COOLDOWN");
        }
    }

    private async Task EnsureOtpVerificationNotRateLimitedAsync(
        long userId,
        short type,
        CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-_authOptions.OtpFailureWindowMinutes);
        var recentFailures = await auditLogs.CountRecentUserActionsAsync(
            userId,
            "OTP_VERIFICATION_FAILURE",
            type,
            cutoff,
            cancellationToken);

        if (recentFailures >= _authOptions.OtpFailureLimit)
        {
            logger.LogWarning(
                "OTP verification rate limit hit for user {UserId}, type {OtpType}.",
                userId,
                type);

            throw GraphQlError("Too many invalid verification code attempts. Please try again later.", "OTP_RATE_LIMITED");
        }
    }

    private async Task EnsureOtpResendNotRateLimitedAsync(
        long userId,
        short type,
        CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-_authOptions.OtpResendWindowMinutes);
        var recentResends = await auditLogs.CountRecentUserActionsAsync(
            userId,
            "OTP_RESENT",
            type,
            cutoff,
            cancellationToken);

        if (recentResends >= _authOptions.OtpResendLimit)
        {
            logger.LogWarning(
                "OTP resend rate limit hit for user {UserId}, type {OtpType}.",
                userId,
                type);

            throw GraphQlError("Too many verification code requests. Please try again later.", "OTP_RESEND_RATE_LIMITED");
        }
    }

    private async Task EnsureLoginNotRateLimitedAsync(
        string identifier,
        ClientMetadata metadata,
        CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-_authOptions.LoginFailureWindowMinutes);
        var recentFailures = await auditLogs.CountRecentLoginFailuresAsync(
            identifier,
            metadata,
            cutoff,
            cancellationToken);

        if (recentFailures >= _authOptions.LoginFailureLimit)
        {
            throw GraphQlError("Too many failed login attempts. Please try again later.", "LOGIN_RATE_LIMITED");
        }
    }

    private async Task RecordLoginFailureAsync(
        string identifier,
        long? userId,
        string reason,
        ClientMetadata metadata,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                userId,
                "LOGIN_FAILURE",
                metadata,
                new { identifier, reason },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    private async Task<(IdentityUser User, AccessTokenPrincipal Principal)> GetCurrentUserAsync(
        CancellationToken cancellationToken)
    {
        var principal = GetCurrentPrincipal();
        var user = await users.FindByIdAsync(principal.UserId, cancellationToken);

        if (user is null)
        {
            throw Unauthenticated();
        }

        if (user.Status == AuthConstants.StatusUnverified)
        {
            throw GraphQlError("Please verify your email before continuing.", "EMAIL_UNVERIFIED");
        }

        if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
        {
            throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
        }

        if (principal.SessionId is not null)
        {
            var sessionIsActive = await sessions.ExistsActiveSessionAsync(
                user.UserId,
                principal.SessionId.Value,
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (!sessionIsActive)
            {
                logger.LogWarning(
                    "Rejected access token for revoked or expired session {SessionId} of user {UserId}.",
                    principal.SessionId.Value,
                    user.UserId);

                throw Unauthenticated();
            }
        }

        return (user, principal);
    }

    private AccessTokenPrincipal GetCurrentPrincipal()
    {
        var authorization = httpContextAccessor.HttpContext?.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            throw Unauthenticated();
        }

        var token = authorization["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(token) ||
            !tokenService.TryValidateAccessToken(token, out var principal) ||
            principal is null)
        {
            throw Unauthenticated();
        }

        return principal;
    }

    private static async Task RollbackQuietlyAsync(
        System.Data.Common.DbTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await transaction.RollbackAsync(cancellationToken);
        }
        catch
        {
            // Original exception is more useful than a rollback failure.
        }
    }

    private static GraphQLException InvalidCredentials() => GraphQlError("Invalid credentials.", "INVALID_CREDENTIALS");

    private static GraphQLException Unauthenticated() => GraphQlError("Authentication is required.", "UNAUTHENTICATED");

    private static GraphQLException GraphQlError(string message, string code) =>
        new(ErrorBuilder.New().SetMessage(message).SetCode(code).Build());

    private GatewayCookieInstruction CreateSetRefreshTokenCookie(
        string refreshToken,
        DateTimeOffset expiresAt)
    {
        var instruction = new GatewayCookieInstruction(
            "SET",
            _authOptions.RefreshTokenCookieName,
            refreshToken,
            _authOptions.RefreshTokenCookiePath,
            _authOptions.RefreshTokenCookieSameSite,
            _authOptions.RefreshTokenCookieHttpOnly,
            _authOptions.RefreshTokenCookieSecure,
            _authOptions.RefreshTokenCookieMaxAgeSeconds,
            expiresAt);
        WriteGatewayCookieInstructionHeader(instruction);
        return instruction;
    }

    private GatewayCookieInstruction CreateClearRefreshTokenCookie()
    {
        var instruction = new GatewayCookieInstruction(
            "CLEAR",
            _authOptions.RefreshTokenCookieName,
            string.Empty,
            _authOptions.RefreshTokenCookiePath,
            _authOptions.RefreshTokenCookieSameSite,
            _authOptions.RefreshTokenCookieHttpOnly,
            _authOptions.RefreshTokenCookieSecure,
            0,
            DateTimeOffset.UnixEpoch);
        WriteGatewayCookieInstructionHeader(instruction);
        return instruction;
    }

    private void WriteGatewayCookieInstructionHeader(GatewayCookieInstruction instruction)
    {
        var response = httpContextAccessor.HttpContext?.Response;
        if (response is null || response.HasStarted)
        {
            return;
        }

        var json = JsonSerializer.Serialize(instruction, JsonOptions);
        response.Headers[GatewayCookieInstructionHeaderName] =
            Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    private sealed record NormalizedRegisterInput(
        string DisplayName,
        DateOnly Dob,
        string Email,
        string Username,
        string Password);
}
