using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using fakebookAuth;
using HotChocolate;
using HotChocolate.Execution;
using HotChocolate.Types;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class AuthenticationContractTests
{
    private const string SharedSecret = "test-gateway-secret-at-least-32-bytes";

    [Fact]
    public async Task Schema_IsEmailOnly_AndContainsNoUnsupportedIdentityFields()
    {
        var schema = await ExportSchemaAsync();

        var registerInput = ExtractBlock(schema, "input RegisterInput");
        Assert.Contains("email: String!", registerInput, StringComparison.Ordinal);
        Assert.Contains("password: String!", registerInput, StringComparison.Ordinal);
        AssertUnsupportedIdentityFieldsAbsent(registerInput);

        var userType = ExtractBlock(schema, "type UserType");
        AssertUnsupportedIdentityFieldsAbsent(userType);
        Assert.Contains("validDate: DateTime", userType, StringComparison.Ordinal);

        var sessionValidation = ExtractBlock(schema, "type GatewaySessionValidationPayload");
        AssertUnsupportedIdentityFieldsAbsent(sessionValidation);

        var paymentInput = ExtractBlock(schema, "input SetPaymentValidDateInput");
        Assert.Contains("validDate: DateTime!", paymentInput, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InternalProvisioning_RejectsInvalidEmailBeforeDatabaseAccess()
    {
        var service = CreateValidationOnlyAuthService();
        var input = new CreateUserIdentityInput(
            123,
            "not-an-email",
            "Password123!");

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.CreateUserIdentityAsync(input, CancellationToken.None));

        Assert.Equal("INVALID_EMAIL", exception.Errors[0].Code);
    }

    [Fact]
    public async Task InternalProvisioning_RejectsWeakPasswordBeforeDatabaseAccess()
    {
        var service = CreateValidationOnlyAuthService();
        var input = new CreateUserIdentityInput(
            123,
            "a@example.com",
            "short");

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.CreateUserIdentityAsync(input, CancellationToken.None));

        Assert.Equal("WEAK_PASSWORD", exception.Errors[0].Code);
    }

    [Fact]
    public async Task InternalProvisioning_AcceptsDedicatedAuthenticationServiceSecret()
    {
        const string dedicatedSecret = "dedicated-authentication-secret-at-least-32-bytes";
        var service = CreateValidationOnlyAuthService(
            headerName: "X-Internal-AuthenticationService-Secret",
            providedSecret: dedicatedSecret,
            gatewaySecret: SharedSecret,
            authenticationServiceSecret: dedicatedSecret);

        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.CreateUserIdentityAsync(
                new CreateUserIdentityInput(123, "not-an-email", "Password123!"),
                CancellationToken.None));

        Assert.Equal("INVALID_EMAIL", exception.Errors[0].Code);
    }

    [Fact]
    public async Task InternalProvisioning_RetryIsIdempotentAndSkipsBcrypt()
    {
        const string dedicatedSecret = "dedicated-authentication-secret-at-least-32-bytes";
        var existing = new IdentityUser
        {
            UserId = 123,
            Email = "a@example.com",
            Status = AuthConstants.StatusUnverified
        };
        var hasher = new RecordingPasswordHasher();
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Internal-AuthenticationService-Secret"] = dedicatedSecret;
        var service = new AuthService(
            dataSource: null!,
            users: new RecordingUserRepository(existing),
            credentials: null!,
            verifications: null!,
            sessions: null!,
            auditLogs: null!,
            passwordHasher: hasher,
            tokenService: null!,
            emailSender: null!,
            ids: null!,
            new HttpContextAccessor { HttpContext = context },
            NullLogger<AuthService>.Instance,
            Options.Create(new AuthOptions()),
            Options.Create(new GatewayOptions
            {
                AuthenticationServiceSharedSecret = dedicatedSecret
            }),
            Options.Create(new SmtpOptions()));

        var result = await service.CreateUserIdentityAsync(
            new CreateUserIdentityInput(123, "a@example.com", "Password123!"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("User identity is already provisioned.", result.Message);
        Assert.Equal(0, hasher.HashCalls);
    }

    [Fact]
    public async Task InternalProvisioning_DoesNotAcceptGatewaySecretWhenDedicatedSecretIsConfigured()
    {
        var service = CreateValidationOnlyAuthService(
            headerName: "X-Gateway-Secret",
            providedSecret: SharedSecret,
            gatewaySecret: SharedSecret,
            authenticationServiceSecret: "dedicated-authentication-secret-at-least-32-bytes");

        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.CreateUserIdentityAsync(
                new CreateUserIdentityInput(123, "a@example.com", "Password123!"),
                CancellationToken.None));

        Assert.Equal("FORBIDDEN", exception.Errors[0].Code);
    }

    [Fact]
    public async Task InternalProvisioning_DoesNotFallBackToGatewaySecretWhenDedicatedSecretIsMissing()
    {
        var service = CreateValidationOnlyAuthService(
            headerName: "X-Gateway-Secret",
            providedSecret: SharedSecret,
            gatewaySecret: SharedSecret,
            authenticationServiceSecret: "");

        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.CreateUserIdentityAsync(
                new CreateUserIdentityInput(123, "a@example.com", "Password123!"),
                CancellationToken.None));

        Assert.Equal("FORBIDDEN", exception.Errors[0].Code);
    }

    [Fact]
    public async Task DeleteIdentity_RejectsInvalidIdBeforeDatabaseAccess()
    {
        const string dedicatedSecret = "dedicated-authentication-secret-at-least-32-bytes";
        var service = CreateValidationOnlyAuthService(
            headerName: "X-Internal-AuthenticationService-Secret",
            providedSecret: dedicatedSecret,
            gatewaySecret: SharedSecret,
            authenticationServiceSecret: dedicatedSecret);

        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.DeleteUserIdentityAsync(0, CancellationToken.None));

        Assert.Equal("INVALID_USER_ID", exception.Errors[0].Code);
    }

    [Fact]
    public async Task GatewaySessionValidation_DoesNotTrustProvisioningSecretHeader()
    {
        const string dedicatedSecret = "dedicated-authentication-secret-at-least-32-bytes";
        var service = CreateValidationOnlyAuthService(
            headerName: "X-Internal-AuthenticationService-Secret",
            providedSecret: dedicatedSecret,
            gatewaySecret: SharedSecret,
            authenticationServiceSecret: dedicatedSecret);

        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.ValidateGatewaySessionAsync(
                new GatewaySessionValidationInput(0, 0),
                CancellationToken.None));

        Assert.Equal("FORBIDDEN", exception.Errors[0].Code);
    }

    [Fact]
    public void InternalProvisioningContract_ContainsOnlyIdentityFields()
    {
        const string json = """
            {
              "userId": 123,
              "email": "a@example.com",
              "password": "Password123!"
            }
            """;

        var input = JsonSerializer.Deserialize<CreateUserIdentityInput>(
            json,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(input);
        Assert.Equal(123, input.UserId);
        Assert.Equal(
            ["Email", "Password", "UserId"],
            typeof(CreateUserIdentityInput)
                .GetProperties()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));
    }

    [Fact]
    public void AccessToken_DoesNotContainUnsupportedIdentityClaims()
    {
        using var rsa = RSA.Create(2048);
        var service = new TokenService(Options.Create(new JwtOptions
        {
            PrivateKeyBase64 = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
            KeyId = "test-key-1",
            Issuer = "test-issuer",
            Audience = "test-audience"
        }));

        var token = service.CreateAccessToken(new IdentityUser
        {
            UserId = 123,
            Email = "a@example.com",
            Status = AuthConstants.StatusActive
        }, 456);

        using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(token.Split('.')[1]));
        foreach (var field in UnsupportedIdentityFields)
        {
            Assert.False(payload.RootElement.TryGetProperty(field, out _));
        }

        Assert.False(payload.RootElement.TryGetProperty("name", out _));
        Assert.Equal(123, payload.RootElement.GetProperty("user_id").GetInt64());
        Assert.Equal(456, payload.RootElement.GetProperty("sid").GetInt64());
        using var header = JsonDocument.Parse(WebEncoders.Base64UrlDecode(token.Split('.')[0]));
        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("test-key-1", header.RootElement.GetProperty("kid").GetString());
        Assert.True(service.TryValidateAccessToken(token, out var principal));
        Assert.Equal(new AccessTokenPrincipal(123, 456), principal);
    }

    [Fact]
    public void AccessToken_RejectsWrongKeyIdAndUnconfiguredLegacyAlgorithm()
    {
        using var rsa = RSA.Create(2048);
        var options = new JwtOptions
        {
            PrivateKeyBase64 = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
            KeyId = "expected-key",
            Issuer = "test-issuer",
            Audience = "test-audience",
            LegacySigningKey = string.Empty
        };
        using var service = new TokenService(Options.Create(options));
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = options.Audience,
            Subject = new ClaimsIdentity([new Claim("user_id", "123", ClaimValueTypes.Integer64)]),
            Expires = DateTime.UtcNow.AddMinutes(5)
        };

        descriptor.SigningCredentials = new SigningCredentials(
            new RsaSecurityKey(rsa) { KeyId = "wrong-key" },
            SecurityAlgorithms.RsaSha256);
        Assert.False(service.TryValidateAccessToken(handler.CreateEncodedJwt(descriptor), out _));

        descriptor.SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("legacy-key-not-enabled-1234567890")),
            SecurityAlgorithms.HmacSha256);
        Assert.False(service.TryValidateAccessToken(handler.CreateEncodedJwt(descriptor), out _));
    }

    [Fact]
    public async Task PaymentUpdate_NormalizesValidDateToUtc()
    {
        var repository = new RecordingUserRepository();
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Payment-Secret"] = SharedSecret;
        var service = new PaymentPremiumService(
            repository,
            new HttpContextAccessor { HttpContext = context },
            Options.Create(new PaymentOptions { InternalSharedSecret = SharedSecret }));
        var localValidDate = new DateTimeOffset(2030, 2, 3, 10, 30, 0, TimeSpan.FromHours(7));

        var result = await service.SetAsync(
            new SetPaymentValidDateInput("123", localValidDate),
            CancellationToken.None);

        Assert.Equal(TimeSpan.Zero, repository.LastValidDate?.Offset);
        Assert.Equal(localValidDate.ToUniversalTime(), repository.LastValidDate);
        Assert.Equal(repository.LastValidDate, result.ValidDate);
    }

    [Fact]
    public void DatabaseArtifacts_UseAuthSchemaAndRemoveUnsupportedFields()
    {
        var schema = File.ReadAllText(System.IO.Path.Combine(AppContext.BaseDirectory, "schema.sql"));
        var repositorySource = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "Repositories.cs"));
        var usernameMigration = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "20260714_remove_username.sql"));
        var profileMigration = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "20260714_remove_profile_fields.sql"));
        var phoneMigration = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "20260714_remove_phone.sql"));
        var schemaRenameMigration = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "20260714_rename_schema_to_auth.sql"));

        Assert.Contains("CREATE SCHEMA IF NOT EXISTS auth", schema, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SET search_path TO auth", schema, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CREATE SCHEMA IF NOT EXISTS fb", schema, StringComparison.OrdinalIgnoreCase);
        AssertUnsupportedIdentityFieldsAbsent(schema);
        Assert.DoesNotContain("display_name", schema, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("id_user_phone_idx", schema, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("auth.id_user", repositorySource, StringComparison.Ordinal);
        Assert.DoesNotContain("fb.", repositorySource, StringComparison.Ordinal);
        Assert.Null(typeof(IdentityUser).GetProperty("Phone"));
        Assert.Contains("DROP COLUMN IF EXISTS username", usernameMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP INDEX IF EXISTS fb.id_user_phone_idx", phoneMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP COLUMN IF EXISTS phone", phoneMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP COLUMN IF EXISTS dob", profileMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP COLUMN IF EXISTS display_name", profileMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP COLUMN IF EXISTS gender", profileMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("to_regnamespace('auth')", schemaRenameMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("to_regnamespace('fb')", schemaRenameMigration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ALTER SCHEMA fb RENAME TO auth", schemaRenameMigration, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<string> ExportSchemaAsync()
    {
        var services = new ServiceCollection();
        services
            .AddGraphQLServer("Authentication")
            .AddQueryType<Query>()
            .AddMutationType<AuthMutations>();

        await using var provider = services.BuildServiceProvider();
        var resolver = provider.GetRequiredService<IRequestExecutorProvider>();
        var executor = await resolver.GetExecutorAsync("Authentication");
        return executor.Schema.ToString();
    }

    private static string ExtractBlock(string schema, string declaration)
    {
        var start = schema.IndexOf(declaration, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Schema declaration '{declaration}' was not found.");
        var end = schema.IndexOf("\n}", start, StringComparison.Ordinal);
        Assert.True(end > start, $"Schema declaration '{declaration}' was not terminated.");
        return schema[start..(end + 2)];
    }

    private static readonly string[] UnsupportedIdentityFields =
        ["username", "phone", "displayName", "dob", "gender"];

    private static void AssertUnsupportedIdentityFieldsAbsent(string value)
    {
        foreach (var field in UnsupportedIdentityFields)
        {
            Assert.DoesNotMatch(
                new Regex($@"\b{Regex.Escape(field)}\b", RegexOptions.IgnoreCase),
                value);
        }
    }

    private static AuthService CreateValidationOnlyAuthService(
        string headerName = "X-Internal-AuthenticationService-Secret",
        string providedSecret = SharedSecret,
        string gatewaySecret = SharedSecret,
        string authenticationServiceSecret = SharedSecret)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[headerName] = providedSecret;
        return new AuthService(
            dataSource: null!,
            users: null!,
            credentials: null!,
            verifications: null!,
            sessions: null!,
            auditLogs: null!,
            passwordHasher: null!,
            tokenService: null!,
            emailSender: null!,
            ids: null!,
            new HttpContextAccessor { HttpContext = context },
            NullLogger<AuthService>.Instance,
            Options.Create(new AuthOptions()),
            Options.Create(new GatewayOptions
            {
                InternalSharedSecret = gatewaySecret,
                AuthenticationServiceSharedSecret = authenticationServiceSecret
            }),
            Options.Create(new SmtpOptions()));
    }

    private sealed class RecordingUserRepository(IdentityUser? existing = null) : IUserRepository
    {
        public DateTimeOffset? LastValidDate { get; private set; }

        public Task<DateTimeOffset?> SetValidDateAsync(
            long userId,
            DateTimeOffset validDate,
            CancellationToken cancellationToken)
        {
            LastValidDate = validDate;
            return Task.FromResult<DateTimeOffset?>(validDate);
        }

        public Task<bool> EmailExistsAsync(
            DbConnection connection,
            DbTransaction transaction,
            string email,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task InsertAsync(
            DbConnection connection,
            DbTransaction transaction,
            IdentityUser user,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityUser?> FindByEmailAsync(
            string email,
            CancellationToken cancellationToken) => Task.FromResult(
                existing is not null && string.Equals(existing.Email, email, StringComparison.OrdinalIgnoreCase)
                    ? existing
                    : null);

        public Task<IdentityUser?> FindByIdAsync(
            long userId,
            CancellationToken cancellationToken) => Task.FromResult(
                existing?.UserId == userId ? existing : null);

        public Task<IdentityUser?> FindByIdAsync(
            DbConnection connection,
            DbTransaction transaction,
            long userId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityUser?> FindByEmailAsync(
            DbConnection connection,
            DbTransaction transaction,
            string email,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task ActivateAsync(
            DbConnection connection,
            DbTransaction transaction,
            long userId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task MarkDeletedAsync(
            DbConnection connection,
            DbTransaction transaction,
            long userId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingPasswordHasher : IPasswordHasher
    {
        public int HashCalls { get; private set; }

        public Task<string> HashAsync(string password, CancellationToken cancellationToken)
        {
            HashCalls++;
            return Task.FromResult("unexpected");
        }

        public Task<bool> VerifyAsync(string password, string passwordHash, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }
}
