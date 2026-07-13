using System.Data.Common;
using System.Text.Json;
using fakebookAuth;
using HotChocolate;
using HotChocolate.Execution;
using HotChocolate.Types;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class AuthenticationContractTests
{
    private const string SharedSecret = "test-gateway-secret-at-least-32-bytes";

    [Fact]
    public async Task Schema_IsEmailOnly_AndRequiresRegistrationAndPaymentFields()
    {
        var schema = await ExportSchemaAsync();

        var registerInput = ExtractBlock(schema, "input RegisterInput");
        Assert.Contains("dob: Date!", registerInput, StringComparison.Ordinal);
        Assert.Contains("gender: Boolean!", registerInput, StringComparison.Ordinal);
        Assert.DoesNotContain("username", registerInput, StringComparison.OrdinalIgnoreCase);

        var userType = ExtractBlock(schema, "type UserType");
        Assert.DoesNotContain("username", userType, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gender: Boolean", userType, StringComparison.Ordinal);
        Assert.Contains("validDate: DateTime", userType, StringComparison.Ordinal);

        var sessionValidation = ExtractBlock(schema, "type GatewaySessionValidationPayload");
        Assert.DoesNotContain("username", sessionValidation, StringComparison.OrdinalIgnoreCase);

        var paymentInput = ExtractBlock(schema, "input SetPaymentValidDateInput");
        Assert.Contains("validDate: DateTime!", paymentInput, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InternalProvisioning_RejectsMissingGenderBeforeDatabaseAccess()
    {
        var service = CreateValidationOnlyAuthService();
        var input = new CreateUserIdentityInput(
            123,
            "a@example.com",
            "Password123!",
            "Nguyen Van A",
            new DateOnly(2000, 1, 1),
            Gender: null);

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.CreateUserIdentityAsync(input, CancellationToken.None));

        Assert.Equal("INVALID_GENDER", exception.Errors[0].Code);
    }

    [Fact]
    public async Task InternalProvisioning_RejectsMissingDobBeforeDatabaseAccess()
    {
        var service = CreateValidationOnlyAuthService();
        var input = new CreateUserIdentityInput(
            123,
            "a@example.com",
            "Password123!",
            "Nguyen Van A",
            Dob: null,
            Gender: true);

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.CreateUserIdentityAsync(input, CancellationToken.None));

        Assert.Equal("INVALID_DOB", exception.Errors[0].Code);
    }

    [Fact]
    public void InternalProvisioningJson_DistinguishesMissingGender()
    {
        const string json = """
            {
              "userId": 123,
              "email": "a@example.com",
              "password": "Password123!",
              "displayName": "Nguyen Van A",
              "dob": "2000-01-01"
            }
            """;

        var input = JsonSerializer.Deserialize<CreateUserIdentityInput>(
            json,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(input);
        Assert.Null(input.Gender);
        Assert.Null(typeof(CreateUserIdentityInput).GetProperty("Username"));
    }

    [Fact]
    public void AccessToken_DoesNotContainUsernameClaim()
    {
        var service = new TokenService(Options.Create(new JwtOptions
        {
            SigningKey = "test-jwt-signing-key-at-least-32-bytes",
            Issuer = "test-issuer",
            Audience = "test-audience"
        }));

        var token = service.CreateAccessToken(new IdentityUser
        {
            UserId = 123,
            Email = "a@example.com",
            DisplayName = "Nguyen Van A",
            Status = AuthConstants.StatusActive
        }, 456);

        using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(token.Split('.')[1]));
        Assert.False(payload.RootElement.TryGetProperty("username", out _));
        Assert.Equal(123, payload.RootElement.GetProperty("user_id").GetInt64());
        Assert.Equal(456, payload.RootElement.GetProperty("sid").GetInt64());
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
    public void DatabaseArtifacts_RemoveIdentityUsername()
    {
        var schema = File.ReadAllText(System.IO.Path.Combine(AppContext.BaseDirectory, "schema.sql"));
        var migration = File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "20260714_remove_username.sql"));

        Assert.DoesNotContain("username", schema, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DROP COLUMN IF EXISTS username", migration, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<string> ExportSchemaAsync()
    {
        var services = new ServiceCollection();
        services
            .AddGraphQLServer("Authentication")
            .AddQueryType<Query>()
            .AddMutationType<AuthMutations>()
            .AddType<DateType>();

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

    private static AuthService CreateValidationOnlyAuthService()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Gateway-Secret"] = SharedSecret;
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
            Options.Create(new GatewayOptions { InternalSharedSecret = SharedSecret }),
            Options.Create(new SmtpOptions()));
    }

    private sealed class RecordingUserRepository : IUserRepository
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
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityUser?> FindByIdAsync(
            long userId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

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
    }
}
