using fakebookAuth;
using HotChocolate;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace fakebookAuth.Tests;

/// <summary>
/// LoginAsync writes the supplied identifier into auth.id_audit_log on every failed attempt.
/// It previously accepted any string of any length, so an anonymous caller could grow that table
/// without bound on a database shared by every service, and an identifier past the btree page
/// limit made the insert throw a server error instead of failing the login cleanly.
/// These inputs must be rejected before any database work happens at all — the service under
/// test is built with a null data source, so reaching the database would surface as a crash.
/// </summary>
public sealed class LoginIdentifierHardeningTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-email")]
    [InlineData("still@ not an email")]
    public async Task Login_rejects_a_malformed_identifier_before_touching_the_database(string identifier)
    {
        var service = CreateService();

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.LoginAsync(new LoginInput(identifier, "irrelevant-password"), CancellationToken.None));

        Assert.Equal("INVALID_CREDENTIALS", Assert.Single(exception.Errors).Code);
    }

    [Fact]
    public async Task Login_rejects_an_oversized_identifier_before_touching_the_database()
    {
        var service = CreateService();
        var oversized = new string('a', 5_000);

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.LoginAsync(new LoginInput(oversized, "irrelevant-password"), CancellationToken.None));

        Assert.Equal("INVALID_CREDENTIALS", Assert.Single(exception.Errors).Code);
    }

    [Fact]
    public async Task Login_rejects_an_empty_password_before_touching_the_database()
    {
        var service = CreateService();

        var exception = await Assert.ThrowsAsync<GraphQLException>(
            () => service.LoginAsync(new LoginInput("someone@example.com", "   "), CancellationToken.None));

        Assert.Equal("INVALID_CREDENTIALS", Assert.Single(exception.Errors).Code);
    }

    private static AuthService CreateService() =>
        new(
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
            new HttpContextAccessor { HttpContext = new DefaultHttpContext() },
            NullLogger<AuthService>.Instance,
            Options.Create(new AuthOptions()),
            Options.Create(new GatewayOptions
            {
                InternalSharedSecret = "test-gateway-secret-at-least-32-bytes",
                AuthenticationServiceSharedSecret = "test-gateway-secret-at-least-32-bytes"
            }),
            Options.Create(new SmtpOptions()));
}
