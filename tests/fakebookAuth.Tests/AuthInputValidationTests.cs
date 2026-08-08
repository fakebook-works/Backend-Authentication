using fakebookAuth;
using HotChocolate;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class AuthInputValidationTests
{
    [Fact]
    public void Email_accepts_the_254_character_boundary_and_canonicalizes_case()
    {
        var local = new string('A', 64);
        var domain = new string('B', 63) + "." + new string('C', 63) + "." + new string('D', 61);

        Assert.Equal(254, local.Length + 1 + domain.Length);
        Assert.True(AuthInputValidation.TryNormalizeEmail($"{local}@{domain}", out var normalized));
        Assert.Equal(normalized, normalized.ToLowerInvariant());
        Assert.Equal(254, normalized.Length);
    }

    [Theory]
    [InlineData("a@@example.com")]
    [InlineData("a..b@example.com")]
    [InlineData(".a@example.com")]
    [InlineData("a.@example.com")]
    [InlineData("a@-example.com")]
    [InlineData("a@example-.com")]
    [InlineData("a@exam_ple.com")]
    [InlineData("a\n@example.com")]
    [InlineData("\u00A0a@example.com")]
    [InlineData("a\u202E@example.com")]
    [InlineData("مستخدم@example.com")]
    public void Email_rejects_malformed_or_heavy_unicode_identifiers(string value)
    {
        Assert.False(AuthInputValidation.TryNormalizeEmail(value, out _));
    }

    [Fact]
    public void Email_rejects_255_characters_without_truncation()
    {
        var local = new string('a', 64);
        var domain = new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 62);
        var value = $"{local}@{domain}";

        Assert.Equal(255, value.Length);
        Assert.False(AuthInputValidation.TryNormalizeEmail(value, out _));
    }

    [Fact]
    public void Password_boundary_matches_bcrypt_utf8_limit()
    {
        Assert.True(AuthInputValidation.IsPasswordWithinBounds(new string('a', 72), requireMinimumLength: true));
        Assert.False(AuthInputValidation.IsPasswordWithinBounds(new string('a', 73), requireMinimumLength: true));
        Assert.True(AuthInputValidation.IsPasswordWithinBounds(new string('密', 24), requireMinimumLength: true)); // 72 UTF-8 bytes
        Assert.False(AuthInputValidation.IsPasswordWithinBounds(new string('密', 25), requireMinimumLength: true));
    }

    [Fact]
    public void Password_rejects_invalid_utf16_and_unbounded_zalgo()
    {
        Assert.False(AuthInputValidation.IsPasswordWithinBounds("1234567\uD800", requireMinimumLength: true));
        Assert.False(AuthInputValidation.IsPasswordWithinBounds(new string('\u0301', 1_000), requireMinimumLength: true));
    }

    [Fact]
    public void Refresh_tokens_require_the_generated_base64url_shape()
    {
        Assert.True(AuthInputValidation.IsRefreshToken(new string('A', AuthInputValidation.RefreshTokenLength)));
        Assert.False(AuthInputValidation.IsRefreshToken(new string('A', AuthInputValidation.RefreshTokenLength - 1)));
        Assert.False(AuthInputValidation.IsRefreshToken(new string('A', AuthInputValidation.RefreshTokenLength - 1) + "!"));
        Assert.False(AuthInputValidation.IsRefreshToken(new string('م', AuthInputValidation.RefreshTokenLength)));
    }

    [Fact]
    public void User_agent_projection_removes_controls_bidi_and_caps_length()
    {
        var input = "Chrome\u202E\u0301\n" + new string('x', 2_000);
        var output = AuthInputValidation.SanitizeUserAgent(input);

        Assert.NotNull(output);
        Assert.True(output!.Length <= AuthInputValidation.MaxUserAgentLength);
        Assert.DoesNotContain('\u202E', output);
        Assert.DoesNotContain('\u0301', output);
        Assert.DoesNotContain('\n', output);
    }

    [Theory]
    [InlineData("trace-1", true)]
    [InlineData("a/b:c_1.2", true)]
    [InlineData("", false)]
    [InlineData("bad id", false)]
    [InlineData("bad\r\nheader", false)]
    [InlineData("שלום", false)]
    public void Correlation_ids_are_safe_to_echo_and_log(string value, bool expected)
    {
        Assert.Equal(expected, AuthInputValidation.TryNormalizeCorrelationId(value, out _));
    }

    [Fact]
    public async Task Arabic_otp_digits_are_rejected_before_database_access()
    {
        var service = CreateValidationOnlyAuthService();
        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.VerifyEmailAsync(
                new VerifyEmailInput("person@example.com", "١٢٣٤٥٦"),
                CancellationToken.None));

        Assert.Equal("INVALID_VERIFICATION_CODE", exception.Errors[0].Code);
    }

    [Fact]
    public async Task Malformed_reset_identifier_returns_generic_response_without_database_access()
    {
        var service = CreateValidationOnlyAuthService();
        var result = await service.RequestPasswordResetAsync(
            new RequestPasswordResetInput("not-an-email\u202E"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains("If the account exists", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Oversized_refresh_token_is_rejected_before_database_access()
    {
        var service = CreateValidationOnlyAuthService();
        var exception = await Assert.ThrowsAsync<GraphQLException>(() =>
            service.RefreshTokenAsync(
                new RefreshTokenInput(new string('A', 10_000)),
                CancellationToken.None));

        Assert.Equal("INVALID_REFRESH_TOKEN", exception.Errors[0].Code);
    }

    private static AuthService CreateValidationOnlyAuthService()
    {
        var context = new DefaultHttpContext();
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
                InternalSharedSecret = "test-gateway-secret-at-least-32-bytes",
                AuthenticationServiceSharedSecret = "test-auth-secret-at-least-32-bytes"
            }),
            Options.Create(new SmtpOptions()));
    }
}
