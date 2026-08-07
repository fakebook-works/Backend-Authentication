using System.Net.Mime;
using System.Text;
using fakebookAuth;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class FakebookEmailTemplatesTests
{
    [Fact]
    public void VerificationBuildsBrandedHtmlAndPlainTextWithConfiguredExpiry()
    {
        var content = FakebookEmailTemplates.Verification("123456", 23);

        Assert.Equal("Verify your Fakebook account", content.Subject);
        Assert.Contains("123456", content.PlainTextBody, StringComparison.Ordinal);
        Assert.Contains("23 minutes", content.PlainTextBody, StringComparison.Ordinal);
        Assert.Contains("<!doctype html>", content.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("class=\"otp-code\"", content.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("font-size:46px", content.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("123456", content.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("23 minutes", content.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("#0866ff", content.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("confirm this email address", content.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("finish setting up", content.HtmlBody, StringComparison.Ordinal);
        Assert.True(
            content.HtmlBody.IndexOf("123456", StringComparison.Ordinal) >
            content.HtmlBody.IndexOf("class=\"otp-code\"", StringComparison.Ordinal),
            "The OTP must appear in the prominent code block, not in notification preview text.");
        Assert.DoesNotContain("http://", content.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", content.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<script", content.HtmlBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PasswordResetUsesResetSpecificCopy()
    {
        var content = FakebookEmailTemplates.PasswordReset("654321", 9);

        Assert.Equal("Reset your Fakebook password", content.Subject);
        Assert.Contains("YOUR PASSWORD RESET CODE", content.PlainTextBody, StringComparison.Ordinal);
        Assert.Contains("Your password will not change", content.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("654321", content.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("confirm this email address", content.HtmlBody, StringComparison.Ordinal);
    }

    [Fact]
    public void UsesSingularMinuteCopyWhenExpiryIsOneMinute()
    {
        var content = FakebookEmailTemplates.Verification("123456", 1);

        Assert.Contains("expires in 1 minute", content.PlainTextBody, StringComparison.Ordinal);
        Assert.Contains("expires in <strong style=\"color:#1c1e21;\">1 minute</strong>", content.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("1 minutes", content.PlainTextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("1 minutes", content.HtmlBody, StringComparison.Ordinal);
    }

    [Fact]
    public void SmtpMessageContainsPlainTextAndUtf8HtmlAlternative()
    {
        var content = FakebookEmailTemplates.Verification("123456", 15);
        using var message = SmtpEmailSender.CreateMailMessage(
            new SmtpOptions
            {
                FromEmail = "security@fakebook.example",
                FromName = "Fakebook"
            },
            "person@example.com",
            content);

        Assert.False(message.IsBodyHtml);
        Assert.Equal(content.PlainTextBody, message.Body);
        Assert.Equal(Encoding.UTF8.WebName, message.BodyEncoding?.WebName);
        Assert.Equal(Encoding.UTF8.WebName, message.SubjectEncoding?.WebName);
        Assert.Equal("person@example.com", Assert.Single(message.To).Address);

        var htmlView = Assert.Single(message.AlternateViews);
        Assert.Equal(MediaTypeNames.Text.Html, htmlView.ContentType.MediaType);
        Assert.Equal(Encoding.UTF8.WebName, htmlView.ContentType.CharSet);

        htmlView.ContentStream.Position = 0;
        using var reader = new StreamReader(
            htmlView.ContentStream,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true,
            leaveOpen: true);
        Assert.Equal(content.HtmlBody, reader.ReadToEnd());
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("１２３４５６")]
    public void RejectsMalformedOtp(string otp)
    {
        Assert.Throws<ArgumentException>(() => FakebookEmailTemplates.Verification(otp, 15));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RejectsNonPositiveExpiry(int expiresInMinutes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => FakebookEmailTemplates.PasswordReset("123456", expiresInMinutes));
    }
}
