using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using Microsoft.Extensions.Options;

namespace fakebookAuth;

public interface IEmailSender
{
    Task SendVerificationOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken);

    Task SendPasswordResetOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken);
}

public sealed class SmtpEmailSender(
    IOptions<SmtpOptions> options,
    IOptions<AuthOptions> authOptions) : IEmailSender
{
    private readonly SmtpOptions _options = options.Value;
    private readonly AuthOptions _authOptions = authOptions.Value;

    public async Task SendVerificationOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken)
    {
        var content = FakebookEmailTemplates.Verification(
            otp,
            _authOptions.EmailVerificationMinutes);

        await SendOtpAsync(
            email,
            content,
            cancellationToken);
    }

    public async Task SendPasswordResetOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken)
    {
        var content = FakebookEmailTemplates.PasswordReset(
            otp,
            _authOptions.PasswordResetMinutes);

        await SendOtpAsync(
            email,
            content,
            cancellationToken);
    }

    private async Task SendOtpAsync(
        string email,
        OtpEmailContent content,
        CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var message = CreateMailMessage(_options, email, content);

        using var client = new SmtpClient(_options.Host, _options.Port)
        {
            EnableSsl = _options.EnableSsl,
            Credentials = new NetworkCredential(_options.Username, _options.Password),
            DeliveryMethod = SmtpDeliveryMethod.Network
        };

        await client.SendMailAsync(message, cancellationToken);
    }

    internal static MailMessage CreateMailMessage(
        SmtpOptions options,
        string email,
        OtpEmailContent content)
    {
        var message = new MailMessage
        {
            From = new MailAddress(options.FromEmail, options.FromName),
            Subject = content.Subject,
            SubjectEncoding = Encoding.UTF8,
            Body = content.PlainTextBody,
            BodyEncoding = Encoding.UTF8,
            IsBodyHtml = false
        };

        try
        {
            message.To.Add(new MailAddress(email));
            message.AlternateViews.Add(
                AlternateView.CreateAlternateViewFromString(
                    content.HtmlBody,
                    Encoding.UTF8,
                    MediaTypeNames.Text.Html));

            return message;
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }
}
