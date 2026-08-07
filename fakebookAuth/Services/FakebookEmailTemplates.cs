using System.Net;

namespace fakebookAuth;

public sealed record OtpEmailContent(
    string Subject,
    string PlainTextBody,
    string HtmlBody);

public static class FakebookEmailTemplates
{
    private const string VerificationSubject = "Verify your Fakebook account";
    private const string PasswordResetSubject = "Reset your Fakebook password";

    public static OtpEmailContent Verification(string otp, int expiresInMinutes)
    {
        Validate(otp, expiresInMinutes);
        var expiryText = FormatExpiry(expiresInMinutes);

        return Build(
            subject: VerificationSubject,
            preheader: $"Confirm your email address with the one-time code inside. It expires in {expiryText}.",
            kicker: "EMAIL CONFIRMATION",
            heading: "Verify your email.",
            introduction: "Use this one-time code to confirm this email address for your Fakebook account.",
            codeLabel: "YOUR VERIFICATION CODE",
            otp,
            expiryText,
            ignoreMessage: "If you didn't create a Fakebook account or change its email address, you can safely ignore this email.");
    }

    public static OtpEmailContent PasswordReset(string otp, int expiresInMinutes)
    {
        Validate(otp, expiresInMinutes);
        var expiryText = FormatExpiry(expiresInMinutes);

        return Build(
            subject: PasswordResetSubject,
            preheader: $"Use the one-time code inside to reset your Fakebook password. It expires in {expiryText}.",
            kicker: "PASSWORD RESET",
            heading: "Reset your password.",
            introduction: "Use this one-time code to reset your Fakebook password.",
            codeLabel: "YOUR PASSWORD RESET CODE",
            otp,
            expiryText,
            ignoreMessage: "If you didn't request a password reset, you can safely ignore this email. Your password will not change.");
    }

    private static OtpEmailContent Build(
        string subject,
        string preheader,
        string kicker,
        string heading,
        string introduction,
        string codeLabel,
        string otp,
        string expiryText,
        string ignoreMessage)
    {
        var plainTextBody = $"""
            Fakebook

            {heading}

            {introduction}

            {codeLabel}:
            {otp}

            This code expires in {expiryText} and can only be used once.
            Never share this code. Fakebook will never ask for it in a message or phone call.

            {ignoreMessage}

            Fakebook
            """;

        var htmlBody = BuildHtmlBody(
            preheader,
            kicker,
            heading,
            introduction,
            codeLabel,
            otp,
            expiryText,
            ignoreMessage);

        return new OtpEmailContent(subject, plainTextBody, htmlBody);
    }

    private static string BuildHtmlBody(
        string preheader,
        string kicker,
        string heading,
        string introduction,
        string codeLabel,
        string otp,
        string expiryText,
        string ignoreMessage)
    {
        var safePreheader = WebUtility.HtmlEncode(preheader);
        var safeKicker = WebUtility.HtmlEncode(kicker);
        var safeHeading = WebUtility.HtmlEncode(heading);
        var safeIntroduction = WebUtility.HtmlEncode(introduction);
        var safeCodeLabel = WebUtility.HtmlEncode(codeLabel);
        var safeOtp = WebUtility.HtmlEncode(otp);
        var safeExpiryText = WebUtility.HtmlEncode(expiryText);
        var safeIgnoreMessage = WebUtility.HtmlEncode(ignoreMessage);

        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <meta name="color-scheme" content="light only">
              <meta name="supported-color-schemes" content="light only">
              <title>{{safeHeading}}</title>
              <style>
                @media only screen and (max-width: 620px) {
                  .email-shell { padding: 22px 12px !important; }
                  .email-card { border-radius: 16px !important; }
                  .email-content { padding: 34px 24px 30px !important; }
                  .email-heading { font-size: 28px !important; }
                  .otp-panel { padding: 22px 14px !important; }
                  .otp-code { font-size: 38px !important; letter-spacing: 7px !important; }
                  .brand-row { padding-left: 4px !important; padding-right: 4px !important; }
                }
              </style>
            </head>
            <body style="margin:0; padding:0; background-color:#f0f2f5; color:#1c1e21; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
              <div style="display:none; max-height:0; overflow:hidden; opacity:0; color:transparent; line-height:1px; font-size:1px; mso-hide:all;">
                {{safePreheader}}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
              </div>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#f0f2f5" style="width:100%; background-color:#f0f2f5;">
                <tr>
                  <td class="email-shell" align="center" style="padding:42px 16px;">
                    <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:100%; max-width:600px;">
                      <tr>
                        <td class="brand-row" style="padding:0 8px 18px;">
                          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              <td align="left" style="color:#0866ff; font-size:27px; font-weight:800; letter-spacing:-1.2px; line-height:32px;">fakebook</td>
                              <td align="right">
                                <span style="display:inline-block; padding:6px 10px; border:1px solid #ccd0d5; border-radius:999px; color:#65676b; font-size:11px; font-weight:700; letter-spacing:1.2px; line-height:14px;">SECURITY</span>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <tr>
                        <td class="email-card" bgcolor="#ffffff" style="overflow:hidden; border:1px solid #dddfe2; border-radius:20px; background-color:#ffffff; box-shadow:0 12px 28px rgba(0,0,0,0.08);">
                          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              <td height="7" bgcolor="#0866ff" style="height:7px; background-color:#0866ff; font-size:0; line-height:0;">&nbsp;</td>
                            </tr>
                            <tr>
                              <td class="email-content" style="padding:46px 52px 40px;">
                                <p style="margin:0 0 10px; color:#65676b; font-size:12px; font-weight:800; letter-spacing:1.6px; line-height:18px;">{{safeKicker}}</p>
                                <h1 class="email-heading" style="margin:0 0 14px; color:#1c1e21; font-size:34px; font-weight:700; letter-spacing:-0.9px; line-height:1.18;">{{safeHeading}}</h1>
                                <p style="margin:0 0 30px; color:#65676b; font-size:16px; line-height:25px;">{{safeIntroduction}}</p>

                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#e7f3ff" style="width:100%; border:1px solid #b9d7ff; border-radius:16px; background-color:#e7f3ff;">
                                  <tr>
                                    <td class="otp-panel" align="center" style="padding:27px 18px 25px;">
                                      <p style="margin:0 0 12px; color:#37516f; font-size:11px; font-weight:800; letter-spacing:1.45px; line-height:16px;">{{safeCodeLabel}}</p>
                                      <div class="otp-code" style="margin:0; color:#0866ff; font-family:'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size:46px; font-weight:800; letter-spacing:10px; line-height:1.2; white-space:nowrap; mso-line-height-rule:exactly;">{{safeOtp}}</div>
                                    </td>
                                  </tr>
                                </table>

                                <p style="margin:17px 0 0; color:#65676b; font-size:14px; line-height:21px; text-align:center;">
                                  This code expires in <strong style="color:#1c1e21;">{{safeExpiryText}}</strong> and can only be used once.
                                </p>

                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                                  <tr>
                                    <td height="30" style="height:30px; font-size:0; line-height:0;">&nbsp;</td>
                                  </tr>
                                </table>
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#f7f9fc" style="width:100%; border-left:4px solid #0866ff; border-radius:8px; background-color:#f7f9fc;">
                                  <tr>
                                    <td style="padding:16px 18px;">
                                      <p style="margin:0 0 4px; color:#1c1e21; font-size:13px; font-weight:700; line-height:19px;">Keep this code private</p>
                                      <p style="margin:0; color:#65676b; font-size:13px; line-height:20px;">Never share this code. Fakebook will never ask for it in a message or phone call.</p>
                                    </td>
                                  </tr>
                                </table>

                                <div style="height:1px; margin:30px 0 22px; background-color:#e4e6eb; font-size:0; line-height:0;">&nbsp;</div>
                                <p style="margin:0; color:#65676b; font-size:13px; line-height:20px;">{{safeIgnoreMessage}}</p>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <tr>
                        <td align="center" style="padding:20px 20px 0; color:#65676b; font-size:12px; line-height:19px;">
                          Sent by Fakebook<br>
                          <span style="color:#65676b;">Connect with the people and things you love.</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </body>
            </html>
            """;
    }

    private static void Validate(string otp, int expiresInMinutes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(otp);

        if (otp.Length != 6 || !otp.All(char.IsAsciiDigit))
        {
            throw new ArgumentException("OTP must contain exactly six ASCII digits.", nameof(otp));
        }

        if (expiresInMinutes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresInMinutes),
                expiresInMinutes,
                "OTP expiry must be greater than zero minutes.");
        }
    }

    private static string FormatExpiry(int expiresInMinutes) =>
        expiresInMinutes == 1
            ? "1 minute"
            : $"{expiresInMinutes} minutes";
}
