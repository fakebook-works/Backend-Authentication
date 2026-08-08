using System.Text;

namespace fakebookAuth;

/// <summary>
/// Small, dependency-free input boundary for the authentication service.
///
/// Authentication does not own profile text (SocialGraph does), but it does receive
/// identifiers, secrets, tokens and request metadata from other services and from the
/// GraphQL edge.  Keeping these checks in one place prevents a new resolver from
/// accidentally re-introducing an unbounded value into the audit/database paths.
/// </summary>
internal static class AuthInputValidation
{
    // RFC 5321's maximum address length.  The database column is text, so this limit
    // must be enforced before every lookup/write as well as at registration time.
    public const int MaxEmailLength = 254;

    // BCrypt's normal (non-enhanced) format consumes at most 72 UTF-8 bytes.  Values
    // beyond that are truncated by the algorithm and would make distinct passwords
    // equivalent.  Rejecting them is safer than silently truncating them.  The
    // character cap also bounds malformed UTF-16 input before encoding it.
    public const int MaxPasswordLength = 128;
    public const int MaxPasswordUtf8Bytes = 72;

    public const int MaxUserAgentLength = 512;
    public const int MaxCorrelationIdLength = 128;
    public const int RefreshTokenLength = 86; // 64 random bytes in base64url form.

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static bool TryNormalizeEmail(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (value is null ||
            value.Length == 0 ||
            value.Length > MaxEmailLength ||
            string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        // Check the untrimmed value as well.  Otherwise a control/bidi/non-ASCII
        // character at an edge could be silently removed by Trim() and accepted as a
        // different identifier from the one the caller actually submitted.
        if (value.Any(character => character > '\u007f' || char.IsControl(character)))
        {
            return false;
        }

        var email = value.Trim();
        if (email.Length == 0 ||
            email.Length > MaxEmailLength ||
            !IsAsciiEmail(email))
        {
            return false;
        }

        // Email addresses are stored and looked up in their canonical lower-case
        // representation by this service.  We intentionally reject Unicode/EAI here:
        // profile/display text belongs to SocialGraph, while Auth identifiers must be
        // deterministic across all services and database collations.
        normalized = email.ToLowerInvariant();
        return true;
    }

    public static bool IsPasswordWithinBounds(string? password, bool requireMinimumLength)
    {
        if (password is null ||
            password.Length == 0 ||
            password.Length > MaxPasswordLength ||
            (requireMinimumLength && password.Length < 8))
        {
            return false;
        }

        try
        {
            // Do not normalize or sanitize a password: changing secret material during
            // validation would make login behaviour surprising.  We only reject invalid
            // UTF-16 and the bcrypt truncation boundary.
            return StrictUtf8.GetByteCount(password) <= MaxPasswordUtf8Bytes;
        }
        catch (EncoderFallbackException)
        {
            return false;
        }
    }

    public static bool IsRefreshToken(string? value)
    {
        if (value is null || value.Length != RefreshTokenLength)
        {
            return false;
        }

        return value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }

    /// <summary>
    /// User-Agent is only used for device/session metadata and audit diagnostics.  Keep
    /// a short printable-ASCII projection so control, bidi and combining-heavy Unicode
    /// cannot be persisted or rendered by a client later.
    /// </summary>
    public static string? SanitizeUserAgent(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        var builder = new StringBuilder(Math.Min(value.Length, MaxUserAgentLength));
        foreach (var character in value)
        {
            if (builder.Length >= MaxUserAgentLength)
            {
                break;
            }

            if (character is >= '\u0020' and <= '\u007e')
            {
                builder.Append(character);
            }
        }

        return builder.Length == 0 ? null : builder.ToString();
    }

    /// <summary>
    /// Correlation IDs are echoed in a response header and placed in log scopes.  Only
    /// conservative token characters are accepted to prevent header/log injection.
    /// </summary>
    public static bool TryNormalizeCorrelationId(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrEmpty(value) || value.Length > MaxCorrelationIdLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.' and not ':' and not '/')
            {
                return false;
            }
        }

        normalized = value;
        return true;
    }

    public static bool TryParsePositiveId(string? value, out long id)
    {
        id = 0;
        if (string.IsNullOrEmpty(value) ||
            value.Length > 19 ||
            value.Any(character => !char.IsAsciiDigit(character)) ||
            !long.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out id))
        {
            id = 0;
            return false;
        }

        return id > 0;
    }

    private static bool IsAsciiEmail(string email)
    {
        var separator = email.IndexOf('@');
        if (separator <= 0 ||
            separator != email.LastIndexOf('@') ||
            separator >= email.Length - 1)
        {
            return false;
        }

        var local = email[..separator];
        var domain = email[(separator + 1)..];
        if (local.Length > 64 ||
            local[0] == '.' ||
            local[^1] == '.' ||
            local.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var character in local)
        {
            if (!IsAllowedLocalCharacter(character))
            {
                return false;
            }
        }

        if (domain.Length > 253 || domain[0] == '.' || domain[^1] == '.')
        {
            return false;
        }

        var labels = domain.Split('.');
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 ||
                label[0] == '-' ||
                label[^1] == '-')
            {
                return false;
            }

            foreach (var character in label)
            {
                if (!char.IsAsciiLetterOrDigit(character) && character != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsAllowedLocalCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) ||
        character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or
            '/' or '=' or '?' or '^' or '_' or '`' or '{' or '|' or '}' or '~' or '.';
}
