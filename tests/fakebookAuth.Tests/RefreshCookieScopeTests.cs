using fakebookAuth;
using Xunit;

namespace fakebookAuth.Tests;

/// <summary>
/// The refresh cookie is a 30-day credential. The edge serves /graphql, /api/ and /media/ from a
/// single origin, so a "/" path made the browser attach it to every media request — sending it to
/// the Upload server, which processes user-supplied files and is the largest attack surface in the
/// system. Only the Gateway GraphQL endpoint ever reads this cookie.
/// </summary>
public sealed class RefreshCookieScopeTests
{
    [Fact]
    public void Refresh_cookie_is_scoped_to_the_graphql_endpoint_by_default()
    {
        var options = new AuthOptions();

        Assert.Equal("/graphql", options.RefreshTokenCookiePath);
    }

    [Fact]
    public void Refresh_cookie_keeps_its_hardening_attributes()
    {
        var options = new AuthOptions();

        Assert.True(options.RefreshTokenCookieHttpOnly);
        Assert.True(options.RefreshTokenCookieSecure);
        Assert.Equal("Lax", options.RefreshTokenCookieSameSite);
        Assert.Equal("fb_refresh", options.RefreshTokenCookieName);
    }
}
