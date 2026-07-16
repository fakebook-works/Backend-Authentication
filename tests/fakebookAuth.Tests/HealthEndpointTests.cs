using fakebookAuth;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class HealthEndpointTests
{
    [Fact]
    public void Live_ReturnsOkWithoutDatabaseDependency()
    {
        var result = AuthHealthEndpoints.Live();

        Assert.Equal(
            StatusCodes.Status200OK,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
        var payload = Assert.IsType<AuthHealthResponse>(
            Assert.IsAssignableFrom<IValueHttpResult>(result).Value);
        Assert.Equal("live", payload.Status);
        Assert.Equal("Authentication", payload.Service);
    }

    [Theory]
    [InlineData(true, StatusCodes.Status200OK, "ready")]
    [InlineData(false, StatusCodes.Status503ServiceUnavailable, "not-ready")]
    public async Task Ready_MapsDatabaseProbeState(
        bool databaseReady,
        int expectedStatus,
        string expectedState)
    {
        var probe = new StubReadinessProbe(databaseReady);

        var result = await AuthHealthEndpoints.ReadyAsync(probe, CancellationToken.None);

        Assert.Equal(
            expectedStatus,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
        var payload = Assert.IsType<AuthHealthResponse>(
            Assert.IsAssignableFrom<IValueHttpResult>(result).Value);
        Assert.Equal(expectedState, payload.Status);
        Assert.True(probe.WasCalled);
    }

    private sealed class StubReadinessProbe(bool result) : IAuthDatabaseReadinessProbe
    {
        public bool WasCalled { get; private set; }

        public Task<bool> IsReadyAsync(CancellationToken cancellationToken)
        {
            WasCalled = true;
            return Task.FromResult(result);
        }
    }
}
