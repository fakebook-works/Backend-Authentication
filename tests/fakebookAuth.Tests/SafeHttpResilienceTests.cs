using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class SafeHttpResilienceTests
{
    [Fact]
    public async Task UnsafePostIsNotRetriedButSafeGetIs()
    {
        var services = new ServiceCollection();
        services.AddFakebookServiceDefaults(new ConfigurationBuilder().Build(), "resilience-test");
        var handler = new FailOnceHandler();
        services.AddHttpClient("probe").ConfigurePrimaryHttpMessageHandler(() => handler);

        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("probe");

        using var post = await client.PostAsync("https://example.invalid/mutation", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, post.StatusCode);
        Assert.Equal(1, handler.Attempts);

        handler.Reset();
        using var get = await client.GetAsync("https://example.invalid/read");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(2, handler.Attempts);
    }

    private sealed class FailOnceHandler : HttpMessageHandler
    {
        public int Attempts { get; private set; }

        public void Reset() => Attempts = 0;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Attempts++;
            return Task.FromResult(new HttpResponseMessage(
                Attempts == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        }
    }
}
