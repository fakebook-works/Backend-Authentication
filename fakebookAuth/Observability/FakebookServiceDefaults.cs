using System.Globalization;
using Microsoft.Extensions.Http.Resilience;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Microsoft.Extensions.DependencyInjection;

public static class FakebookServiceDefaults
{
    public static IServiceCollection AddFakebookServiceDefaults(
        this IServiceCollection services,
        IConfiguration configuration,
        string serviceName)
    {
        var sampleRatio = ReadSampleRatio(configuration);
        var endpoint = ReadOtlpEndpoint(configuration);
        var telemetry = services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService(
                serviceName,
                serviceVersion: typeof(FakebookServiceDefaults).Assembly.GetName().Version?.ToString(),
                serviceInstanceId: Environment.MachineName));

        telemetry.WithTracing(tracing =>
        {
            tracing
                .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(sampleRatio)))
                .AddAspNetCoreInstrumentation(options =>
                    options.Filter = context => !context.Request.Path.StartsWithSegments("/health"))
                .AddHttpClientInstrumentation(options =>
                    options.FilterHttpRequestMessage = request => request.RequestUri?.AbsolutePath.StartsWith("/health", StringComparison.OrdinalIgnoreCase) != true);
            if (endpoint is not null) tracing.AddOtlpExporter(options => options.Endpoint = endpoint);
        });

        telemetry.WithMetrics(metrics =>
        {
            metrics
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation();
            if (endpoint is not null) metrics.AddOtlpExporter(options => options.Endpoint = endpoint);
        });

        // Register before service-specific signing handlers: each safe-method retry then
        // traverses the signer again and receives a fresh timestamp/nonce. Unsafe methods
        // (POST/PUT/PATCH/DELETE/CONNECT) are never automatically retried.
        services.ConfigureHttpClientDefaults(http =>
            http.AddStandardResilienceHandler(options => options.Retry.DisableForUnsafeHttpMethods()));
        return services;
    }

    private static double ReadSampleRatio(IConfiguration configuration)
    {
        var raw = configuration["Observability:TraceSampleRatio"] ??
                  configuration["OTEL_TRACES_SAMPLER_ARG"];
        return double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
            ? Math.Clamp(parsed, 0d, 1d)
            : 0.1d;
    }

    private static Uri? ReadOtlpEndpoint(IConfiguration configuration)
    {
        var raw = configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] ??
                  configuration["OpenTelemetry:OtlpEndpoint"];
        return Uri.TryCreate(raw, UriKind.Absolute, out var endpoint) ? endpoint : null;
    }
}
