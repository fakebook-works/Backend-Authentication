using fakebookAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace fakebookAuth.Tests;

/// <summary>
/// auth.id_audit_log, id_verification and id_session were only ever inserted into and
/// updated; nothing deleted a row. The audit log is written on every failed sign-in by
/// anonymous callers, so its growth was not bounded by the number of real users, and all of
/// it sat on a database shared with every other service.
/// </summary>
public sealed class AuthRetentionServiceTests
{
    [Fact]
    public async Task Sweeps_until_nothing_is_left_to_remove()
    {
        var repository = new CountingRepository(returns: [500, 500, 120, 0]);

        await RunAsync(repository);

        Assert.Equal(4, repository.Calls);
    }

    [Fact]
    public async Task Stops_at_the_batch_ceiling_rather_than_running_unbounded()
    {
        // A sweep that has fallen a long way behind must still end, leaving the rest for the
        // next interval instead of holding the connection for an unbounded time.
        var repository = new CountingRepository(alwaysReturns: 500);

        await RunAsync(repository, maxBatches: 3);

        Assert.Equal(3, repository.Calls);
    }

    [Fact]
    public async Task Does_nothing_when_disabled()
    {
        var repository = new CountingRepository(alwaysReturns: 500);

        await RunAsync(repository, enabled: false);

        Assert.Equal(0, repository.Calls);
    }

    [Fact]
    public async Task Passes_the_configured_batch_size_through()
    {
        var repository = new CountingRepository(returns: [10, 0]);

        await RunAsync(repository, batchSize: 250);

        Assert.Equal(250, repository.LastBatchSize);
    }

    [Fact]
    public async Task Keeps_running_after_a_failed_sweep()
    {
        var repository = new ThrowingRepository();

        await RunAsync(repository);

        // The exception is logged, not propagated, so one bad sweep cannot take the host down.
        Assert.True(repository.Called);
    }

    private static async Task RunAsync(
        IAuthRetentionRepository repository,
        bool enabled = true,
        int batchSize = 500,
        int maxBatches = 40)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => repository);
        await using var provider = services.BuildServiceProvider();

        var service = new AuthRetentionService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new AuthRetentionOptions
            {
                Enabled = enabled,
                BatchSize = batchSize,
                MaxBatchesPerSweep = maxBatches,
                SweepIntervalMinutes = 1_440
            }),
            NullLogger<AuthRetentionService>.Instance);

        using var cancellation = new CancellationTokenSource();
        await service.StartAsync(cancellation.Token);
        await Task.Delay(300, CancellationToken.None);
        await cancellation.CancelAsync();
        await service.StopAsync(CancellationToken.None);
    }

    private sealed class CountingRepository : IAuthRetentionRepository
    {
        private readonly int[]? _returns;
        private readonly int _alwaysReturns;

        public CountingRepository(int[]? returns = null, int alwaysReturns = 0)
        {
            _returns = returns;
            _alwaysReturns = alwaysReturns;
        }

        public int Calls { get; private set; }

        public int LastBatchSize { get; private set; }

        public Task<int> DeleteExpiredAsync(
            int batchSize,
            AuthRetentionOptions options,
            CancellationToken cancellationToken)
        {
            LastBatchSize = batchSize;
            var index = Calls;
            Calls++;
            var result = _returns is null
                ? _alwaysReturns
                : index < _returns.Length ? _returns[index] : 0;
            return Task.FromResult(result);
        }
    }

    private sealed class ThrowingRepository : IAuthRetentionRepository
    {
        public bool Called { get; private set; }

        public Task<int> DeleteExpiredAsync(
            int batchSize,
            AuthRetentionOptions options,
            CancellationToken cancellationToken)
        {
            Called = true;
            throw new InvalidOperationException("connection lost");
        }
    }
}
