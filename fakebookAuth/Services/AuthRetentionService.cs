using System.Data.Common;
using Dapper;
using Microsoft.Extensions.Options;
using Npgsql;

namespace fakebookAuth;

/// <summary>
/// Bounds how long the append-only identity tables are kept.
/// </summary>
/// <remarks>
/// auth.id_audit_log, id_verification, id_session and id_session_refresh_token were only
/// ever inserted into and updated — nothing deleted a row — on a database shared by every
/// service. The audit log in particular is written on every failed sign-in by anonymous
/// callers, so its growth is not bounded by the number of real users.
/// </remarks>
public sealed class AuthRetentionOptions
{
    public const string SectionName = "AuthRetention";

    public bool Enabled { get; init; } = true;

    /// <summary>Security history is worth keeping for a while; it is also the noisiest table.</summary>
    public int AuditLogRetentionDays { get; init; } = 90;

    /// <summary>A verification code is spent or expired long before this.</summary>
    public int VerificationRetentionDays { get; init; } = 7;

    /// <summary>Grace period after a session has already expired, so recent history stays visible.</summary>
    public int ExpiredSessionRetentionDays { get; init; } = 30;

    /// <summary>Rows removed per statement, so each delete takes a short lock.</summary>
    public int BatchSize { get; init; } = 500;

    /// <summary>Upper bound on batches per table per sweep.</summary>
    public int MaxBatchesPerSweep { get; init; } = 40;

    public int SweepIntervalMinutes { get; init; } = 360;
}

public interface IAuthRetentionRepository
{
    Task<int> DeleteExpiredAsync(int batchSize, AuthRetentionOptions options, CancellationToken cancellationToken);
}

public sealed class AuthRetentionRepository(NpgsqlDataSource dataSource) : IAuthRetentionRepository
{
    /// <summary>
    /// Runs one bounded delete against each table and returns how many rows went.
    /// </summary>
    /// <remarks>
    /// Each statement selects its victims by primary key with a LIMIT before deleting, so a
    /// sweep never takes a lock proportional to how far behind it has fallen. Sessions are
    /// removed only once already expired for the grace period, and refresh tokens cascade
    /// from their session, so they need no statement of their own.
    /// </remarks>
    public async Task<int> DeleteExpiredAsync(
        int batchSize,
        AuthRetentionOptions options,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);

        var removed = 0;
        removed += await ExecuteAsync(
            connection,
            """
            DELETE FROM auth.id_audit_log
            WHERE audit_id IN (
                SELECT audit_id FROM auth.id_audit_log
                WHERE created_at < @Cutoff
                ORDER BY created_at
                LIMIT @BatchSize
            );
            """,
            new { Cutoff = now.AddDays(-options.AuditLogRetentionDays), BatchSize = batchSize },
            cancellationToken);

        removed += await ExecuteAsync(
            connection,
            """
            DELETE FROM auth.id_verification
            WHERE verification_id IN (
                SELECT verification_id FROM auth.id_verification
                WHERE created_at < @Cutoff OR (is_used AND expires_at < @Now)
                ORDER BY created_at
                LIMIT @BatchSize
            );
            """,
            new
            {
                Cutoff = now.AddDays(-options.VerificationRetentionDays),
                Now = now,
                BatchSize = batchSize
            },
            cancellationToken);

        removed += await ExecuteAsync(
            connection,
            """
            DELETE FROM auth.id_session
            WHERE session_id IN (
                SELECT session_id FROM auth.id_session
                WHERE expires_at < @Cutoff
                ORDER BY expires_at
                LIMIT @BatchSize
            );
            """,
            new { Cutoff = now.AddDays(-options.ExpiredSessionRetentionDays), BatchSize = batchSize },
            cancellationToken);

        return removed;
    }

    private static Task<int> ExecuteAsync(
        DbConnection connection,
        string sql,
        object parameters,
        CancellationToken cancellationToken) =>
        connection.ExecuteAsync(new CommandDefinition(sql, parameters, cancellationToken: cancellationToken));
}

public sealed class AuthRetentionService(
    IServiceScopeFactory scopeFactory,
    IOptions<AuthRetentionOptions> options,
    ILogger<AuthRetentionService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled)
        {
            logger.LogInformation("Identity retention is disabled; the append-only tables will grow without bound.");
            return;
        }

        var interval = TimeSpan.FromMinutes(Math.Clamp(settings.SweepIntervalMinutes, 1, 24 * 60));
        using var timer = new PeriodicTimer(interval);

        do
        {
            try
            {
                await SweepAsync(settings, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Identity retention sweep failed; it will run again next interval.");
            }
        }
        while (await SafeWaitAsync(timer, stoppingToken));
    }

    private async Task SweepAsync(AuthRetentionOptions settings, CancellationToken cancellationToken)
    {
        var batchSize = Math.Clamp(settings.BatchSize, 1, 10_000);
        var maxBatches = Math.Clamp(settings.MaxBatchesPerSweep, 1, 1_000);

        await using var scope = scopeFactory.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAuthRetentionRepository>();

        var total = 0;
        for (var batch = 0; batch < maxBatches; batch++)
        {
            var removed = await repository.DeleteExpiredAsync(batchSize, settings, cancellationToken);
            if (removed == 0)
            {
                break;
            }

            total += removed;
        }

        if (total > 0)
        {
            logger.LogInformation("Identity retention removed {Removed} expired rows.", total);
        }
    }

    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
