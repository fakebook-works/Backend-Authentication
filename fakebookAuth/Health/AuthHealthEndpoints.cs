using Npgsql;

namespace fakebookAuth;

public interface IAuthDatabaseReadinessProbe
{
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
}

public sealed class PostgresAuthDatabaseReadinessProbe(
    NpgsqlDataSource dataSource,
    ILogger<PostgresAuthDatabaseReadinessProbe> logger) : IAuthDatabaseReadinessProbe
{
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand("SELECT 1", connection);
            await command.ExecuteScalarAsync(cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Authentication database readiness check failed.");
            return false;
        }
    }
}

public static class AuthHealthEndpoints
{
    public static IResult Live() =>
        Results.Ok(new AuthHealthResponse("live", "Authentication"));

    public static async Task<IResult> ReadyAsync(
        IAuthDatabaseReadinessProbe database,
        CancellationToken cancellationToken) =>
        await database.IsReadyAsync(cancellationToken)
            ? Results.Ok(new AuthHealthResponse("ready", "Authentication"))
            : Results.Json(
                new AuthHealthResponse("not-ready", "Authentication"),
                statusCode: StatusCodes.Status503ServiceUnavailable);
}

public sealed record AuthHealthResponse(string Status, string Service);
