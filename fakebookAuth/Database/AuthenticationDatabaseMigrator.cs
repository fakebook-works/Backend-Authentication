using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace fakebookAuth;

public sealed class DatabaseMigrationOptions
{
    public const string SectionName = "DatabaseMigrations";

    public bool Enabled { get; set; } = true;
    public string ConnectionString { get; set; } = string.Empty;
    public int CommandTimeoutSeconds { get; set; } = 120;
}

public sealed class AuthenticationDatabaseMigrator
{
    public const string BaselineVersion = "00000000_schema";

    private const long AdvisoryLockKey = 0x4642415554484D47; // "FBAUTHMG"
    private const string BaselineResource = "fakebookAuth.Database.schema.sql";
    private const string ResourcePrefix = "fakebookAuth.Database.Migrations.";

    private static readonly MigrationDefinition[] Migrations =
    [
        new("20260713_add_gender", MigrationStage.LegacyFb),
        new("20260713_add_valid_date", MigrationStage.LegacyFb),
        new("20260714_remove_username", MigrationStage.LegacyFb),
        new("20260714_remove_profile_fields", MigrationStage.LegacyFb),
        new("20260714_remove_phone", MigrationStage.LegacyFb),
        new("20260714_rename_schema_to_auth", MigrationStage.RenameToAuth),
        new("20260727_add_absolute_session_expiry", MigrationStage.Auth),
        new("20260727_add_login_path_indexes", MigrationStage.Auth)
    ];

    private readonly string _connectionString;
    private readonly int _commandTimeoutSeconds;
    private readonly ILogger<AuthenticationDatabaseMigrator> _logger;

    public AuthenticationDatabaseMigrator(
        string connectionString,
        int commandTimeoutSeconds,
        ILogger<AuthenticationDatabaseMigrator> logger)
    {
        _connectionString = CreateSessionScopedConnectionString(connectionString);
        _commandTimeoutSeconds = commandTimeoutSeconds;
        _logger = logger;
    }

    public static string CreateSessionScopedConnectionString(string connectionString)
    {
        var migrationConnection = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = false,
            Multiplexing = false,
            Enlist = false
        };
        return migrationConnection.ConnectionString;
    }

    public static IReadOnlyList<string> OrderedVersions =>
        new[] { BaselineVersion }
            .Concat(Migrations.Select(migration => migration.Version))
            .ToArray();

    public async Task MigrateAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);

        try
        {
            await connection.OpenAsync(cancellationToken);
            await ExecuteScalarAsync(
                connection,
                "SELECT pg_advisory_lock(@lock_key);",
                cancellationToken,
                ("lock_key", AdvisoryLockKey));

            try
            {
                await MigrateWhileLockedAsync(connection, cancellationToken);
            }
            finally
            {
                if (connection.State == System.Data.ConnectionState.Open)
                {
                    try
                    {
                        await ExecuteScalarAsync(
                            connection,
                            "SELECT pg_advisory_unlock(@lock_key);",
                            CancellationToken.None,
                            ("lock_key", AdvisoryLockKey));
                    }
                    catch (Exception)
                    {
                        _logger.LogWarning("Could not explicitly release the Authentication migration lock; closing the connection will release it.");
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "Authentication database migration failed. Ensure the migration connection targets PostgreSQL and its role can create/alter the auth schema.",
                exception);
        }
    }

    private async Task MigrateWhileLockedAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        var (hasAuthSchema, hasLegacySchema) = await ReadSchemaStateAsync(connection, cancellationToken);

        if (hasAuthSchema && hasLegacySchema)
        {
            throw new InvalidOperationException(
                "Both PostgreSQL schemas 'fb' and 'auth' exist. Resolve the ambiguous Authentication schema state before startup.");
        }

        if (!hasAuthSchema && !hasLegacySchema)
        {
            await CreateFreshDatabaseAsync(connection, cancellationToken);
            _logger.LogInformation("Initialized a fresh Authentication database and baselined {Count} migrations.", Migrations.Length);
            return;
        }

        var currentSchema = hasLegacySchema ? "fb" : "auth";
        if (!await TableExistsAsync(connection, currentSchema, "id_user", cancellationToken))
        {
            throw new InvalidOperationException(
                $"PostgreSQL schema '{currentSchema}' exists but does not contain id_user; refusing to guess its migration history.");
        }

        await EnsureLedgerAsync(
            connection,
            currentSchema,
            transaction: null,
            cancellationToken: cancellationToken);
        if (currentSchema == "auth")
        {
            await VerifyRecordedBaselineChecksumAsync(connection, cancellationToken);
        }

        foreach (var migration in Migrations)
        {
            var sql = ReadEmbeddedSql(ResourcePrefix + migration.Version + ".sql");
            var checksum = Sha256(sql);
            var recordedChecksum = await ReadRecordedChecksumAsync(
                connection,
                currentSchema,
                migration.Version,
                cancellationToken);

            if (recordedChecksum is not null)
            {
                EnsureChecksumMatches(migration.Version, checksum, recordedChecksum);
                if (migration.Stage == MigrationStage.RenameToAuth)
                {
                    currentSchema = "auth";
                }

                continue;
            }

            var satisfied = await IsMigrationSatisfiedAsync(
                connection,
                currentSchema,
                migration.Version,
                cancellationToken);

            if (satisfied)
            {
                await RecordOnlyAsync(
                    connection,
                    currentSchema,
                    migration.Version,
                    checksum,
                    "reconciled",
                    cancellationToken);
                if (migration.Stage == MigrationStage.RenameToAuth)
                {
                    currentSchema = "auth";
                }

                continue;
            }

            if ((migration.Stage is MigrationStage.LegacyFb or MigrationStage.RenameToAuth) &&
                currentSchema != "fb")
            {
                throw new InvalidOperationException(
                    $"Existing auth schema does not satisfy historical migration {migration.Version}. Historical fb migrations are never replayed against auth.");
            }

            var ledgerSchemaAfterMigration = migration.Stage == MigrationStage.RenameToAuth
                ? "auth"
                : currentSchema;
            await ApplyMigrationAsync(
                connection,
                sql,
                ledgerSchemaAfterMigration,
                migration.Version,
                checksum,
                cancellationToken);
            currentSchema = ledgerSchemaAfterMigration;
            _logger.LogInformation("Applied Authentication database migration {Version}.", migration.Version);
        }

        var finalState = await ReadSchemaStateAsync(connection, cancellationToken);
        if (!finalState.HasAuthSchema || finalState.HasLegacySchema)
        {
            throw new InvalidOperationException("Authentication migrations did not produce the required auth-only schema state.");
        }

        await ValidateCanonicalAuthShapeAsync(
            connection,
            transaction: null,
            cancellationToken: cancellationToken);
        await EnsureBaselineLedgerAsync(connection, cancellationToken);
    }

    private async Task CreateFreshDatabaseAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        var schemaSql = ReadEmbeddedSql(BaselineResource);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await ExecuteNonQueryAsync(connection, schemaSql, transaction, cancellationToken);
            await ValidateCanonicalAuthShapeAsync(connection, transaction, cancellationToken);
            await EnsureLedgerAsync(connection, "auth", transaction, cancellationToken);
            await InsertLedgerRowAsync(
                connection,
                "auth",
                BaselineVersion,
                Sha256(schemaSql),
                "applied",
                transaction,
                cancellationToken);

            foreach (var migration in Migrations)
            {
                var migrationSql = ReadEmbeddedSql(ResourcePrefix + migration.Version + ".sql");
                await InsertLedgerRowAsync(
                    connection,
                    "auth",
                    migration.Version,
                    Sha256(migrationSql),
                    "baseline",
                    transaction,
                    cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    private async Task EnsureBaselineLedgerAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        var baselineSql = ReadEmbeddedSql(BaselineResource);
        var expectedChecksum = Sha256(baselineSql);
        var recordedChecksum = await ReadRecordedChecksumAsync(
            connection,
            "auth",
            BaselineVersion,
            cancellationToken);
        if (recordedChecksum is not null)
        {
            EnsureChecksumMatches(BaselineVersion, expectedChecksum, recordedChecksum);
            return;
        }

        await RecordOnlyAsync(
            connection,
            "auth",
            BaselineVersion,
            expectedChecksum,
            "reconciled",
            cancellationToken);
        _logger.LogInformation("Reconciled the immutable Authentication schema baseline.");
    }

    private async Task VerifyRecordedBaselineChecksumAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        var recordedChecksum = await ReadRecordedChecksumAsync(
            connection,
            "auth",
            BaselineVersion,
            cancellationToken);
        if (recordedChecksum is not null)
        {
            EnsureChecksumMatches(
                BaselineVersion,
                Sha256(ReadEmbeddedSql(BaselineResource)),
                recordedChecksum);
        }
    }

    private async Task ValidateCanonicalAuthShapeAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        CancellationToken cancellationToken)
    {
        const string sql = """
            WITH expected_columns(table_name, column_name, udt_name, is_nullable) AS (
                VALUES
                    ('id_user', 'user_id', 'int8', 'NO'),
                    ('id_user', 'email', 'text', 'YES'),
                    ('id_user', 'valid_date', 'timestamptz', 'YES'),
                    ('id_user', 'status', 'int2', 'NO'),
                    ('id_user', 'created_at', 'timestamptz', 'NO'),
                    ('id_user', 'updated_at', 'timestamptz', 'NO'),
                    ('id_credential', 'credential_id', 'int8', 'NO'),
                    ('id_credential', 'user_id', 'int8', 'NO'),
                    ('id_credential', 'provider', 'int2', 'NO'),
                    ('id_credential', 'secret_hash', 'text', 'YES'),
                    ('id_credential', 'created_at', 'timestamptz', 'NO'),
                    ('id_credential', 'last_used_at', 'timestamptz', 'YES'),
                    ('id_session', 'session_id', 'int8', 'NO'),
                    ('id_session', 'user_id', 'int8', 'NO'),
                    ('id_session', 'refresh_token', 'text', 'NO'),
                    ('id_session', 'device_name', 'text', 'YES'),
                    ('id_session', 'os', 'text', 'YES'),
                    ('id_session', 'browser', 'text', 'YES'),
                    ('id_session', 'ip_address', 'inet', 'YES'),
                    ('id_session', 'expires_at', 'timestamptz', 'NO'),
                    ('id_session', 'absolute_expires_at', 'timestamptz', 'NO'),
                    ('id_session', 'created_at', 'timestamptz', 'NO'),
                    ('id_session', 'last_seen_at', 'timestamptz', 'NO'),
                    ('id_session', 'revocation_reason', 'text', 'YES'),
                    ('id_session', 'revoked_at', 'timestamptz', 'YES'),
                    ('id_session_refresh_token', 'token_hash', 'text', 'NO'),
                    ('id_session_refresh_token', 'session_id', 'int8', 'NO'),
                    ('id_session_refresh_token', 'expires_at', 'timestamptz', 'NO'),
                    ('id_session_refresh_token', 'created_at', 'timestamptz', 'NO'),
                    ('id_session_refresh_token', 'replaced_at', 'timestamptz', 'YES'),
                    ('id_session_refresh_token', 'reuse_detected_at', 'timestamptz', 'YES'),
                    ('id_verification', 'verification_id', 'int8', 'NO'),
                    ('id_verification', 'user_id', 'int8', 'NO'),
                    ('id_verification', 'type', 'int2', 'NO'),
                    ('id_verification', 'token_hash', 'text', 'NO'),
                    ('id_verification', 'is_used', 'bool', 'NO'),
                    ('id_verification', 'expires_at', 'timestamptz', 'NO'),
                    ('id_verification', 'created_at', 'timestamptz', 'NO'),
                    ('id_role', 'role_id', 'int8', 'NO'),
                    ('id_role', 'code', 'text', 'NO'),
                    ('id_role', 'name', 'text', 'NO'),
                    ('id_role', 'created_at', 'timestamptz', 'NO'),
                    ('id_permission', 'permission_id', 'int8', 'NO'),
                    ('id_permission', 'code', 'text', 'NO'),
                    ('id_permission', 'name', 'text', 'NO'),
                    ('id_role_permission', 'role_id', 'int8', 'NO'),
                    ('id_role_permission', 'permission_id', 'int8', 'NO'),
                    ('id_user_role', 'user_id', 'int8', 'NO'),
                    ('id_user_role', 'role_id', 'int8', 'NO'),
                    ('id_mfa_method', 'mfa_id', 'int8', 'NO'),
                    ('id_mfa_method', 'user_id', 'int8', 'NO'),
                    ('id_mfa_method', 'method', 'int2', 'NO'),
                    ('id_mfa_method', 'secret', 'text', 'NO'),
                    ('id_mfa_method', 'is_enabled', 'bool', 'NO'),
                    ('id_mfa_method', 'created_at', 'timestamptz', 'NO'),
                    ('id_audit_log', 'audit_id', 'int8', 'NO'),
                    ('id_audit_log', 'user_id', 'int8', 'YES'),
                    ('id_audit_log', 'action', 'text', 'NO'),
                    ('id_audit_log', 'ip_address', 'inet', 'YES'),
                    ('id_audit_log', 'user_agent', 'text', 'YES'),
                    ('id_audit_log', 'created_at', 'timestamptz', 'NO'),
                    ('id_audit_log', 'data', 'jsonb', 'NO')
            ),
            expected_primary_keys(table_name, column_name, ordinal_position) AS (
                VALUES
                    ('id_user', 'user_id', 1),
                    ('id_credential', 'credential_id', 1),
                    ('id_session', 'session_id', 1),
                    ('id_session_refresh_token', 'token_hash', 1),
                    ('id_verification', 'verification_id', 1),
                    ('id_role', 'role_id', 1),
                    ('id_permission', 'permission_id', 1),
                    ('id_role_permission', 'role_id', 1),
                    ('id_role_permission', 'permission_id', 2),
                    ('id_user_role', 'user_id', 1),
                    ('id_user_role', 'role_id', 2),
                    ('id_mfa_method', 'mfa_id', 1),
                    ('id_audit_log', 'audit_id', 1)
            ),
            actual_primary_keys AS (
                SELECT
                    constraint_row.table_name,
                    key_row.column_name,
                    key_row.ordinal_position
                FROM information_schema.table_constraints constraint_row
                JOIN information_schema.key_column_usage key_row
                  ON key_row.constraint_schema = constraint_row.constraint_schema
                 AND key_row.constraint_name = constraint_row.constraint_name
                 AND key_row.table_schema = constraint_row.table_schema
                 AND key_row.table_name = constraint_row.table_name
                WHERE constraint_row.table_schema = 'auth'
                  AND constraint_row.constraint_type = 'PRIMARY KEY'
                  AND constraint_row.table_name IN (
                      SELECT DISTINCT table_name FROM expected_primary_keys
                  )
            ),
            required_indexes(table_name, index_name) AS (
                VALUES
                    ('id_session', 'id_session_user_idx'),
                    ('id_session_refresh_token', 'id_session_refresh_token_session_idx'),
                    ('id_audit_log', 'id_audit_user_time_idx'),
                    ('id_audit_log', 'id_audit_login_success_identifier_time_idx'),
                    ('id_audit_log', 'id_audit_login_failure_identifier_time_idx'),
                    ('id_audit_log', 'id_audit_otp_user_action_type_time_idx'),
                    ('id_verification', 'id_verification_token_idx'),
                    ('id_verification', 'id_verification_user_type_time_idx'),
                    ('id_credential', 'id_credential_user_provider_idx')
            )
            SELECT
                (
                    SELECT count(*)
                    FROM expected_columns expected
                    JOIN information_schema.columns actual
                      ON actual.table_schema = 'auth'
                     AND actual.table_name = expected.table_name
                     AND actual.column_name = expected.column_name
                     AND actual.udt_name = expected.udt_name
                     AND actual.is_nullable = expected.is_nullable
                ) = (SELECT count(*) FROM expected_columns)
                AND (
                    SELECT count(*)
                    FROM expected_primary_keys expected
                    JOIN actual_primary_keys actual USING (table_name, column_name, ordinal_position)
                ) = (SELECT count(*) FROM expected_primary_keys)
                AND (SELECT count(*) FROM actual_primary_keys) =
                    (SELECT count(*) FROM expected_primary_keys)
                AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = 'auth'
                      AND table_name = 'id_user'
                      AND column_name IN ('phone', 'username', 'dob', 'display_name', 'gender')
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_constraint constraint_row
                    JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid
                    JOIN pg_namespace schema_row ON schema_row.oid = table_row.relnamespace
                    WHERE schema_row.nspname = 'auth'
                      AND table_row.relname = 'id_user'
                      AND constraint_row.contype = 'u'
                      AND (
                          SELECT array_agg(attribute_row.attname::text ORDER BY key_row.ordinality)
                          FROM unnest(constraint_row.conkey) WITH ORDINALITY key_row(attnum, ordinality)
                          JOIN pg_attribute attribute_row
                            ON attribute_row.attrelid = table_row.oid
                           AND attribute_row.attnum = key_row.attnum
                      ) = ARRAY['email']::text[]
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_constraint constraint_row
                    JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid
                    JOIN pg_namespace schema_row ON schema_row.oid = table_row.relnamespace
                    WHERE schema_row.nspname = 'auth'
                      AND table_row.relname = 'id_session'
                      AND constraint_row.conname = 'ck_id_session_absolute_expiry'
                      AND constraint_row.contype = 'c'
                      AND constraint_row.convalidated
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM required_indexes required
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM pg_class index_row
                        JOIN pg_namespace index_schema ON index_schema.oid = index_row.relnamespace
                        JOIN pg_index index_state ON index_state.indexrelid = index_row.oid
                        JOIN pg_class table_row ON table_row.oid = index_state.indrelid
                        WHERE index_schema.nspname = 'auth'
                          AND index_row.relname = required.index_name
                          AND table_row.relname = required.table_name
                          AND index_state.indisvalid
                          AND index_state.indisready
                    )
                );
            """;

        await using var command = CreateCommand(connection, sql, transaction);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        if (result is not true)
        {
            throw new InvalidOperationException(
                "The existing auth schema does not match the canonical schema.sql shape; refusing to record its immutable baseline.");
        }
    }

    private async Task ApplyMigrationAsync(
        NpgsqlConnection connection,
        string sql,
        string ledgerSchema,
        string version,
        string checksum,
        CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await ExecuteNonQueryAsync(
                connection,
                RemoveOuterTransaction(sql),
                transaction,
                cancellationToken);
            await InsertLedgerRowAsync(
                connection,
                ledgerSchema,
                version,
                checksum,
                "applied",
                transaction,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    private async Task RecordOnlyAsync(
        NpgsqlConnection connection,
        string ledgerSchema,
        string version,
        string checksum,
        string executionKind,
        CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await InsertLedgerRowAsync(
                connection,
                ledgerSchema,
                version,
                checksum,
                executionKind,
                transaction,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    private async Task<bool> IsMigrationSatisfiedAsync(
        NpgsqlConnection connection,
        string schema,
        string version,
        CancellationToken cancellationToken) => version switch
    {
        "20260713_add_gender" when schema == "auth" =>
            await TableExistsAsync(connection, "auth", "id_user", cancellationToken),
        "20260713_add_gender" =>
            await ColumnExistsAsync(connection, schema, "id_user", "gender", cancellationToken) ||
            (!await ColumnExistsAsync(connection, schema, "id_user", "dob", cancellationToken) &&
             !await ColumnExistsAsync(connection, schema, "id_user", "display_name", cancellationToken)),
        "20260713_add_valid_date" =>
            await ColumnExistsAsync(connection, schema, "id_user", "valid_date", cancellationToken),
        "20260714_remove_username" =>
            !await ColumnExistsAsync(connection, schema, "id_user", "username", cancellationToken) &&
            !await RelationExistsAsync(connection, schema, "id_user_username_idx", cancellationToken),
        "20260714_remove_profile_fields" =>
            !await ColumnExistsAsync(connection, schema, "id_user", "dob", cancellationToken) &&
            !await ColumnExistsAsync(connection, schema, "id_user", "display_name", cancellationToken) &&
            !await ColumnExistsAsync(connection, schema, "id_user", "gender", cancellationToken),
        "20260714_remove_phone" =>
            !await ColumnExistsAsync(connection, schema, "id_user", "phone", cancellationToken) &&
            !await RelationExistsAsync(connection, schema, "id_user_phone_idx", cancellationToken),
        "20260714_rename_schema_to_auth" => schema == "auth",
        "20260727_add_absolute_session_expiry" =>
            await AbsoluteSessionExpiryIsReadyAsync(connection, cancellationToken),
        "20260727_add_login_path_indexes" =>
            await LoginIndexesAreReadyAsync(connection, cancellationToken),
        _ => false
    };

    private async Task<bool> AbsoluteSessionExpiryIsReadyAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'auth' AND table_name = 'id_session'
                      AND column_name = 'absolute_expires_at' AND is_nullable = 'NO'
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_constraint constraint_row
                    JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid
                    JOIN pg_namespace schema_row ON schema_row.oid = table_row.relnamespace
                    WHERE schema_row.nspname = 'auth'
                      AND table_row.relname = 'id_session'
                      AND constraint_row.conname = 'ck_id_session_absolute_expiry'
                      AND constraint_row.convalidated
                );
            """;
        return await ExecuteBooleanAsync(connection, sql, cancellationToken);
    }

    private async Task<bool> LoginIndexesAreReadyAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken) =>
        await RelationExistsAsync(connection, "auth", "id_credential_user_provider_idx", cancellationToken) &&
        await RelationExistsAsync(connection, "auth", "id_verification_user_type_time_idx", cancellationToken) &&
        !await RelationExistsAsync(connection, "auth", "id_user_email_idx", cancellationToken) &&
        !await RelationExistsAsync(connection, "auth", "id_session_refresh_token_replaced_idx", cancellationToken);

    private async Task<(bool HasAuthSchema, bool HasLegacySchema)> ReadSchemaStateAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = CreateCommand(
            connection,
            "SELECT to_regnamespace('auth') IS NOT NULL, to_regnamespace('fb') IS NOT NULL;");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return (reader.GetBoolean(0), reader.GetBoolean(1));
    }

    private Task<bool> TableExistsAsync(
        NpgsqlConnection connection,
        string schema,
        string table,
        CancellationToken cancellationToken) =>
        RelationExistsAsync(connection, schema, table, cancellationToken);

    private async Task<bool> RelationExistsAsync(
        NpgsqlConnection connection,
        string schema,
        string relation,
        CancellationToken cancellationToken) =>
        await ExecuteBooleanAsync(
            connection,
            "SELECT to_regclass(@qualified_name) IS NOT NULL;",
            cancellationToken,
            ("qualified_name", $"{schema}.{relation}"));

    private async Task<bool> ColumnExistsAsync(
        NpgsqlConnection connection,
        string schema,
        string table,
        string column,
        CancellationToken cancellationToken) =>
        await ExecuteBooleanAsync(
            connection,
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = @schema_name
                  AND table_name = @table_name
                  AND column_name = @column_name
            );
            """,
            cancellationToken,
            ("schema_name", schema),
            ("table_name", table),
            ("column_name", column));

    private async Task EnsureLedgerAsync(
        NpgsqlConnection connection,
        string schema,
        NpgsqlTransaction? transaction,
        CancellationToken cancellationToken)
    {
        var sql = $"""
            CREATE TABLE IF NOT EXISTS {schema}.schema_migrations (
                version text PRIMARY KEY,
                checksum_sha256 char(64) NOT NULL,
                execution_kind text NOT NULL CHECK (execution_kind IN ('applied', 'baseline', 'reconciled')),
                applied_at timestamptz NOT NULL DEFAULT now()
            );
            """;
        await ExecuteNonQueryAsync(connection, sql, transaction, cancellationToken);
    }

    private async Task<string?> ReadRecordedChecksumAsync(
        NpgsqlConnection connection,
        string schema,
        string version,
        CancellationToken cancellationToken)
    {
        await using var command = CreateCommand(
            connection,
            $"SELECT checksum_sha256 FROM {schema}.schema_migrations WHERE version = @version;");
        command.Parameters.AddWithValue("version", version);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result as string;
    }

    private async Task InsertLedgerRowAsync(
        NpgsqlConnection connection,
        string schema,
        string version,
        string checksum,
        string executionKind,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = CreateCommand(
            connection,
            $"""
            INSERT INTO {schema}.schema_migrations (version, checksum_sha256, execution_kind)
            VALUES (@version, @checksum, @execution_kind);
            """,
            transaction);
        command.Parameters.AddWithValue("version", version);
        command.Parameters.AddWithValue("checksum", checksum);
        command.Parameters.AddWithValue("execution_kind", executionKind);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<bool> ExecuteBooleanAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        var result = await ExecuteScalarAsync(connection, sql, cancellationToken, parameters);
        return result is true;
    }

    private async Task<object?> ExecuteScalarAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var command = CreateCommand(connection, sql);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return await command.ExecuteScalarAsync(cancellationToken);
    }

    private async Task ExecuteNonQueryAsync(
        NpgsqlConnection connection,
        string sql,
        NpgsqlTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = CreateCommand(connection, sql, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private NpgsqlCommand CreateCommand(
        NpgsqlConnection connection,
        string sql,
        NpgsqlTransaction? transaction = null) => new(sql, connection, transaction)
    {
        CommandTimeout = _commandTimeoutSeconds
    };

    private static string ReadEmbeddedSql(string resourceName)
    {
        using var stream = typeof(AuthenticationDatabaseMigrator).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded migration resource '{resourceName}' is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string Sha256(string sql)
    {
        var normalizedSql = sql
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedSql)))
            .ToLowerInvariant();
    }

    private static void EnsureChecksumMatches(string version, string expected, string recorded)
    {
        if (!string.Equals(expected, recorded.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Authentication migration {version} no longer matches the checksum recorded in auth.schema_migrations. Published migration files are immutable.");
        }
    }

    private static string RemoveOuterTransaction(string sql)
    {
        var lines = sql.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();
        var beginIndex = lines.FindIndex(line => string.Equals(line.Trim(), "BEGIN;", StringComparison.OrdinalIgnoreCase));
        var commitIndex = lines.FindLastIndex(line => string.Equals(line.Trim(), "COMMIT;", StringComparison.OrdinalIgnoreCase));
        if (beginIndex >= 0 && commitIndex > beginIndex)
        {
            lines.RemoveAt(commitIndex);
            lines.RemoveAt(beginIndex);
        }

        return string.Join('\n', lines);
    }

    private sealed record MigrationDefinition(string Version, MigrationStage Stage);

    private enum MigrationStage
    {
        LegacyFb,
        RenameToAuth,
        Auth
    }
}
