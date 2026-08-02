using fakebookAuth;
using Npgsql;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class DatabaseMigrationContractTests
{
    [Fact]
    public void StartupMigrations_AreEnabledByDefault()
    {
        var options = new DatabaseMigrationOptions();

        Assert.True(options.Enabled);
        Assert.Equal(120, options.CommandTimeoutSeconds);
    }

    [Fact]
    public void MigrationHistory_HasTheRequiredLegacyRenameAndAuthOrder()
    {
        Assert.Equal(
            [
                "00000000_schema",
                "20260713_add_gender",
                "20260713_add_valid_date",
                "20260714_remove_username",
                "20260714_remove_profile_fields",
                "20260714_remove_phone",
                "20260714_rename_schema_to_auth",
                "20260727_add_absolute_session_expiry",
                "20260727_add_login_path_indexes"
            ],
            AuthenticationDatabaseMigrator.OrderedVersions);
    }

    [Fact]
    public void FreshSchemaAndAllVersionedMigrations_AreEmbeddedInTheService()
    {
        var resourceNames = typeof(AuthenticationDatabaseMigrator)
            .Assembly
            .GetManifestResourceNames();

        Assert.Contains("fakebookAuth.Database.schema.sql", resourceNames);
        foreach (var version in AuthenticationDatabaseMigrator.OrderedVersions.Skip(1))
        {
            Assert.Contains($"fakebookAuth.Database.Migrations.{version}.sql", resourceNames);
        }
    }

    [Fact]
    public void MigrationConnection_IsPhysicalAndSessionScoped()
    {
        var configured = AuthenticationDatabaseMigrator.CreateSessionScopedConnectionString(
            "Host=localhost;Database=fakebook;Username=migration_owner;Password=test-only;Pooling=true;Multiplexing=true;Enlist=true");
        var parsed = new NpgsqlConnectionStringBuilder(configured);

        Assert.False(parsed.Pooling);
        Assert.False(parsed.Multiplexing);
        Assert.False(parsed.Enlist);
    }
}
