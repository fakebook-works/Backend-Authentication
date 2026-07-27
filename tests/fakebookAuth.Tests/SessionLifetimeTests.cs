namespace fakebookAuth.Tests;

using Xunit;

public sealed class SessionLifetimeTests
{
    [Fact]
    public void RefreshExpiry_UsesTheSlidingWindowWhenItEndsFirst()
    {
        var now = new DateTimeOffset(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);

        var result = SessionLifetime.CapRefreshExpiry(now, 30, now.AddDays(90));

        Assert.Equal(now.AddDays(30), result);
    }

    [Fact]
    public void RefreshExpiry_IsCappedByTheAbsoluteSessionDeadline()
    {
        var now = new DateTimeOffset(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);
        var absoluteDeadline = now.AddDays(4);

        var result = SessionLifetime.CapRefreshExpiry(now, 30, absoluteDeadline);

        Assert.Equal(absoluteDeadline, result);
    }

    [Fact]
    public void MigrationBackfillsFromOriginalCreationTime()
    {
        var workspace = FindWorkspaceRoot();
        var migration = File.ReadAllText(Path.Combine(
            workspace,
            "fakebookAuth",
            "migrations",
            "20260727_add_absolute_session_expiry.sql"));

        Assert.Contains("created_at + interval '90 days'", migration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("absolute_expires_at", migration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SET NOT NULL", migration, StringComparison.OrdinalIgnoreCase);
    }

    private static string FindWorkspaceRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "fakebookAuth")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Authentication repository root was not found.");
    }
}
