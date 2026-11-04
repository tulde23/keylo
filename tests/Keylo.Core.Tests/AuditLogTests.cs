using Keylo.Core.Security;

namespace Keylo.Core.Tests;

public sealed class AuditLogTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keylo-audit-").FullName;
    private string Log => AuditLog.PathIn(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Entry(DateTimeOffset time, string secret) =>
        $"{{\"time\":\"{time:O}\",\"operation\":\"run\",\"secrets\":[\"{secret}\"]}}";

    [Fact]
    public void Entries_older_than_the_retention_are_pruned()
    {
        var now = DateTimeOffset.Now;
        File.WriteAllLines(Log, [Entry(now.AddDays(-120), "old"), "not json", Entry(now.AddDays(-30), "recent"), Entry(now, "new")]);

        Assert.Equal(1, AuditLog.Prune(Log, 90, now));

        var lines = File.ReadAllLines(Log);
        Assert.Equal(3, lines.Length);
        Assert.DoesNotContain(lines, l => l.Contains("\"old\""));
        Assert.Contains("not json", lines); // unreadable lines are kept, never silently lost
    }

    [Fact]
    public void Nothing_is_rewritten_when_the_oldest_entry_is_still_current_or_retention_is_forever()
    {
        var now = DateTimeOffset.Now;
        File.WriteAllLines(Log, [Entry(now.AddDays(-10), "a"), Entry(now, "b")]);
        var written = File.GetLastWriteTimeUtc(Log);

        Assert.Equal(0, AuditLog.Prune(Log, 90, now));
        Assert.Equal(0, AuditLog.Prune(Log, 0, now.AddYears(5)));
        Assert.Equal(written, File.GetLastWriteTimeUtc(Log));
    }

    [Fact]
    public void Write_appends_and_prunes_using_the_configured_retention()
    {
        new KeyloConfig { AuditRetentionDays = 30 }.Save(_dir);
        File.WriteAllLines(Log, [Entry(DateTimeOffset.Now.AddDays(-45), "stale")]);

        AuditLog.Write("run", ["fresh"], key: null, via: "test", dataDirectory: _dir);

        var lines = File.ReadAllLines(Log);
        Assert.Single(lines);
        Assert.Contains("fresh", lines[0]);
    }
}
