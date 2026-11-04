using Keylo.Core.Security;

namespace Keylo.Core.Tests;

public sealed class ActivityTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keylo-activity-").FullName;
    private readonly Activity _activity;

    public ActivityTests() => _activity = new Activity(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Pins_toggle_and_follow_renames_and_deletes()
    {
        _activity.SetPinned("a", true);
        _activity.SetPinned("b", true);
        _activity.SetPinned("A", true); // case-insensitive: no duplicate
        Assert.Equal(["b", "A"], _activity.Pins());

        _activity.Renamed("b", "bee");
        Assert.True(_activity.IsPinned("BEE"));

        _activity.Removed(["a"]);
        Assert.Equal(["bee"], _activity.Pins());

        _activity.SetPinned("bee", false);
        Assert.Empty(_activity.Pins());
    }

    [Fact]
    public void Recent_merges_your_uses_with_tools_from_the_audit_log_newest_first_once_per_secret()
    {
        _activity.RecordUse("old", "viewed");
        var past = DateTimeOffset.Now.AddHours(-1);
        File.WriteAllLines(AuditLog.PathIn(_dir),
        [
            $"{{\"time\":\"{past:O}\",\"operation\":\"run\",\"secrets\":[\"gh\",\"db\"],\"key\":\"Claude Code\"}}",
            "garbage",
        ]);
        _activity.RecordUse("gh", "copied"); // newer than the tool's use of gh

        var recent = _activity.Recent();
        Assert.Equal(["gh", "old", "db"], recent.Select(r => r.Name));
        Assert.Equal(("You", "copied"), (recent[0].Who, recent[0].Action));
        Assert.Equal(("Claude Code", "run"), (recent[2].Who, recent[2].Action));
    }

    [Fact]
    public void Renames_and_deletes_carry_through_your_history()
    {
        _activity.RecordUse("x", "copied");
        _activity.Renamed("x", "y");
        Assert.Equal(["y"], _activity.Recent().Select(r => r.Name));
        _activity.Removed(["y"]);
        Assert.Empty(_activity.Recent());
    }
}
