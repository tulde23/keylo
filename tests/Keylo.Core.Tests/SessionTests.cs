using Keylo.Core.Security;

namespace Keylo.Core.Tests;

public sealed class SessionTests : IDisposable
{
    private sealed class AlwaysYes : IUserVerifier
    {
        public int Prompts { get; private set; }

        public Task<(VerificationResult Result, string? Detail)> VerifyAsync(IntPtr ownerWindow, string message)
        {
            Prompts++;
            return Task.FromResult((VerificationResult.Verified, (string?)null));
        }
    }

    private readonly string _dir = Directory.CreateTempSubdirectory("keylo-session-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public async Task Activity_slides_the_session_to_a_full_length_from_now()
    {
        var config = new KeyloConfig { Hello = HelloMode.Session, SessionMinutes = 1 };
        var verifier = new AlwaysYes();
        var gate = new AccessGate(config, verifier, _dir);

        await gate.UnlockAsync(IntPtr.Zero);
        var first = gate.SessionExpiresAt!.Value;
        Assert.True(first <= DateTimeOffset.UtcNow.AddMinutes(1));

        config.SessionMinutes = 15;
        gate.ExtendSession();
        Assert.True(gate.SessionExpiresAt!.Value > first.AddMinutes(10));
        Assert.Equal(1, verifier.Prompts); // sliding never prompts
    }

    [Fact]
    public void Extending_never_starts_a_session()
    {
        var gate = new AccessGate(new KeyloConfig { Hello = HelloMode.Session }, new AlwaysYes(), _dir);
        gate.ExtendSession();
        Assert.False(gate.IsUnlocked);
    }
}
