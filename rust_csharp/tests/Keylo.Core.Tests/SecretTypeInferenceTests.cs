using System.Text;

namespace Keylo.Core.Tests;

public sealed class SecretTypeInferenceTests
{
    private static InferredType? Infer(string file, string content) => SecretTypeInference.Infer(file, Encoding.UTF8.GetBytes(content));

    [Theory]
    [InlineData("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", "ssh_key")]
    [InlineData("server.pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n", "ssh_key")]
    [InlineData("db.env", "postgres://alice:p%40ss@db.local:5432/app", "database")]
    [InlineData("anything", "Server=sql1;Database=x;User Id=a;Password=b;", "database")]
    [InlineData("prod-db", "some-opaque-string", "database")]
    [InlineData("router-password.txt", "hunter2", "login")]
    [InlineData("github-token", "ghp_abc123", "api_key")]
    [InlineData("stripe_api_key.txt", "sk_test_123", "api_key")]
    public void Confident_guesses(string file, string content, string type) =>
        Assert.Equal(type, Infer(file, content)?.TypeId);

    [Theory]
    [InlineData("id_ed25519.pub", "ssh-ed25519 AAAA… me@host")]
    [InlineData("notes.txt", "remember the milk")]
    [InlineData("github-token", "line one\nline two")]
    [InlineData("cert.crt", "-----BEGIN CERTIFICATE-----")]
    [InlineData("keyboard-layout", "us")]
    public void Everything_else_stays_plain(string file, string content) => Assert.Null(Infer(file, content));

    [Fact]
    public void Binary_files_stay_plain() => Assert.Null(SecretTypeInference.Infer("token.bin", [0xff, 0xfe, 0x00, 0x01]));

    [Fact]
    public void Database_urls_are_split_into_fields()
    {
        var fields = SecretTypeInference.ParseDatabaseUrl("postgresql://alice:p%40ss@db.local:5432/app")!;
        Assert.Equal(("postgres", "db.local", "5432", "app", "alice", "p@ss"),
            (fields["engine"], fields["host"], fields["port"], fields["database"], fields["username"], fields["password"]));
    }
}
