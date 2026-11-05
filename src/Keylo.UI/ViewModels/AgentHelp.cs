using Keylo.App.Services;

namespace Keylo.App.ViewModels;

/// <summary>One MCP tool, as listed in Settings → AI agents.</summary>
public sealed record AgentTool(string Name, string Does);

/// <summary>Settings → AI agents: what Keylo's MCP server is and why it's there, for x:Static in both apps.</summary>
public static class AgentHelp
{
    /// <summary>Settings → About: what Keylo is for.</summary>
    public static string Purpose =>
        "Keylo is a simple secret store for developers: API keys, tokens, passwords and database logins, kept on this computer " +
        $"in its own secure store ({Ui.Store}) and unlocked with {Ui.Verifier}. Use them from the app or the keylo command, " +
        "and, through Keylo's built-in MCP server, let AI agents such as Claude Code use your secrets to get work done " +
        "without the values ever entering the conversation. You decide what each agent may use, and approve everything else.";

    public const string Title = "Let AI agents use secrets without seeing them";

    public const string Why =
        "Coding agents such as Claude Code often need an API key or a database password to run a command. " +
        "Pasting it into the chat, or leaving it in a .env file the agent reads, puts the value in the conversation, " +
        "where it's sent to the model and kept in transcripts and logs.";

    public const string How =
        "Keylo includes an MCP server (keylo mcp) that agents connect to instead. An agent asks for a secret by name; " +
        "Keylo passes it to the command as an environment variable and replaces the value with [keylo:name] in the output. " +
        "The agent gets the work done, and the value stays on your machine.";

    public static string Control =>
        $"An access key (below) decides what each agent can use without asking. Anything else opens an approval window that needs {Ui.Verifier}, " +
        "and every use is recorded in the audit log.";

    public const string SetUp =
        "Set up: New key below → Add to Claude Code → restart Claude Code (or run /mcp). " +
        "Other MCP clients work too: run keylo mcp with the key in KEYLO_ACCESS_KEY.";

    public static IReadOnlyList<AgentTool> Tools { get; } =
    [
        new("search_secrets", "Find secrets by name, category or field. Never returns values."),
        new("list_categories", "List categories and whether the agent's key covers them."),
        new("list_types", "List secret types and their fields."),
        new("run_with_secrets", "Run a command with secrets as environment variables; values are redacted from its output."),
        new("get_secret", "Return a value into the conversation. Only for keys allowed to read values."),
        new("request_access", "Ask you to add secrets to the agent's key."),
    ];
}
