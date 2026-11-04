using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keylo.Core;

namespace Keylo.Cli.Mcp;

/// <summary>
/// A Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0), so agents such as
/// Claude Code can find and use secrets through tools. Only protocol messages go to stdout;
/// everything else is redirected to stderr.
/// </summary>
internal static class McpServer
{
    private static readonly string[] ProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"];

    private const string Instructions = """
        Keylo holds the user's secrets (API keys, passwords, tokens) on this Windows PC.
        - Find secrets with search_secrets. Each result says what your access key allows: "run", "run, get", or "needs approval".
        - Secrets have types (login, api_key, database, ssh_key, note, custom) with named fields; search results include each
          secret's field schema. Address one field as "name:field" (e.g. "prod-db:connection_string"); a bare name means its main value.
        - Some secrets are links (type "link") to items in another vault such as 1Password; they work the same way and are read
          live from that vault, which may ask the user to unlock it.
        - Prefer run_with_secrets: values reach the command as environment variables and are redacted from its output, so they never enter this conversation.
        - Use get_secret only when the value itself is needed (e.g. to fill in a login). It returns the value into the conversation.
        - Using a secret outside your key's scope asks the user to approve it in a Keylo window (with Windows Hello); an approval
          lasts for their Keylo session (15 minutes by default). If they deny it, don't retry; ask them.
        - request_access asks the user to add secrets to your key permanently.
        Never write secret values into files, commits or messages unless the user asks.
        """;

    private static readonly SemaphoreSlim WriteLock = new(1, 1);
    private static Stream _out = Stream.Null;

    public static async Task<int> RunAsync()
    {
        _out = Console.OpenStandardOutput();
        Console.SetOut(Console.Error);

        var tools = new KeyloTools();
        var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        var inFlight = new List<Task>();

        while (await input.ReadLineAsync() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            JsonNode? message;
            try
            {
                message = JsonNode.Parse(line);
            }
            catch (JsonException)
            {
                await SendAsync(Error(null, -32700, "Parse error"));
                continue;
            }

            // Requests are handled concurrently, so a ping isn't stuck behind an approval prompt.
            var messages = message is JsonArray batch ? batch.OfType<JsonObject>().ToList() : message is JsonObject single ? [single] : [];
            foreach (var request in messages) inFlight.Add(Task.Run(() => HandleAsync(tools, request)));
            inFlight.RemoveAll(t => t.IsCompleted);
        }

        await Task.WhenAll(inFlight);
        return 0;
    }

    private static async Task HandleAsync(KeyloTools tools, JsonObject request)
    {
        var id = request["id"]?.DeepClone();
        var method = request["method"]?.GetValue<string>();
        var parameters = request["params"] as JsonObject;
        if (id is null) return; // A notification (initialized, cancelled): nothing to answer.

        try
        {
            JsonNode result = method switch
            {
                "initialize" => Initialize(parameters),
                "ping" => new JsonObject(),
                "tools/list" => new JsonObject { ["tools"] = KeyloTools.Definitions() },
                "tools/call" => await CallToolAsync(tools, parameters),
                _ => throw new McpException(-32601, $"Method not found: {method}"),
            };
            await SendAsync(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result });
        }
        catch (McpException ex)
        {
            await SendAsync(Error(id, ex.Code, ex.Message));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"keylo mcp: {ex}");
            await SendAsync(Error(id, -32603, "Internal error"));
        }
    }

    private static JsonObject Initialize(JsonObject? parameters)
    {
        var requested = parameters?["protocolVersion"]?.GetValue<string>();
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
        return new JsonObject
        {
            ["protocolVersion"] = ProtocolVersions.Contains(requested) ? requested : ProtocolVersions[0],
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
            ["serverInfo"] = new JsonObject { ["name"] = "keylo", ["title"] = "Keylo", ["version"] = version },
            ["instructions"] = Instructions,
        };
    }

    private static async Task<JsonNode> CallToolAsync(KeyloTools tools, JsonObject? parameters)
    {
        var name = parameters?["name"]?.GetValue<string>() ?? throw new McpException(-32602, "Missing tool name.");
        var arguments = parameters["arguments"] as JsonObject ?? new JsonObject();
        if (!KeyloTools.Exists(name)) throw new McpException(-32602, $"Unknown tool: {name}");

        string text;
        var isError = false;
        try
        {
            text = await tools.CallAsync(name, arguments);
        }
        catch (Exception ex) when (ex is KeyloException or ArgumentException or FormatException or InvalidOperationException)
        {
            // Tool failures (denied, not found, bad arguments) go back to the agent as results it can act on.
            text = ex.Message;
            isError = true;
        }

        return new JsonObject
        {
            ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }),
            ["isError"] = isError,
        };
    }

    private static JsonObject Error(JsonNode? id, int code, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
    };

    private static async Task SendAsync(JsonObject message)
    {
        var bytes = Encoding.UTF8.GetBytes(message.ToJsonString() + "\n");
        await WriteLock.WaitAsync();
        try
        {
            await _out.WriteAsync(bytes);
            await _out.FlushAsync();
        }
        finally
        {
            WriteLock.Release();
        }
    }

    private sealed class McpException(int code, string message) : Exception(message)
    {
        public int Code { get; } = code;
    }
}
