using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using KerioControlUsageAnalyzer.Models;

namespace KerioControlUsageAnalyzer.Services;

public sealed class KerioJsonRpcClient
{
    private readonly HttpClient _httpClient;

    public KerioJsonRpcClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> LoginAsync(KerioConfig config, CancellationToken cancellationToken)
    {
        var url = BuildApiUrl(config.BaseUrl);
        var body = new
        {
            jsonrpc = "2.0",
            id = "login",
            method = "Session.login",
            @params = new
            {
                userName = config.Username,
                password = config.Password,
                application = new
                {
                    vendor = "Internal",
                    name = "KerioControlUsageAnalyzer",
                    version = "1.0"
                }
            }
        };

        using var response = await SendJsonRpcAsync(url, body, cancellationToken);
        EnsureNoJsonRpcError(response.RootElement, "Session.login");

        if (!response.RootElement.TryGetProperty("result", out var result))
        {
            throw new InvalidOperationException($"Kerio login failed: {response.RootElement}");
        }

        if (result.TryGetProperty("token", out var tokenElement))
        {
            return tokenElement.GetString() ?? string.Empty;
        }

        if (result.TryGetProperty("sessionToken", out var sessionTokenElement))
        {
            return sessionTokenElement.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    public async Task<IReadOnlyList<InternetLogEntry>> GetInternetLogsAsync(
        KerioConfig config,
        string token,
        DateTime from,
        DateTime to,
        CancellationToken cancellationToken)
    {
        var url = BuildApiUrl(config.BaseUrl);
        var attempts = BuildLogRequestPayloads(from, to);
        var attemptErrors = new List<string>();

        foreach (var attempt in attempts)
        {
            try
            {
                using var doc = await SendAuthorizedJsonRpcAsync(url, token, attempt.Payload, cancellationToken);
                EnsureNoJsonRpcError(doc.RootElement, attempt.AttemptName);

                if (!TryExtractLogItems(doc.RootElement, out var items))
                {
                    attemptErrors.Add($"{attempt.AttemptName}: response has no log array");
                    continue;
                }

                return ParseLogs(items);
            }
            catch (InvalidOperationException ex)
            {
                attemptErrors.Add(ex.Message);
            }
        }

        throw new InvalidOperationException($"Не удалось получить логи KerioControl. {string.Join("; ", attemptErrors)}");
    }

    private static IReadOnlyList<(string AttemptName, object Payload)> BuildLogRequestPayloads(DateTime from, DateTime to)
    {
        var fromIso = from.ToUniversalTime().ToString("O");
        var toIso = to.ToUniversalTime().ToString("O");
        var fromUnix = new DateTimeOffset(from.ToUniversalTime()).ToUnixTimeSeconds();
        var toUnix = new DateTimeOffset(to.ToUniversalTime()).ToUnixTimeSeconds();

        var fields = new[] { "timestamp", "user", "url", "category", "bytes" };
        var logNames = new[] { "http", "http_access", "web" };
        var attempts = new List<(string AttemptName, object Payload)>();

        foreach (var logName in logNames)
        {
            // Варианты с "logName"
            attempts.Add((
                $"Logs.get(logName={logName}, query.from/to iso)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    query = new { from = fromIso, to = toIso },
                    fields,
                    limit = 5000
                })));

            attempts.Add((
                $"Logs.get(logName={logName}, query.from/to unix)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    query = new { from = fromUnix, to = toUnix },
                    fields,
                    limit = 5000
                })));

            attempts.Add((
                $"Logs.get(logName={logName}, top-level from/to iso)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    from = fromIso,
                    to = toIso,
                    fields,
                    limit = 5000
                })));

            attempts.Add((
                $"Logs.get(logName={logName}, top-level from/to unix)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    from = fromUnix,
                    to = toUnix,
                    fields,
                    limit = 5000
                })));

            attempts.Add((
                $"Logs.get(logName={logName}, query.dateFrom/dateTo)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    query = new { dateFrom = fromIso, dateTo = toIso },
                    fields,
                    limit = 5000
                })));

            // Варианты с альтернативными ключами имени лога
            attempts.Add((
                $"Logs.get(name={logName}, query.from/to iso)",
                BuildPayload("Logs.get", new
                {
                    name = logName,
                    query = new { from = fromIso, to = toIso },
                    fields,
                    limit = 5000
                })));

            attempts.Add((
                $"Logs.get(type={logName}, query.from/to iso)",
                BuildPayload("Logs.get", new
                {
                    type = logName,
                    query = new { from = fromIso, to = toIso },
                    fields,
                    limit = 5000
                })));

            // Варианты filter/page
            attempts.Add((
                $"Logs.get(logName={logName}, filter.timestamp, page)",
                BuildPayload("Logs.get", new
                {
                    logName,
                    filter = new
                    {
                        timestamp = new { from = fromUnix, to = toUnix }
                    },
                    fields,
                    page = new { offset = 0, limit = 5000 }
                })));

            // Positional array
            attempts.Add((
                $"Logs.get positional({logName}, from,to,fields,limit)",
                BuildPayload("Logs.get", new object[] { logName, fromUnix, toUnix, fields, 5000 })));

            attempts.Add((
                $"Logs.get positional({logName}, query,fields,limit)",
                BuildPayload("Logs.get", new object[] { logName, new { from = fromIso, to = toIso }, fields, 5000 })));

            // Метод-синоним
            attempts.Add((
                $"LogReader.get({logName}, from/to)",
                BuildPayload("LogReader.get", new
                {
                    logName,
                    from = fromUnix,
                    to = toUnix,
                    fields,
                    limit = 5000
                })));

            // Минимальные
            attempts.Add((
                $"Logs.get(logName={logName})",
                BuildPayload("Logs.get", new { logName })));
        }

        attempts.Add(("Logs.get(empty params)", BuildPayload("Logs.get", new { })));
        attempts.Add(("Logs.get(positional empty)", BuildPayload("Logs.get", Array.Empty<object>())));

        return attempts;
    }

    private static object BuildPayload(string method, object parameters)
    {
        return new
        {
            jsonrpc = "2.0",
            id = Guid.NewGuid().ToString("N"),
            method,
            @params = parameters
        };
    }

    private async Task<JsonDocument> SendJsonRpcAsync(string url, object payload, CancellationToken cancellationToken)
    {
        var requestJson = JsonSerializer.Serialize(payload);

        using var response = await _httpClient.PostAsync(
            url,
            new StringContent(requestJson, Encoding.UTF8, "application/json"),
            cancellationToken);

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonDocument.Parse(content);
    }

    private async Task<JsonDocument> SendAuthorizedJsonRpcAsync(string url, string token, object payload, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonDocument.Parse(content);
    }

    private static bool TryExtractLogItems(JsonElement root, out JsonElement items)
    {
        items = default;

        if (!root.TryGetProperty("result", out var result))
        {
            return false;
        }

        if (result.ValueKind == JsonValueKind.Array)
        {
            items = result;
            return true;
        }

        if (TryGetArray(result, out items, "items", "list", "entries", "data", "logs", "records", "rows"))
        {
            return true;
        }

        if (TryGetArray(root, out items, "items", "list", "entries", "data", "logs", "records", "rows"))
        {
            return true;
        }

        return false;
    }

    private static bool TryGetArray(JsonElement obj, out JsonElement array, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var candidate) && candidate.ValueKind == JsonValueKind.Array)
            {
                array = candidate;
                return true;
            }
        }

        array = default;
        return false;
    }

    private static List<InternetLogEntry> ParseLogs(JsonElement items)
    {
        var logs = new List<InternetLogEntry>();

        foreach (var item in items.EnumerateArray())
        {
            logs.Add(new InternetLogEntry
            {
                Timestamp = ReadDate(item, "timestamp", "time", "date", "eventTime"),
                Username = ReadString(item, "user", "username", "srcUser", "account", "userName"),
                Url = ReadString(item, "url", "uri", "request", "requestUrl", "target"),
                Category = ReadString(item, "category", "contentCategory", "rule", "policy"),
                Bytes = ReadLong(item, "bytes", "size", "transferred", "sent", "rxBytes", "txBytes")
            });
        }

        return logs;
    }

    private static void EnsureNoJsonRpcError(JsonElement root, string attemptName)
    {
        if (!root.TryGetProperty("error", out var error))
        {
            return;
        }

        var message = error.TryGetProperty("message", out var messageElement)
            ? messageElement.GetString()
            : error.ToString();

        var code = error.TryGetProperty("code", out var codeElement)
            ? codeElement.ToString()
            : "n/a";

        throw new InvalidOperationException($"{attemptName}: JSON-RPC error (code={code}): {message}");
    }

    private static string BuildApiUrl(string baseUrl)
    {
        var normalized = baseUrl.TrimEnd('/');
        return $"{normalized}/admin/api/jsonrpc";
    }

    private static DateTime ReadDate(JsonElement item, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (!item.TryGetProperty(propertyName, out var property))
            {
                continue;
            }

            if (property.ValueKind == JsonValueKind.String && DateTime.TryParse(property.GetString(), out var parsedString))
            {
                return parsedString;
            }

            if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out var unixSeconds))
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).DateTime;
            }
        }

        return DateTime.MinValue;
    }

    private static string ReadString(JsonElement item, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (item.TryGetProperty(propertyName, out var property))
            {
                return property.GetString() ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private static long ReadLong(JsonElement item, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (!item.TryGetProperty(propertyName, out var property))
            {
                continue;
            }

            if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out var numberValue))
            {
                return numberValue;
            }

            if (property.ValueKind == JsonValueKind.String && long.TryParse(property.GetString(), out var parsedString))
            {
                return parsedString;
            }
        }

        return 0;
    }
}
