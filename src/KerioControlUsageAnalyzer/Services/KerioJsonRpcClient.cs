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
            return tokenElement.GetString() ?? throw new InvalidOperationException("Kerio returned empty session token.");
        }

        if (result.TryGetProperty("sessionToken", out var sessionTokenElement))
        {
            return sessionTokenElement.GetString() ?? throw new InvalidOperationException("Kerio returned empty session token.");
        }

        throw new InvalidOperationException("Kerio login response does not include token/sessionToken.");
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
                EnsureNoJsonRpcError(doc.RootElement, attempt.MethodName);

                if (!TryExtractLogItems(doc.RootElement, out var items))
                {
                    attemptErrors.Add($"{attempt.MethodName}: нет массива записей в ответе");
                    continue;
                }

                var logs = ParseLogs(items);
                if (logs.Count > 0)
                {
                    return logs;
                }

                // Пустой массив — корректный ответ (просто нет данных в периоде).
                return logs;
            }
            catch (InvalidOperationException ex)
            {
                attemptErrors.Add($"{attempt.MethodName}: {ex.Message}");
            }
        }

        var allErrors = string.Join("; ", attemptErrors);
        throw new InvalidOperationException($"Не удалось получить логи KerioControl. {allErrors}");
    }

    private static IReadOnlyList<(string MethodName, object Payload)> BuildLogRequestPayloads(DateTime from, DateTime to)
    {
        var fromIso = from.ToUniversalTime().ToString("O");
        var toIso = to.ToUniversalTime().ToString("O");

        return new List<(string, object)>
        {
            (
                "Logs.get",
                new
                {
                    jsonrpc = "2.0",
                    id = "logs-get",
                    method = "Logs.get",
                    @params = new
                    {
                        logName = "http",
                        query = new { from = fromIso, to = toIso },
                        fields = new[] { "timestamp", "user", "url", "category", "bytes" },
                        limit = 5000
                    }
                }
            ),
            (
                "Logs.get (http_access)",
                new
                {
                    jsonrpc = "2.0",
                    id = "logs-get-http-access",
                    method = "Logs.get",
                    @params = new
                    {
                        logName = "http_access",
                        query = new { from = fromIso, to = toIso },
                        fields = new[] { "timestamp", "user", "url", "category", "bytes" },
                        limit = 5000
                    }
                }
            )
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

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

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

        if (TryGetArray(result, out items, "items", "list", "entries", "data", "logs", "records"))
        {
            return true;
        }

        if (TryGetArray(root, out items, "items", "list", "entries", "data", "logs", "records"))
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
                Timestamp = ReadDate(item, "timestamp", "time", "date"),
                Username = ReadString(item, "user", "username", "srcUser", "account"),
                Url = ReadString(item, "url", "uri", "request", "requestUrl"),
                Category = ReadString(item, "category", "contentCategory", "rule"),
                Bytes = ReadLong(item, "bytes", "size", "transferred", "sent")
            });
        }

        return logs;
    }

    private static void EnsureNoJsonRpcError(JsonElement root, string methodName)
    {
        if (!root.TryGetProperty("error", out var error))
        {
            return;
        }

        var message = error.TryGetProperty("message", out var messageElement)
            ? messageElement.GetString()
            : error.ToString();

        throw new InvalidOperationException($"{methodName}: {message}");
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
