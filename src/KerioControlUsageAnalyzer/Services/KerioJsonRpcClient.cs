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
        using var response = await SendJsonRpcAsync(url, BuildPayload("Session.login", new
        {
            userName = config.Username,
            password = config.Password,
            application = new
            {
                vendor = "Internal",
                name = "KerioControlUsageAnalyzer",
                version = "1.0"
            }
        }), cancellationToken);

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
        var discoveredMethods = await DiscoverLogMethodsAsync(url, token, cancellationToken);
        var attempts = BuildLogRequestPayloads(from, to, discoveredMethods);
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

        var discovered = discoveredMethods.Count == 0 ? "n/a" : string.Join(", ", discoveredMethods);
        throw new InvalidOperationException(
            $"Не удалось получить логи KerioControl. Обнаруженные методы логов: {discovered}. Ошибки: {string.Join("; ", attemptErrors)}");
    }

    private static IReadOnlyList<(string AttemptName, object Payload)> BuildLogRequestPayloads(
        DateTime from,
        DateTime to,
        IReadOnlyList<string> discoveredMethods)
    {
        var methods = discoveredMethods.Count > 0
            ? discoveredMethods
            : new[] { "Logs.get" };

        var fromIso = from.ToUniversalTime().ToString("O");
        var toIso = to.ToUniversalTime().ToString("O");
        var fromUnix = new DateTimeOffset(from.ToUniversalTime()).ToUnixTimeSeconds();
        var toUnix = new DateTimeOffset(to.ToUniversalTime()).ToUnixTimeSeconds();

        var fields = new[] { "timestamp", "user", "url", "category", "bytes" };
        var sortBy = new[] { new { columnName = "timestamp", direction = "Desc" } };
        var logNames = new[] { "http", "http_access", "web", "access" };

        var queryFromTo = new { from = fromIso, to = toIso };
        var queryKerio = BuildKerioQuery(fromUnix, toUnix);
        var attempts = new List<(string AttemptName, object Payload)>();

        foreach (var method in methods)
        {
            foreach (var logName in logNames)
            {
                attempts.Add(($"{method}(logName={logName}, query+fields+sortBy+start+limit)", BuildPayload(method, new
                {
                    logName,
                    query = queryKerio,
                    fields,
                    sortBy,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method}(logName={logName}, query+sortBy+start+limit)", BuildPayload(method, new
                {
                    logName,
                    query = queryKerio,
                    sortBy,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method}(query+sortBy+start+limit,no logName)", BuildPayload(method, new
                {
                    query = queryKerio,
                    sortBy,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method}(query.from/to,no logName)", BuildPayload(method, new
                {
                    query = queryFromTo,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method}(log={logName}, query+sortBy)", BuildPayload(method, new
                {
                    log = logName,
                    query = queryKerio,
                    sortBy,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method}(type={logName}, query+sortBy)", BuildPayload(method, new
                {
                    type = logName,
                    query = queryKerio,
                    sortBy,
                    start = 0,
                    limit = 5000
                })));

                attempts.Add(($"{method} positional(logName,query,sortBy,start,limit)", BuildPayload(method, new object[]
                {
                    logName,
                    queryKerio,
                    sortBy,
                    0,
                    5000
                })));

                attempts.Add(($"{method} positional(query,sortBy,start,limit)", BuildPayload(method, new object[]
                {
                    queryKerio,
                    sortBy,
                    0,
                    5000
                })));

                attempts.Add(($"{method} positional(query,start,limit)", BuildPayload(method, new object[]
                {
                    queryKerio,
                    0,
                    5000
                })));

                attempts.Add(($"{method}(logName={logName}, from/to unix + offset/count)", BuildPayload(method, new
                {
                    logName,
                    from = fromUnix,
                    to = toUnix,
                    offset = 0,
                    count = 5000,
                    sortBy
                })));

                attempts.Add(($"{method}(logName={logName})", BuildPayload(method, new { logName })));
            }

            attempts.Add(($"{method}(empty params)", BuildPayload(method, new { })));
        }

        attempts.Add(("Logs.get(no params member)", BuildPayloadWithoutParams("Logs.get")));
        attempts.Add(("Logs.query(no params member)", BuildPayloadWithoutParams("Logs.query")));

        return attempts;
    }

    private static object BuildKerioQuery(long fromUnix, long toUnix)
    {
        return new
        {
            conditions = new object[]
            {
                new { fieldName = "timestamp", comparator = "GreaterOrEqual", value = fromUnix },
                new { fieldName = "timestamp", comparator = "LessOrEqual", value = toUnix }
            },
            combination = "And"
        };
    }

    private async Task<IReadOnlyList<string>> DiscoverLogMethodsAsync(string url, string token, CancellationToken cancellationToken)
    {
        var candidates = new HashSet<string>(StringComparer.Ordinal);
        var probes = new[]
        {
            BuildPayloadWithoutParams("system.listMethods"),
            BuildPayloadWithoutParams("system.describe"),
            BuildPayloadWithoutParams("Api.getMethods")
        };

        foreach (var probe in probes)
        {
            try
            {
                using var doc = await SendAuthorizedJsonRpcAsync(url, token, probe, cancellationToken);
                if (!TryExtractMethodNames(doc.RootElement, out var methods))
                {
                    continue;
                }

                foreach (var method in methods)
                {
                    if (method.Contains("log", StringComparison.OrdinalIgnoreCase))
                    {
                        candidates.Add(method);
                    }
                }
            }
            catch
            {
                // ignore and continue
            }
        }

        return candidates
            .OrderBy(x => x.Contains("Logs.get", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(x => x, StringComparer.Ordinal)
            .Take(8)
            .ToArray();
    }

    private static bool TryExtractMethodNames(JsonElement root, out IReadOnlyList<string> methods)
    {
        var list = new List<string>();

        static void Collect(JsonElement e, List<string> listTarget)
        {
            if (e.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in e.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var s = item.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            listTarget.Add(s);
                        }
                    }
                    else if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
                    {
                        var s = n.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            listTarget.Add(s);
                        }
                    }
                }
            }
        }

        if (root.TryGetProperty("result", out var result))
        {
            Collect(result, list);
            if (result.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in result.EnumerateObject())
                {
                    Collect(prop.Value, list);
                }
            }
        }

        methods = list.Distinct(StringComparer.Ordinal).ToArray();
        return methods.Count > 0;
    }

    private static object BuildPayload(string method, object parameters) => new
    {
        jsonrpc = "2.0",
        id = Guid.NewGuid().ToString("N"),
        method,
        @params = parameters
    };

    private static object BuildPayloadWithoutParams(string method) => new
    {
        jsonrpc = "2.0",
        id = Guid.NewGuid().ToString("N"),
        method
    };

    private async Task<JsonDocument> SendJsonRpcAsync(string url, object payload, CancellationToken cancellationToken)
    {
        var requestJson = JsonSerializer.Serialize(payload);
        using var response = await _httpClient.PostAsync(url, new StringContent(requestJson, Encoding.UTF8, "application/json"), cancellationToken);
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

        var details = error.TryGetProperty("data", out var dataElement)
            ? dataElement.ToString()
            : string.Empty;

        var detailsSuffix = string.IsNullOrWhiteSpace(details) ? string.Empty : $" | data: {details}";

        throw new InvalidOperationException($"{attemptName}: JSON-RPC error (code={code}): {message}{detailsSuffix}");
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
