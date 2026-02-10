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

        var response = await SendJsonRpcAsync(url, body, cancellationToken);

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
        var payload = new
        {
            jsonrpc = "2.0",
            id = "logs",
            method = "Logs.get",
            @params = new
            {
                logName = "http",
                query = new
                {
                    from = from.ToUniversalTime().ToString("O"),
                    to = to.ToUniversalTime().ToString("O")
                },
                fields = new[] { "timestamp", "user", "url", "category", "bytes" },
                limit = 5000
            }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("result", out var result) ||
            !result.TryGetProperty("items", out var items) ||
            items.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("Logs.get did not return result.items array. Проверьте доступность метода в вашей версии KerioControl.");
        }

        var logs = new List<InternetLogEntry>();

        foreach (var item in items.EnumerateArray())
        {
            logs.Add(new InternetLogEntry
            {
                Timestamp = ReadDate(item, "timestamp"),
                Username = ReadString(item, "user"),
                Url = ReadString(item, "url"),
                Category = ReadString(item, "category"),
                Bytes = ReadLong(item, "bytes")
            });
        }

        return logs;
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

    private static string BuildApiUrl(string baseUrl)
    {
        var normalized = baseUrl.TrimEnd('/');
        return $"{normalized}/admin/api/jsonrpc";
    }

    private static DateTime ReadDate(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out var property))
        {
            return DateTime.MinValue;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String when DateTime.TryParse(property.GetString(), out var parsed) => parsed,
            JsonValueKind.Number when property.TryGetInt64(out var unixSeconds) => DateTimeOffset.FromUnixTimeSeconds(unixSeconds).DateTime,
            _ => DateTime.MinValue
        };
    }

    private static string ReadString(JsonElement item, string propertyName)
    {
        return item.TryGetProperty(propertyName, out var property)
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }

    private static long ReadLong(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out var property))
        {
            return 0;
        }

        return property.ValueKind switch
        {
            JsonValueKind.Number when property.TryGetInt64(out var value) => value,
            JsonValueKind.String when long.TryParse(property.GetString(), out var parsed) => parsed,
            _ => 0
        };
    }
}
