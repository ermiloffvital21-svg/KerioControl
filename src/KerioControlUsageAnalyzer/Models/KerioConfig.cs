namespace KerioControlUsageAnalyzer.Models;

public sealed class KerioConfig
{
    public string BaseUrl { get; set; } = "https://kerio.local:4081";

    public string Username { get; set; } = "admin";

    public string Password { get; set; } = string.Empty;

    public bool IgnoreTlsCertificateErrors { get; set; } = true;

    // Примеры: Logs.get, Logs.read
    public string PreferredLogMethod { get; set; } = "Logs.get";

    // Примеры: http,http_access,web,access,traffic
    public string LogNamesCsv { get; set; } = "http,http_access,web,access,traffic";

    // Необязательно: JSON для @params (берется как есть и отправляется первым).
    public string CustomParamsJson { get; set; } = string.Empty;

    // Необязательно: полный JSON-RPC request (method + params), отправляется как есть и имеет наивысший приоритет.
    public string CustomRequestJson { get; set; } = string.Empty;
}
