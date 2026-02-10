namespace KerioControlUsageAnalyzer.Models;

public sealed class KerioConfig
{
    public string BaseUrl { get; set; } = "https://kerio.local:4081";

    public string Username { get; set; } = "admin";

    public string Password { get; set; } = string.Empty;

    public bool IgnoreTlsCertificateErrors { get; set; } = true;
}
