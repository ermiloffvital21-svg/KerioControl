namespace KerioControlUsageAnalyzer.Models;

public sealed class InternetLogEntry
{
    public DateTime Timestamp { get; set; }

    public string Username { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public long Bytes { get; set; }
}
