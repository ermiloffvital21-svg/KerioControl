namespace KerioControlUsageAnalyzer.Models;

public sealed class UserUsageSummary
{
    public string Username { get; init; } = string.Empty;

    public int RequestsCount { get; init; }

    public int DistinctHosts { get; init; }

    public double TrafficMb { get; init; }
}
