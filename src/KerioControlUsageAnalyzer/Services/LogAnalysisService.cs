using KerioControlUsageAnalyzer.Models;

namespace KerioControlUsageAnalyzer.Services;

public sealed class LogAnalysisService
{
    public IReadOnlyList<UserUsageSummary> BuildUserSummary(IEnumerable<InternetLogEntry> logs)
    {
        return logs
            .GroupBy(x => string.IsNullOrWhiteSpace(x.Username) ? "unknown" : x.Username)
            .Select(group => new UserUsageSummary
            {
                Username = group.Key,
                RequestsCount = group.Count(),
                DistinctHosts = group
                    .Select(log => GetHost(log.Url))
                    .Where(host => !string.IsNullOrWhiteSpace(host))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count(),
                TrafficMb = Math.Round(group.Sum(x => x.Bytes) / 1024d / 1024d, 2)
            })
            .OrderByDescending(x => x.TrafficMb)
            .ToList();
    }

    private static string GetHost(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        return string.Empty;
    }
}
