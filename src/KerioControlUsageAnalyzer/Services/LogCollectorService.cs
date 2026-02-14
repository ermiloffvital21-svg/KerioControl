using KerioControlUsageAnalyzer.Models;

namespace KerioControlUsageAnalyzer.Services;

public sealed class LogCollectorService
{
    private readonly KerioJsonRpcClient _client;

    public LogCollectorService(KerioJsonRpcClient client)
    {
        _client = client;
    }

    public async Task<IReadOnlyList<InternetLogEntry>> CollectAsync(
        KerioConfig config,
        DateTime from,
        DateTime to,
        CancellationToken cancellationToken)
    {
        var token = await _client.LoginAsync(config, cancellationToken);
        return await _client.GetInternetLogsAsync(config, token, from, to, cancellationToken);
    }
}
