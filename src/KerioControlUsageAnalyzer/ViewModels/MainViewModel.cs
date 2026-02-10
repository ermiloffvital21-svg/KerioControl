using System.Collections.ObjectModel;
using System.Net.Http;
using KerioControlUsageAnalyzer.Infrastructure;
using KerioControlUsageAnalyzer.Models;
using KerioControlUsageAnalyzer.Services;

namespace KerioControlUsageAnalyzer.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly LogAnalysisService _analysisService = new();

    private bool _isBusy;
    private string _statusMessage = "Готово";
    private DateTime? _fromDate = DateTime.Today.AddDays(-1);
    private DateTime? _toDate = DateTime.Today;

    public MainViewModel()
    {
        Config = new KerioConfig();
        Logs = new ObservableCollection<InternetLogEntry>();
        UserSummaries = new ObservableCollection<UserUsageSummary>();
        LoadLogsCommand = new RelayCommand(_ => LoadLogsAsync(), _ => !_isBusy);
    }

    public KerioConfig Config { get; }

    public ObservableCollection<InternetLogEntry> Logs { get; }

    public ObservableCollection<UserUsageSummary> UserSummaries { get; }

    public RelayCommand LoadLogsCommand { get; }

    public DateTime? FromDate
    {
        get => _fromDate;
        set => SetProperty(ref _fromDate, value);
    }

    public DateTime? ToDate
    {
        get => _toDate;
        set => SetProperty(ref _toDate, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    private async Task LoadLogsAsync()
    {
        if (!FromDate.HasValue || !ToDate.HasValue)
        {
            StatusMessage = "Укажите период загрузки.";
            return;
        }

        if (string.IsNullOrWhiteSpace(Config.BaseUrl) || string.IsNullOrWhiteSpace(Config.Username))
        {
            StatusMessage = "Заполните URL и логин KerioControl.";
            return;
        }

        _isBusy = true;
        LoadLogsCommand.RaiseCanExecuteChanged();

        try
        {
            StatusMessage = "Подключение к KerioControl...";

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            using var httpClient = CreateHttpClient(Config.IgnoreTlsCertificateErrors);
            var collector = new LogCollectorService(new KerioJsonRpcClient(httpClient));

            var logs = await collector.CollectAsync(
                Config,
                FromDate.Value.Date,
                ToDate.Value.Date.AddDays(1).AddTicks(-1),
                cts.Token);

            Logs.Clear();
            foreach (var log in logs.OrderByDescending(x => x.Timestamp))
            {
                Logs.Add(log);
            }

            UserSummaries.Clear();
            foreach (var summary in _analysisService.BuildUserSummary(logs))
            {
                UserSummaries.Add(summary);
            }

            StatusMessage = $"Загружено записей: {Logs.Count}. Пользователей в сводке: {UserSummaries.Count}.";
        }
        catch (HttpRequestException ex) when (ContainsSslError(ex))
        {
            StatusMessage = "Ошибка SSL/TLS. Включите 'Игнорировать ошибки TLS' или установите доверенный сертификат на KerioControl.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка: {ex.Message}";
        }
        finally
        {
            _isBusy = false;
            LoadLogsCommand.RaiseCanExecuteChanged();
        }
    }

    private static HttpClient CreateHttpClient(bool ignoreTlsCertificateErrors)
    {
        var handler = new HttpClientHandler();

        if (ignoreTlsCertificateErrors)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        return new HttpClient(handler, disposeHandler: true);
    }

    private static bool ContainsSslError(HttpRequestException ex)
    {
        var text = ex.ToString();
        return text.Contains("SSL", StringComparison.OrdinalIgnoreCase)
               || text.Contains("TLS", StringComparison.OrdinalIgnoreCase)
               || text.Contains("certificate", StringComparison.OrdinalIgnoreCase);
    }
}
