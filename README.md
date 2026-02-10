# KerioControlUsageAnalyzer (WPF .NET 9)

Пример desktop-приложения (WPF), которое подключается к KerioControl 9.5 по JSON-RPC API, загружает HTTP/Internet логи и строит базовую аналитику по пользователям.

## Что реализовано

- Подключение к KerioControl (`Session.login`).
- Загрузка логов (`Logs.get`, лог `http`) за выбранный период.
- Отображение сырых записей в `DataGrid`.
- Сводка по пользователям:
  - количество запросов,
  - число уникальных хостов,
  - суммарный трафик (МБ).

## Структура

- `src/KerioControlUsageAnalyzer/MainWindow.xaml` — UI.
- `src/KerioControlUsageAnalyzer/ViewModels/MainViewModel.cs` — orchestration загрузки и анализа.
- `src/KerioControlUsageAnalyzer/Services/KerioJsonRpcClient.cs` — вызовы API Kerio.
- `src/KerioControlUsageAnalyzer/Services/LogAnalysisService.cs` — аналитика.

## Запуск

1. Установите .NET SDK 9 и Windows Desktop Runtime.
2. Откройте `src/KerioControlUsageAnalyzer/KerioControlUsageAnalyzer.csproj` в Visual Studio 2022/2025 Preview.
3. Запустите проект под Windows.

## Важные замечания по KerioControl 9.5

- В разных сборках KerioControl могут отличаться названия методов и схема ответа API.
- Если ваш сервер использует cookie-сессию вместо Bearer token, скорректируйте авторизацию в `KerioJsonRpcClient`.
- При самоподписанном TLS-сертификате может потребоваться настройка доверия сертификату в ОС или кастомный `HttpClientHandler`.

## Идеи для развития

- Сохранение настроек подключения (DPAPI/Windows Credential Manager).
- Фильтры по группам пользователей, категориям и доменам.
- Экспорт отчётов в CSV/XLSX.
- Построение графиков и уведомлений по аномалиям.
