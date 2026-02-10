# KerioControlUsageAnalyzer (WPF .NET 9)

Пример desktop-приложения (WPF), которое подключается к KerioControl 9.5 по JSON-RPC API, загружает HTTP/Internet логи и строит базовую аналитику по пользователям.

## Что реализовано

- Подключение к KerioControl (`Session.login`).
- Загрузка логов (`Logs.get`, лог `http`) за выбранный период.
- Отображение сырых записей в `DataGrid`.
- Опция игнорирования TLS ошибок для KerioControl с self-signed сертификатом.
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

- Для предотвращения `A task was canceled` клиент ограничивает количество fallback-попыток и использует увеличенный таймаут запроса; при таймауте UI показывает отдельное понятное сообщение.
- В разных сборках KerioControl могут отличаться названия методов и схема ответа API. Клиент теперь динамически пытается определить доступные log-методы через discovery (`system.listMethods`/`system.describe`/`Api.getMethods`) и затем подбирает несколько форм вызова (`query`, `from/to`, `filter/page`, `start/count`, named/positional, payload без `params`) для `http`/`http_access`/`web`, включая расширенный перебор ключей (`logName/name/type/log/logType`), контейнеров (`query/filter/criteria`) и диапазонов времени (`from/to`, `dateFrom/dateTo`, `begin/end`).
- Если ваш сервер использует cookie-сессию вместо Bearer token, скорректируйте авторизацию в `KerioJsonRpcClient`.
- Диагностика JSON-RPC ошибок включает `error.data`, если сервер его возвращает (полезно для разбора `Invalid params`).
- По умолчанию в приложении включена опция игнорирования TLS-ошибок (удобно для self-signed). Для продакшена рекомендуется выключить эту опцию и установить доверенный сертификат.

## Идеи для развития

- Сохранение настроек подключения (DPAPI/Windows Credential Manager).
- Фильтры по группам пользователей, категориям и доменам.
- Экспорт отчётов в CSV/XLSX.
- Построение графиков и уведомлений по аномалиям.
