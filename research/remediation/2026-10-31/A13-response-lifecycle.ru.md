# A13: завершение body и автоматический H2

fhttp `bd9be71` добавляет once-only `GotResponseBodyDone(method)` при EOF/error,
Close, no-body completion и передаче тела в background drainer. Существующие
типы transport body и независимое время жизни drainer сохранены. Callback
вызывается вне body/connection locks; decoder wrappers только передают событие.

До исправления отдельный H2 API наблюдал timing/activity, а автоматический
H2 из `fhttp.Transport` пропускал все три hooks: реальный запрос с правильными
протоколом и телом давал `0/0/0`. Неизменённый регрессионный тест сохранён
в коммите. Исправление синхронизирует observation-часть поддерживаемого H2
bundle с отдельным H2; полной регенерации со сторонними runtime-изменениями нет.

После исправления прошли 16 race-повторов автоматического H2 контроля и
12 lifecycle-сценариев H1/automatic H2/separate H2 × EOF/Close/drain/empty.
Тесты удерживают суффикс body: возврат headers и положительное непоследнее
чтение не считаются завершением; drainer остаётся жив после передачи ownership,
повторный Close не дублирует событие.

Оба полных source-pinned графа приняты по 1905 запусков, returncodes[0,0,0],
unexpected0, без новых allowances/exclusions. Root batches сериализованы с
прежним 45s cooldown; сеть ограничена owned loopback. Длительные существующие
TestRequestLimit_h2 завершились успешно; deadlines и assertions не менялись.

[Точный отчёт и manifest](checks-a13-response-lifecycle.json) сохраняет before,
after и сырые логи. R18 не переписан. Два fhttp-коммита пока локальны; root pin
прежний. H3 adapters, полная production F03, native и историческая браузерная
приёмка остаются открытыми. Эти gates не доказывают browser indistinguishability.
