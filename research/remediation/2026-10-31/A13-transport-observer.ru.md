# A13: принятый fhttp observer

Локальный fhttp `fc7146a` добавляет общие timing/activity hooks и измерение
connection-owned H2 PING. Это transport capability для будущего F03;
production estimator в root ещё не подключён, root pin пока прежний.

WriteHeadersStart сообщает начало protocol write после подготовки headers;
GotResponseHeaders — конец полных final headers. Первый байт,103 и неполный
HEADERS/CONTINUATION не подменяют второй край HTTP RTT. Method/status arguments
позволяют отличать внутренний CONNECT от исходного запроса. Hooks сохраняют
caller ClientTrace и порядок композиции.

GotResponseBodyBytes сообщает положительные reads encoded response body до
content decoding. Это activity timestamp, не transport byte counter. Новых
обёрток поверх concrete response bodies нет. PingRTT использует фактическое
время отправки собственного preface PING и ACK; callback вызывается вне
connection/ping locks. Нет callback/sample для неотвеченного PING.

Оба source-pinned графа — standalone и production-linked — приняты по1891
тестовому запуску. Return codes[0,0,0],unexpected0, новых allowances/exclusions
нет. Полные root batches сериализованы с прежним45s cooldown; sandbox разрешает
только owned loopback. Отдельно сохранены32 race-повтора H1/H2/trace hooks;
их combined invocation не называется serial full gate. Пределы существующих
проверок и исходные assertions сохранены. Regression gate не является browser
verdict или новой приёмкой всех transport scenarios.

[Машинный отчёт](checks-a13-transport-observer.json) содержит exact source SHA,
checks и immutable private capsule с before/after source. Push этого нового
fhttp коммита ещё требует отдельного разрешения. QUIC/H3/tls-client adapters,
profile activation, SDK capability и полная F03 приёмка ещё предстоят.
