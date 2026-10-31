# A13 / F03: первые измерения network hints

F03 A–B: проведены две независимые когорты по три fresh headed процесса Google
Chrome156.0.8078.76 на macOS27.0.1/arm64. В каждом — четыре HTTPS origins,
Accept-CH/Critical-CH, reload, реальные fetch и navigation после передачи
четырёх1MiB ответов. Сохранены192 target requests, оригинальные headers,
NetLog, CDP, версия/хеш бинарника и исходники owned peer. Для анализа noise
использованы72 явно связанные с launch наблюдения с заголовками.

Это измерительная порция. Production estimator F03 C–E ещё не реализован;
согласованный критерий F03 остаётся открытым. Существующие literal RTT,
Downlink и ECT в155/156 этим измерением не меняются. Новых literal значений
для151–154 нет.

## Закреплённый механизм и измерение

Использован официальный Chromium tag156.0.8078.76, а не HEAD:
[client_hints.cc](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/content/browser/client_hints/client_hints.cc),
[NQE](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/network_quality_estimator.cc)
и его параметры. DEPS закрепляет libc++97b436da4c33663581d394f4ee0a5977fc38c2f4;
исходник std::hash сохранён по этому revision. SHA всех полученных файлов
содержит [машинный отчёт](checks-a13-network-observations.json).

Правило заголовков использует host-dependent multiplier. Hash строки host
складывается с process salt1..21 и приводится к32 битам; остаток по21 выбирает
множитель0.90..1.10 с шагом0.01. Downlink округляется к50kbps и ограничивается
10Mbps, RTT — к50ms и ограничивается3000ms. Salt создаётся один раз на процесс,
а не заново для каждого заголовка. Для64-bit libc++ используется CityHash64;
сохранённый самостоятельный C++ oracle и установленная библиотека дали
одинаковые hashes четырёх hostnames.

Во всех шести NetLog начальная опубликованная оценка была HTTP RTT116ms,
transport RTT125ms, throughput1600kbps, ECT4G. Затем NetLog сохранял реальные
изменения RTT; throughput в этой кампании оставался1600kbps. В target headers
наблюдались Downlink1.50..1.75 и RTT0/50/100/150ms. Строка100/1.45/4g не
описывает эти состояния и их host binding.

| Проверка по всем72 наблюдениям | Результат |
| --- | --- |
| Закреплённое правило с32-bit truncation и единым salt на процесс | Согласуется со всеми6 процессами |
|64-bit modulo без truncation | Отвергнут в каждом процессе |
| Фиксированный Downlink1.45 | Отвергнут в каждом процессе |
| Множитель без зависимости от hostname | Отвергнут в каждом процессе |

Из-за50kbps quantization для каждого процесса остались два допустимых salt,
а не точное единственное значение. Совместимого одного salt для всех шести
процессов нет. Это конечная проверка согласованности source rule; она не
доказывает качество RNG, независимость draws или полное распределение.
Непрерывные исходные значения и запросы сохранены; нормализация касается
только явно вычисленных сравниваемых величин.

## Что требуется перед production estimator

В закреплённом NQE private-host requests фильтруются по разрешённому адресу.
Loopback transfer поэтому не принимается за controlled positive input
обновления estimator. Браузер также выполнял фоновые публичные запросы;
их NetLog сохранён. Зафиксированные переходы RTT нельзя приписывать задержке
owned peer или одному target HTTP response.

Следующий эксперимент должен отдельно контролировать допустимые HTTP RTT,
transport RTT и throughput inputs на принадлежащем владельцу публичном peer,
пороговые переходы ECT, отсутствие наблюдений, cache/default priors и смену
сети. Нужны fresh/reused/resumed connections и независимые cohorts. Затем
JSON сможет выбрать измеренные input/window/update/reset/rounding/noise rules,
а generic bounded state передаст их в общий H1/H2/H3/Critical-CH production
path. Scope каждой части состояния должен соответствовать независимому
browser instance; Fresh не переносит чужие mutable observations или opt-ins.

Отдельно остаются Linux/Windows и исторические151–155. Одной кампанией
156/macOS их denominator не закрывается. Local State snapshot и SHA бинарника
сохранены после кампании; исходные launch args, выводы и post-campaign версия сохранены. Отдельный
pre-launch immutable manifest каждой копии профиля и бинарника не снимался;
post-campaign snapshot не выдаётся за него.

Private capsule:79 файлов,146024791 bytes,
manifest SHA256 `d9c36f6e99e8c24294372036c740dd4fcdd4a78ea7d2cd20096f0b5fc3a21c9c`.
Исходные TLS secrets/NetLog находятся только в ignored collector captures.
