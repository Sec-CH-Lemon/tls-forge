# A13 F03: ECT transitions и host noise

Production F03 остаётся открыт. Эта порция устанавливает конечные наблюдения
Chrome156.0.8078.76 на macOS27.0.1 arm64, в headed fresh processes с явно
сохранённым warm-template input, binary SHA и flags.

Две независимые когорты по3 процесса прошли заранее заданный сценарий
opaque TCP latency tunnel:200/800/1500/0ms в одну сторону и11s idle между
запросами. TLS bytes не переписывались; public origin проверялся обычным
сертификатом, SPKI override относился только к owned loopback peer. В каждом
процессе34 public scripted GET завершились200; всего204. Все четыре ECT
состояния4g/3g/2g/slow-2g подтверждены в navigator и actual request headers
(120 header observations). Это не смена физической сети и не reset estimator.

Исходная первая кампания не объявлена принятой: её a2 driver принял load от
предыдущего документа, навигация была aborted, fetch получил CORS отказ.
Raw CDP и source сохранены. Новый driver привязывает load к точному loaderId,
проверяет frame URL и сохраняет Runtime exceptionDetails. Criteria, requests
и deadlines не ослаблены; новая R02 кампания отделена от старого отказа.

Короткие hostnames4–8 bytes различают два libc++ ABI hash variants. В отдельной
settled-startup когорте2×3 процесса144 actual hint headers объясняются widened
ABI2 и одним salt на процесс; ABI1 не подходит ни одному процессу. Повторение
salt между процессами допустимо. Уникальность draws и RNG distribution не
утверждаются. Pinned Chromium __config_site задаёт ABI_VERSION2.

В первой un-settled когорте предположение о неизменном1600kbps input не
объясняет первые два headers b0. Эти значения сохранены. Source-derived
кандидат воспроизводит переход platform seed к in-memory cached estimate:
initial ECT cache может ещё не иметь transport/downlink; deferred read
заполняет их typical values. Это объяснение проверяется отдельно от прямого
наблюдения внутреннего browser event; ранние строки не выкинуты из анализа.

Отдельные2×3 процесса выполнили96 public GET к /bytes:4 large,6 small и6
large transfers. Ответы200 и exact lengths приняты. Downlink в этих конечных
фазах не изменился. JS overlap не доказывает число eligible NQE URLRequests;
приёмка эффективных min-inflight/min-transfer параметров не присваивается.
Требуется полный timeline окна, источников и публикации.

Наблюдатель платформы также требует data selection: pinned Windows getter
возвращает false, а native macOS SDK определяет TCP_CONNECTION_INFO без
TCP_INFO, которым ограничен pinned POSIX getter. Полная include/build closure
и native matrix остаются отдельными controls; наличие API не доказывает
использование его браузером.

[Машинный отчёт](checks-a13-network-transitions.json) связывает результаты с
неизменной464-file private capsule (352815109 bytes). Исходные headers,
NetLog, TLS keys, driver/tunnel sources и неудачные эксперименты сохранены
под ignored captures с0700/0600. Frozen-ECT и wrong-ABI controls отвергнуты;
это ещё не production generator negative-control acceptance.
