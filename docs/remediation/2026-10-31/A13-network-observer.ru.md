# A13 F03: контракт наблюдателя сети

Статус: source-bound исследование и контракт входов. Production estimator
не реализован; F03 C–E остаются открытыми. Новых browser samples эта порция
не добавляет. Прежние12 Chrome156/macOS процессов и их raw evidence сохранены.

Источники закреплены на tag156.0.8078.76, не HEAD. Хеши локальных первичных
файлов — в [машинном отчёте](checks-a13-network-observer.json).
Основные функции:
[NotifyHeadersReceivedInternal, RequestProvidesRTTObservation и OnConnectionTypeChanged](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/network_quality_estimator.cc),
[ThroughputAnalyzer](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/throughput_analyzer.cc),
[ObservationBuffer](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/observation_buffer.cc),
[параметры](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/network_quality_estimator_params.cc),
[publisher](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/services/network/network_quality_estimator_manager.cc).

## Какие входы нужны

| Вход | Первичный механизм | Что нельзя подставить вместо него |
| --- | --- | --- |
| HTTP RTT | receive_headers_end минус send_start для подходящего GET | Полное время Client.Do, WroteRequest или FirstByte |
| Transport RTT | Отдельные socket/QUIC RTT observations | TLS handshake duration или HTTP RTT |
| Throughput | Разность общего transport receive counter за подходящее окно с ограничениями по активным запросам | len(decoded Body) / duration одного ответа |
| Network change | Идентичность сети, время перехода, сброс/кэш по сети | Имя origin или новый random на каждом header |
| Publication | Асинхронное изменение доступной браузеру оценки | Редкие NETWORK_QUALITY_CHANGED записи как полный timeline |

Текущий [Trace](../../../trace.go) даёт FirstByte и WroteRequest, но не
оба точных края Chromium HTTP RTT. [hintValues](../../../clienthints.go)
пока читает literal profile data. Нет общего production observer для всех
трёх метрик и сетевого reset, на основании которого можно закрыть F03.

RequestProvidesRTTObservation фильтрует private hosts, cache, запросы,
начатые до network change, и методы кроме GET. Время включает ожидание полных
response headers, исключая DNS/TLS до send_start. Cache validation и304 требуют
отдельного согласования stage/was_cached с реальным Chrome, а не догадки.

ThroughputAnalyzer использует activity_monitor::GetBytesReceived()*8.
В pinned исходнике fallback minimum —5 in-flight requests и32KiB; наблюдатель
учитывает запросы, ухудшающие точность, hanging windows и переход сети.
Это source defaults, не основание приписать каждый fallback всем установкам.

## Состояние и JSON

ObservationBuffer ограничен ёмкостью, хранит timestamps в порядке, вытесняет
самое старое наблюдение и считает взвешенный percentile. Веса зависят от
целых секунд возраста и разности signal strength; source fallback half-life
равен60s, feature parameter buffer size —300. Все эти выбираемые значения,
фильтры, окна, пороги recompute, приоритеты источников и reset/cache policy
должны быть явными JSON rules; Go реализует механизмы без browser-name dispatch.

ECT в этом pinned алгоритме классифицируется по итоговому HTTP RTT после
коррекции другими RTT. Комментарий о throughput не заменяет actual branch:
в последнем цикле threshold проверяется именно HTTP RTT. Это не разрешает
потерять throughput: он всё равно влияет на downlink и состояние оценщика.

Source lifecycle network change сохраняет старую оценку по network identity,
очищает RTT/throughput histories, private-host cache, counters, timestamps и
прилагает оценки новой сети. Смена WiFi может иметь тот же connection type.
Смена одного hostname не равна этому переходу.

Scope должен соблюдать принятое A10 решение владельца: каждый обычный Do и
Fresh — отдельный logical browser instance. Salt и mutable observations не
переносятся между такими инстансами. Явный persistent test/client scope имеет
своё состояние. Clone сохраняет policy, не замораживает snapshot estimator.

Noise/hash/rounding уже исследованы отдельно. Captured salt не становится
production default. Literal и generator для одного hint должны конфликтовать
явно; отсутствующий input отличим от0. Не добавлять скрытый fallback100/1.45/4g.

Если нужны внешние network/page inputs, сначала типизированный контракт Go,
Node/Python и daemon с capability negotiation. Network ID — partition key,
а не готовый RTT. Старый процесс не должен молча игнорировать новые inputs.

## Что ещё проверить до production defaults

- Согласованный timeline actual observer, publisher и headers; cache304,
  redirects, Critical-CH и ALPS на H1/H2/H3.
- Контролируемые ECT transitions и network reset в двух независимых когортах.
- Реальные kernel/QUIC RTT и transport byte counters на поддержанных платформах.
- Deterministic clock/RNG, JSON-only изменения порогов/окон/lifecycle, два
  клиента, concurrency, no-input и неправильный origin/opt-in negative controls.
- Матрицу всех заявленных browser/platform combinations. Исторические версии
  и другие платформы не исчезают из знаменателя из-за отсутствия измерения.

Повторный разбор constants всех12 сохранённых NetLog показывает только
SeedFileTrial:SeedFilesLaunched в activeFieldTrialGroups. Raw receipt сохранён.
Это полезная provenance, но не самостоятельное доказательство эффективных
значений каждого feature parameter. Новая browser/RNG/universal verdict
этим source review не устанавливается.
