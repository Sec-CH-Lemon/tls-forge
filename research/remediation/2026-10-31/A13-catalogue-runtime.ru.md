# A13: локальная приёмка каталожного runtime

**Реализована и локально принята materialization F02/C. A13 остаётся открыт:**
production F03, same-major SDK/daemon capability negotiation и native CI ещё
предстоят. Technical source-equivalence не является новой приёмкой всех
исторических браузеров и платформ.

Все83 aliases сохранены и исполняют полные JSON descriptors вместо
MappedTLSClients fallback: TLS vectors/extensions, H1/H2/H3 поля, policies и
lifecycle. Исходный handshake-only scope сохранён: новые browser headers
не придуманы. Registry и compatibility bare-base API читают единственную
data authority. Name/UA не выбирают скрытый браузерный runtime.

Для50 aliases отдельно материализован native QUIC TLS: явные cipher vectors
с hardware-AES selection, точный порядок extensions, TLS1.3/empty session ID,
live transport parameters и свежая связанная MLKEM768/X25519 генерация.
Профили выбирают implemented primitives; keys, tickets, CIDs, binders и counters
не заморожены из capture. Параметры transport/layout, окон, cache capacities,
keepalive, GREASE length и ACK choices доходят до production paths.

В18 shipped profiles и3 close_notify variants добавлены16 обязательных choices.
Отдельный derivation inventory связывает исходные hashes и новые bytes;
original capture provenance не переписан. Класс новых данных — source-derived,
без присвоения нового measured browser verdict. Load/Save/Clone сохраняют
выборы и изолируют mutable данные. Отсутствующие capabilities отклоняются до
I/O на всех schemas. Только явная Migrate дополняет архив из pinned JSON.

Отдельно сохранён RED: raw ClientHello без per_connection мог зависеть от
метаданных и становиться исполняемым после Save. Теперь generation rule
обязателен, Save не выводит его из имени, migration использует исходную
идентичность, а не новое имя назначения. Старые файлы и major не ретегируются.

| Проверка R15 | Результат |
| --- | --- |
| Полный Go normal |23/23 пакета,209.341s |
| Полный Go race |23/23 пакета,897.114s |
| Coverage artifact |17225 statements,0 uncovered |
| Строгий lint |0 issues |
| Source drift |0 между frozen checks |
| FuzzLoad |106548 выполнений,31.1s,без отказов |
| Actual H1/H2/H3 |Все83 aliases; paired raw evidence и прежние assertions сохранены |
| Native source hello comparison |24 пары,6 negative controls отвергнуты |
| Native PSK cold/reused/resumed |12 authenticated requests у2 aliases в2 cohorts |

Lifecycle comparisons используют явно выбранный client scope, чтобы проверить
reuse/resumption; shipped default request isolation удерживается отдельными
A10 controls. Ранее недоступные before-H3 scenarios не удалены из знаменателя:
исходные отказы сохранены, after assertions исполняются для каждого alias.
Нормализации перечислены по полям, исходные значения и packet bytes сохранены.
Финитные свежие draws не доказывают RNG quality или неотличимость браузера.

Полный R13 race прежде отказал в DNS observation и SIGTERM startup fixtures.
Исходный snapshot и оба отказа сохранены; fixes приняты отдельными commits
с negative controls, без ослабления запросов/assertions/deadlines. R14 и R15 — новые
неизменные snapshots, не удаление прежнего отказа. Причина одиночного DNS
отказа не объявлена доказанной только из успешных повторов.

В финальный R15 вошли public pins uTLSbfb/QUIC6f/tls-client30e и отдельный
before/after control: child с tcp-adapter policy мог унаследовать native QUIC
factory от bare-base. Выбранный профиль теперь всегда очищает inherited factory
перед установкой собственной.32 race-повтора и полный normal/race R15 приняты.

[Машинный отчёт](checks-a13-catalogue-runtime.json) содержит exact source/checks
и verified1588-file private capsule. Engine остаётся unpublished1. Нового
Chrome witness в этой кодовой порции нет; новые F03 ECT наблюдения ведутся
отдельной кампанией и пока не дают production estimator acceptance.
