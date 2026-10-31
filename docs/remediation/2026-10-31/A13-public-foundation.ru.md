# A13: опубликованный QUIC runtime и проверочные peers

Принят dependency-компонент; каталог и сетевой оценщик A13 ещё открыты.
Закреплены публичные uTLS `bfb5cb3`, QUIC `6f655a61` и tls-client `48691d4`.
Локальные replace и go.work для приёмки не использовались. Все три remote
head проверены после разрешённых владельцем push.

uTLS задаёт явные QUIC policies и аппаратный AES capability. QUIC исполняет
transport/layout и ACK choices из JSON. tls-client передаёт независимую QUIC
ClientHello factory, конфигурацию и cache selection во все соответствующие
пути. Браузерные значения остаются данными; перенос root catalogue всё ещё
проверяется отдельно. Engine остаётся unpublished 1.0.0.

Оба source-pinned графа uTLS прошли по695 запусков, QUIC — по2592,
tls-client — по466. Новых allowances/exclusions нет. На публичном графе до
последнего test-only коммита tls-client прошли23/23 normal и23/23 race пакета
root; покрыты все17059 statements. Последний коммит меняет только LEMON и
два test-файла: runtime побайтно тот же. На окончательных pins отдельно
прошли tidy, verify, CLI build, race peer witness и lint0. Неиспользуемая
root test wrapper удалена отдельно; исходный lint-отчёт сохранён.

Первый standalone QUIC прогон имел1s timeout
`TestHandshakeAddrResolutionHelpers`. Фиксированные диагностические когорты
32before/32after и один заранее выбранный serial full gate прошли с прежним
таймаутом. Причина первоначального отказа не доказана.

Первый полностью связанный граф tls-client `c098a97` имел5s timeout в
проверке нулевого H3 header limit. Диагностика отдельно воспроизвела TCP/UDP
port collision у test peer. `48691d4` резервирует обе стороны до запроса;
ограниченный повтор касается только подготовки сокетов при EADDRINUSE.
Запросы, response assertions и deadlines не повторяются и не ослаблены.
После исправления прошли384 фиксированных H3-сценария и оба полных графа.
Это не доказывает причину исходного5s timeout; он сохранён как ограничение.

Дополнительная широкая wire-race диагностика не зелёная: allocation assertion
на неизменном parser STREAM падал и до, и после. Обычная zero-allocation
проверка сохранена; targeted ACK/wire/H3 race не заменяет эту диагностику.

Исходные отказы, точные source exports, qlog, before/after и успешные результаты
сохранены в ignored private capsule. Манифест SHA-256 проверен, права0700/0600.
[Машинный отчёт](checks-a13-public-foundation.json) содержит точные heads,
объём и hash манифеста. Новых запусков Chrome в этой порции нет; fork gates
не являются новой browser acceptance или доказательством неотличимости.
