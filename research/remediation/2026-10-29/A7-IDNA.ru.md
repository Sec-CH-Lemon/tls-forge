# A7: IDNA исправлен, приёмка завершена

Runtime-исправление — `9c1d6d45ccf46c32e4c4eea20ee55fc044f51b4a`, ветка
`development`. Разрешение владельца: исправить найденный дефект отдельным
коммитом. Engine остаётся текущим **неопубликованным1.0.0**; schema4,
daemon3, SDK major1 и15 browser profile JSON не изменены. Push не выполнялся.

Этот отчёт дополняет [прежний A7 RED](ACCEPTANCE-A7.ru.md), сохраняя его
исходные результаты. Команды, хеши исходников и результаты — [checks-idna.json](checks-idna.json).

## Причина и исправление

После percent-decoding host содержал некорректные UTF-8 байты. IDNA-библиотека
могла вернуть для них punycode без ошибки, но затем отвергала собственный
результат. `http:%800` давал `http://xn--0-p10i/`; исходный более длинный input —
`HTTP:AAAAA0AAA%80000`.

[WHATWG host parsing](https://url.spec.whatwg.org/#concept-host-parser)
декодирует percent-encoded host как UTF-8; некорректные последовательности
становятся U+FFFD, который domain-to-ASCII отвергает. Теперь движок проверяет
UTF-8 сразу после percent-decoding и до IDNA. Это generic parser integrity,
которое нельзя выразить существующим JSON policy. Browser values/choices в код
не добавлены. Проверка касается host; userinfo/query не получают этого запрета.

В неизменённом before `163153df` новые tests воспроизводимо падают:12 invalid
host cases доходят до intercepted dial; malformed redirect приводит к20
запросам вместо отказа после первого ответа. В after invalid hosts дают0dial;
redirect — один исходный запрос и отказ до следующего dial. Оба протокола H1/H2
проверены. Компилируемый мутант, валидирующий исходный host до percent-decoding,
отклонён этими же тестами.

Original/minimized inputs и raw-byte control добавлены в настоящий Go fuzz
corpus. `FuzzCanonicalURL` побайтово не менялся: фильтра входов и исключений нет.
44-case fixture независимо согласован с Node24.16.0/Ada3.4.4 и двумя свежими
headless Chrome156.0.8078.74 launches. Добавлены invalid UTF-8 continuation,
truncation, overlong, surrogate, out-of-range sequences; положительные controls
сохраняют Cyrillic, Latin, sharp-s и допустимые BOM/zero-width mappings.
Исторический Chrome155 URL wire fixture не переписывался.

## Итоговые проверки

| Проверка | Результат |
|---|---|
| Целевые URL/WHATWG/H1/H2/redirect/corpus tests с `-race` | PASS, 48.595s |
| Полный fresh coverage | 100%; 11319blocks / 16361statements /0uncovered; 158.683s |
| Полный модульный `-race` | Остальные22пакета PASS; root RED по старому ACK-order assertion, 648.051s |
| Полный повтор root `-race` после test-only коррекции | PASS, 509.627s |
| lint / vet / generated-check / docs-check | PASS |
| Сборки go.work / GOWORK=off | обе PASS |
| Node / Python с реальным исправленным daemon | 11/11 каждый, включая IDNA-error contracts |
| Пять URL fuzz cohorts по30s | 5/5 PASS, 1804935executions |
| Итоговая матрица всех семи fuzz-целей по30s | 7/7 PASS, 3364607executions |
| Before replay / компилируемый raw-host mutant | оба ожидаемо RED |
| Независимые URL constructors | 44/44 в Node/Ada и каждом из двух Chrome cohorts |

Каждый fuzz запуск имеет два workers, минимизацию1s, Go timeout и внешний
конечный deadline. Corpus, execution counts, версии и оригинальные ошибки
сохранены. Прежние A7 controls target/authority/credential scope/preemptive auth
сохраняются; целевой race suite повторно выполнил их положительные wire tests.

Предыдущие8/8 known-debt fork gates относятся к тем же неизменённым fork commits
и тому же go.mod/go.sum. Они заново не запускались: runtime change находится
в root URL parser и не меняет транспортные форки/граф модулей. Это не означает
зелёные raw fork suites или закрытие109 исторических обязательств F09/A11.

## Дополнительная коррекция приёмки Cancellation

Первый полный race-прогон выявил отказ старого root immediate control:
инструкция в packet9, reset ACK в packet8, ACK delay256us. Гипотеза о пропуске
packet number не подтвердилась: ACK имеет один диапазон1..3. Диагностический
100-case replay воспроизвёл отказ. Режим as-written не требует совмещения с
ACK: type-only decoder prefix и собственная инструкция могут отправляться
отдельно. ACK delay/порядок не измеряют задержку самой инструкции.

Test-only follow-up измеряет monotonic интервал RESET-send → instruction-receive.
Граница15ms, decoded bytes03/40, обязательный ACK именно reset, opportunistic
bundling assertions и real delayed negative control сохранены. Это также
закрывает старую лазейку: инструкция перед поздним ACK более не считается
немедленной без проверки собственной задержки.130пар immediate/delayed под
race (100обычных и30с GOMAXPROCS1) прошли. Два дополнительных clock-instrumented
replay старого порядка не воспроизвели отказ; они сохранены как PASS, а не
выданы за отрицательные controls. Исходные полный RED и диагностический RED
остаются в evidence. Попутная коррекция не меняет runtime или транспортные форки.

Все остальные пакеты полного race-прогона прошли на том же production source;
после изменения исключительно root `_test.go` полностью повторён root package.
Это составная приёмка, не выдуманный единый зелёный повтор `./...`.

## Доказательства и ограничения

Private archive:
`../net-fp-server/captures/tls-forge-idna-20261029/`, mode0700, SHA256SUMS.
Сохранены before/after source archives, исходный новый corpus, полный before
failure, все after runs, negative mutant, два browser cohorts и SDK output.
Предыдущий private A7 archive остаётся неизменным.

A7 закрыт в согласованном объёме URL oracle/fuzzing с отдельно разрешённым
runtime-исправлением IDNA. Конечные fuzz-прогоны не доказывают отсутствия всех
дефектов. Chrome evidence здесь относится к URL constructor; новые общая wire,
auth и другие platform/browser-version equivalence не заявлены. Profile major1
не менялся; старые измерения/миграционные ограничения сохранены.

Malformed percent paths и backtick host на стадии HTTP request construction
остаются явными ограничениями. Fork pins локальны/не опубликованы; remote CI
этой работой не запускался. A0b, A8–A14 и F09stage2 остаются открытыми.
