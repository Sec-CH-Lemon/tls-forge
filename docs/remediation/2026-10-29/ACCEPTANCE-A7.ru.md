# QUIC: 8/8; A7: корректный oracle и новый runtime-контрпример

Срез реализации: `228c7240`, ветка `development`. Форк QUIC:
`1fda75c1ad73`, ветка `tls-forge`. Публикации/push не было.

**QUIC-порция принята: 8/8 регрессионных гейтов. A7 реализован как
тестовая инфраструктура, но URL fuzzing остаётся красным на новом дефекте
IDNA. Полностью зелёную приёмку A7 не объявляем.** Исходный F05 с ложным
требованием Go parser исправлен. Новый runtime-дефект сохранён отдельно;
A7 по утверждённому плану не меняет движок и не сужает входы ради теста.

Предыдущий [отчёт 7/8](README.ru.md) остаётся историческим свидетельством.
Полные команды, времена, исходники и результаты — [checks-a7.json](checks-a7.json).

## Что исправлено в QUIC-проверках

Cancellation/ACK: тест путал байт типа QPACK decoder stream `03` с
инструкцией Stream Cancellation `40` для request stream0. Раздельная отправка
этих байтов законна. До исправления принудительно отделённый prefix
воспроизводимо даёт прежний отказ ACK=nil. Теперь тест читает оба байта,
находит пакет с байтом инструкции на offset1 и ACK именно серверного RESET.
Порядок проверяется по отправленным пакетам клиента, независимо от порядка
доставки на loopback. Opportunistic должен совместить инструкцию с delayed
ACK; immediate должен отправить её до ACK либо с немедленным ACK. Реальный
delayed control обязан не пройти immediate-правило. Проверки не заменены
наличием любого пакета decoder stream.

MITM: прежний секундный deadline не вмещал восстановление после пяти
последовательно повреждённых серверных Initial. Это воспроизведено на старом
бюджете. Новый test-only бюджет — два `DefaultHandshakeIdleTimeout`;
серия тех же пяти повреждений завершается с полной проверкой echo payload.
Оба направления случайной порчи имеют локальный PCG seed и журнал фактических
повреждений; XOR всегда меняет байт. Конечный deadline действует и на stream
I/O. Production retry/PTO/таймеры и browser JSON не менялись.

Промежуточный полный прогон выявил пропущенную при переносе вспомогательную
функцию теста. Исходный compile failure сохранён; функция восстановлена
отдельным коммитом, полный HTTP/3 `-race` и оба QUIC-гейта затем прошли.

fhttp: один timestamp Go Framer имел нулевую дробную часть и был записан без
точки. Поэтому прежний matcher ошибочно счёл его новой диагностикой.
Поддержаны оба фактических формата времени; malformed timestamp остаётся
отрицательным контролем. Значения всех кадров, основные diagnostics и их
повторы по-прежнему сравниваются точно. Старые failure fingerprints и список
109 обязательств не расширялись. Полный исходный транскрипт повторно оценён
новым matcher; новый запуск тестов для изменения парсера лога не подменяется.

## Приёмка

| Проверка | Результат |
|---|---|
| uTLS standalone / production | 2/2 приняты |
| fhttp standalone / production | 2/2 приняты |
| tls-client standalone / production | 2/2 приняты |
| QUIC standalone / production | 2/2 приняты, self integration выполнен |
| Всего записей run, включая subtests | 10844 |
| Полный root `-race -p2 -count=1 ./...` до добавления A7 tests | PASS, 637.181s |
| A7 целевые H1/H2/credentials/corpus под `-race` | PASS, 26.331s |
| Полный fresh `make cover` после A7 tests | PASS, 100%, 152.997s |
| lint / vet / generated-check | PASS |
| `make build` с обычным go.work и с GOWORK=off | оба PASS |
| Fork gate unit/negative controls | 14/14 |
| Компилируемые A7 мутанты target / authority / origin / preemptive auth | 4/4 отклонены |
| Node24.16.0 / Ada3.4.4 / два свежих Chrome156.0.8078.74 | 26/26 в каждом constructor cohort |
| FuzzDecodeJobs, FuzzRenderReport, FuzzSplitInline, FuzzHandle, FuzzParseClientHello, FuzzLoad | 6/6 PASS, 3022522 executions |
| FuzzCanonicalURL | RED: новый IDNA-дефект; исходные F05 seeds проходят |
| Workflow action pins / actionlint | PASS; удалённого CI запуска не было |

Каждая из шести прошедших fuzz-целей получила30s, два workers и
`-fuzzminimizetime=1s`. URL-цель обнаружила дефект после14080 executions;
независимый запуск — после35779; replay сохранённого seed завершается красным
сразу. Самая ранняя версия runner неверно передавала package после внутреннего
Go test флага; шесть пустых прогонов отвергнуты проверкой executions>0, затем
runner исправлен и все цели действительно выполнены. Эти промежуточные
результаты сохранены, зелёными не посчитаны.

Другие production-гейты выполнены на root snapshot `24c8f9ba`, с QUIC pin
`517b1f3e`. До итогового `1fda75c1` в этом форке изменён исключительно
`http3/bundle_test.go`: non-test source и requirements побайтово одинаковы.
Итоговый QUIC проверен повторно на обоих графах; соответствующая граница
воспроизводимости записана в JSON. Другие форки не менялись.

8/8 означает отсутствие новых необъяснённых отказов относительно зафиксированного
долга. Сами raw fork suites остаются с известными отказами: F09 stage2/A11
не закрыт. Это также не заключение о полной RFC/Chrome эквивалентности.

## A7 и оставшийся URL-дефект

[Метод URL проверки](../../url-oracle.md) разделяет четыре обязательства:
идемпотентность; независимые WHATWG компоненты; реальные H1/H2 request-target
и authority; credentials и challenge/origin scope. Node не нужен обычному Go
suite. Независимый fixture не обновляется автоматически. Оба исходных входа
F05 включены в `testdata/fuzz/FuzzCanonicalURL/`.

Единственная объявленная component-нормализация — base credentials в relative
redirect: WHATWG constructor сохраняет их в href, движок ведёт их в chain/session
состоянии отдельно от request URL. Оригиналы и байты credentials сохранены;
новое явное userinfo не нормализуется. Реальные H1/H2 controls проверяют отсутствие
Authorization до challenge и на другом origin даже после его одноимённого realm.

Текущие ограничения представления остаются явными и проверяются до dial:
malformed percent в path, запрещённый port и backtick host на стадии создания
HTTP request. Для последнего CanonicalURL уже успешен. Это не объявлено ошибкой
WHATWG input и не замаскировано новым runtime rejection.

**Новый незакрытый дефект:** `http:%800` принимается CanonicalURL как
`http://xn--0-p10i/`, но второй CanonicalURL его отклоняет. Исходный более длинный
контрпример — `HTTP:AAAAA0AAA%80000`. Node/Ada и два независимых Chrome constructor
cohorts оба входа отвергают. Это нарушение runtime-идемпотентности, а не прежняя
ошибка тестового oracle. Отрицательный вход не исключён из fuzz property.
Minimized corpus и raw падения сохранены в private evidence; исправление движка
вынесено за tests-only A7 и требует отдельного решения владельца.

Workflow `fuzz.yml` автоматически находит все семь целей, запускает их еженедельно
на default branch либо вручную и отдельно сверяет fixture с настоящим Chrome.
Он не публикует raw corpus/logs. Сейчас URL job должен честно ловить описанный
дефект; его зелёное завершение не обещано.

## Коммиты этой порции

Основной проект:

- `440b36e9` — distinguish decoder type from cancellation.
- `24c8f9ba` — QUIC recovery/cancellation test pins.
- `3bb85703` — complete QUIC cancellation pin.
- `36fb321c` — zero-fraction Go trace timestamps.
- `b62aa555` — independent WHATWG and production request URL oracles.
- `228c7240` — scheduled bounded fuzzing of every discovered target.

QUIC fork:

- `91c439e7` — actual cancellation bytes and sender packets.
- `517b1f3e` — corrupt packet recovery budget across PTOs.
- `1fda75c1` — restore the omitted test predicate.

## Доказательства и границы

Private evidence:
`../net-fp-server/captures/tls-forge-accept-a7-20261029/`, mode0700,
с SHA256SUMS: before/after source archives, первоначальные отказы, полный raw
output всех гейтов, PCG faults, sender/receiver qlog assertions, corpus,
constructor cohorts, мутанты и результаты проверок. Предыдущий private archive
`tls-forge-fixes-20261029` сохраняет исходные два нестабильных отказа.

Production Go source, browser JSON, engine1.0.0/schema4/daemon3 и SDK major1
этой порцией не изменены. Новая browser навигация/auth/wire эквивалентность
не измерена; constructor fixture не переносит исторический вердикт Chrome155
на156 или на другую ОС. QUIC и tls-client pins локальны и ещё не опубликованы.
A0b, A8–A14, F09 stage2 и итоговая browser/platform кампания остаются открытыми.
Shared KB получает новые наблюдения, не переписывая прежние результаты.
