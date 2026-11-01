# A13: каталожный кандидат и незакрытые критерии

Статус: **не принят как завершение A13**. Материализация83 aliases подготовлена
в отдельном экспорте. В root зафиксирован опубликованный TLS foundation,
H2 sentinel и отдельное исправление тестового QUIC oracle. Новый каталожный
runtime ещё не перенесён в development: три его зависимости пока локальные.
F02/C, production estimator F03 C–E и native A13 остаются открытыми.

Root go.mod содержит опубликованные pins. Существующий локальный go.work
подключает live fork checkouts; поэтому утверждения об опубликованном графе
относятся к GOWORK=off, а не к произвольному локальному запуску с go.work.

[Машинный отчёт](checks-a13-catalogue-candidate.json) содержит точные commits,
graphs, hashes, результаты gates и приватный capsule. Прежние checkpoint,
исходные отказы и source archives сохранены отдельно.

## Подготовленные данные и механизм

В кандидате profile/catalogue.json содержит83 отдельных полных Profile objects
со schema4 и engine_major1, вместо alias→legacy-template. TLS vectors,
параметры extensions, generation/session sources, H2 vectors/order/flow,
эффективные H3 SETTINGS/order/pseudo headers и существующие HTTP/lifecycle
policies экспортированы в явные данные. Provenance — export/import Go presets,
не browser capture. Заголовки и User-Agent остаются пустыми: эти entries всё
ещё требуют явного согласия на исполнение handshake-only каталога.

Production fallback через MappedTLSClients и UTLSIdToSpec удалён из кандидата.
Старый Base API становится data-backed facade. Проверки entry name,
отсутствия base indirection и exact engine major выполняются до построения
транспорта. Save/Load/Clone сохраняют данные и изолируют mutable values.
Catalogue provenance при Clone сохраняется; Save/Load не выдают произвольный
файл за встроенную запись. Name и UA не выбирают алгоритм TLS.

Перенос учитывает старые эффективные defaults: nil H2 priority становится
явным значением, stream0 — явным stream1. Для прежнего H3 nil map значения
6/51 материализованы с порядком6,51. Раньше порядок Go map не был объявлен;
его новая фиксация — явное изменение, не скрытая нормализация сравнения.
Extension order выбирается самим TLS descriptor; общий transport shuffle
больше не перекрывает явно выбранный fixed/moving/utls.

Но эти83 записи **ещё не означают полноту JSON-first**. У50 entries
quic.enabled=false выбирает native QUIC. В этом пути QUICConfig по-прежнему
собирается из engine defaults. Это оставшаяся работа, а не допустимое
исключение из контракта владельца.

## Исправления в локальных форках

| Форк | Атомарные commits | Назначение |
| --- | --- | --- |
| uTLS | 6599476b,8bfa7fee | Строгие capability guards для существующих H3 settings; JSON template причины ошибки draft setting |
| QUIC | 75fe9e7a,0c35ebb0 | Реальная согласованная RFC/draft datagram версия; authenticated errors с JSON-подстановками id/value |
| tls-client | d22be148 | Сохранение отличия nil SETTINGS от явно пустого map в обычном Alt-Svc пути |

Setting8 допускает только boolean; historical WebTransport setting допускает
только0, потому что включающая capability отсутствует. Для объявленного
draft datagram setting требуется h3.datagram_setting_error_reason. Пустая
строка — явный допустимый template. Необъявленный draft parameter сохраняет
семантику unknown setting. Новых script/bypass/default-Chrome переключателей нет.

Исходные encrypted-wire отказы сохранены: hardcoded reason вместо JSON и
потеря пустого SETTINGS с подстановкой H1 header limit. After-проверки проходят
через production Client.Do, включая обычный hostname/Alt-Svc и racing.
Первые IP/DNS fixtures, не достигавшие выбранного пути, сохранены как
диагностические отказы и не засчитаны доказательствами дефекта.

## Проверки и их границы

- 83/83 descriptor comparisons, Save/Load/Clone, strict malformed data и
  отсутствие production Go-preset lookup.
- H1/default-ALPN:83×2×3=498 запросов на actor. H3:83×3=249 after requests.
  Сохранены исходные bytes, поля, порядок и connection/stream/resumption state.
- Старый H3 actor имел68 успешных aliases и15 placeholder-factory отказов.
  Все15 остаются в denominator; для них проверен успешный after, а успешного
  парного before не заявляется. Старые12 H2 sentinel отказов сохранены отдельно
  от baseline после исправления175129e4.
- JSON-only controls меняют actual H3 values/order/pseudo headers/GREASE и
  error text.336 отрицательных entry/route cases проверяют отказ до DNS,
  сокетов, прокси, QUIC и transport constructor; положительные witnesses сохранены.
- R09 normal:23/23 пакета,17082 покрытых statements,0 непокрытых; lint0.
  Fuzzing после нового декодера:198541 executions, без найденного дефекта.
- Оба полных source-pinned fork graphs: uTLS648, QUIC2589, tls-client463
  запусков на graph, returncodes0. Прежние host/capability skips сохранены,
  новых failure allowances или invocation exclusions нет. Production graph
  каждого fork использует опубликованные остальные pins; окончательный
  совместный опубликованный graph ещё требуется.

Приватный catalogue capsule содержит5108 файлов; manifest и каждый SHA256
проверены, каталог ignored, права0700/0600. Отдельные immutable capsules
сохраняют idle oracle и NQE observer primary sources. Секреты и raw packets
не добавлены в root git.

R06 parser diagnostic failure и R08 ошибочное требование только us не скрыты.
Первое исправлено порядком строгой валидации, второе — отдельным test-only
[ee94b42](A13-idle-oracle.ru.md), с независимым первичным источником и мутантами.

## Два сохранившихся отказа приёмки

**Native QUIC JSON-first.** На actual Client.Do с firefox_148 два сохранённых
JSON файла выбирают quic.initial_packet_bytes1250 и1300. Оба проходят Load,
а первый UDP datagram в обоих случаях равен1280. Исходные datagrams и JSON
сохранены.50 aliases найдены по source-selected ветке; wire контрпример
выполнен для одного alias с двумя choices. Подменять им все50 wire-замеров
или отключать H3 у этих aliases нельзя.

**H3 под race.** Полный R09 race сохраняет таймаут
TestA13CatalogueHTTP3Production/okhttp4_android_10. Normal gate прошёл,
но полный race этим не становится зелёным. В отдельном диагностическом
экспорте830 сценариев прошли с server qlog и явным закрытием принадлежащих
fixture соединений после сценария. Во всех830 cleanup snapshots оставалось
по одному активному соединению до этого закрытия. Это свидетельство границы
lifetime fixture, а не установленная причина исходного таймаута. Изменённая
диагностика не заменяет исходный gate и не закрывает отказ удачным повтором.

## Продолжение

1. Устранить native data-ownership gap без переключения этих50 aliases на
   придуманный Chrome профиль; сохранить исходный JSON/wire RED и провести
   отдельную приёмку generic mechanism и явных данных.
2. Довести H3 fixture lifetime и причину race-таймаута до воспроизводимой
   проверки; сохранить все текущие assertions/deadlines и повторить полный gate.
3. Получить отдельное разрешение публикации точных локальных fork ranges,
   закрепить опубликованные versions без replace, выполнить tidy/verify/notices,
   field-reference/README/CHANGELOG/AGENTS contracts и coupled production graphs.
   Только затем фиксировать каталожный runtime в root атомарной порцией.
4. F03: controlled ECT transitions/network reset и точные production inputs,
   затем реальный bounded estimator и JSON rules. Сейчас есть12 Chrome156/macOS
   процессов и source-bound observer contract; estimator не реализован.
5. Отдельная публикация root и разрешённый native CI. Historical browser builds
   и прочие platforms остаются неизмеренными; новые engine primitives остаются
   в той же непубликованной1.0.0, не создают engine2.

Численный P3 timebox не утверждён. Никакие незавершённые критерии этим отчётом
не снимаются. A14, общее качество всех путей и неотличимость от браузера
не объявляются принятыми.
