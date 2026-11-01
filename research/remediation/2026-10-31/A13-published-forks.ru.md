# A13: опубликованные H3-зависимости

Принят отдельный dependency-компонент. A13 остаётся открытым. По прямому
решению владельца от31.10.2026 исследование продолжается **без таймбокса**
до реализации и приёмки всех заявленных возможностей. Прежние сообщения
о неуказанном P3 timebox остаются историей, а не текущим ограничением.

В существующие origin/tls-forge отправлены ровно разрешённые диапазоны:

| Репозиторий | Before | Опубликованный head |
| --- | --- | --- |
| uTLS | 785f3ba | 8bfa7fe, включая6599476 |
| QUIC | 5c4149bd | 0c35ebb0, включая75fe9e7a |
| tls-client | 7b5e8ee | d22be148 |

Без force, новых веток и публикации root. Удалённый ref каждого форка
независимо проверен после push; before/after receipts сохранены.

Root закреплён на фактически опубликованных pseudo-versions:

- uTLS v1.7.8-barnius.0.20261031104910-8bfa7feee58e;
- QUIC v1.0.10-utls.0.20261031104912-0c35ebb0af98;
- tls-client v1.15.2-0.20261031111436-d22be148271f.

Все проверки выполнены в чистом git-archive экспорте с GOWORK=off,
без replace и постороннего untracked tmp/. Пройдены tidy, module verify,
CLI build, генерация notices, lint0,23/23 normal packages с100% statement
coverage и23/23 race packages. Таймаут20m сохранён. Совместные production
fork graphs приняты: uTLS648, QUIC2589, tls-client463 запусков, returncodes0,
без новых failure allowances и invocation exclusions; capability skips
записаны. Standalone receipts этих же commits сохранены в прежнем capsule.

Это приёмка текущего root runtime с опубликованными зависимостями. Полный
83-entry каталожный runtime пока отдельный кандидат; его прежний H3 race
отказ не заменён этим gate. Native QUIC data ownership и F03 estimator
не объявляются реализованными. Новых browser samples или native CI нет.

[Машинный отчёт](checks-a13-published-forks.json) содержит source/module
hashes, все package results, skips и manifest нового immutable приватного
capsule PUBLISHED-H3-FORKS. Существующий go.work может подключать последующие
локальные изменения; его дерево не является проверенным published graph.

Следующие порции: H3 fixture lifetime, полная native-QUIC JSON-модель и
продуктовый network estimator с приёмкой всех заявленных комбинаций. Root
и новые последующие fork commits не публикуются без отдельного разрешения.
