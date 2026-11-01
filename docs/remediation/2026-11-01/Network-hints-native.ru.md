# Нативная CI-приёмка network hints

Владелец разрешил push до ef1f9a62 и CI Linux/Windows/macOS.
Диапазон024e5c91..ef1f9a62 опубликован без force-push.

Исходный [CI41300980769](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41300980769)
сохранён как отказ. Причины: Darwin-only regression компилировался на других
ОС; standalone Go-example имел старый dependency lock; notices зависели от ОС.
Mac Go, SDK, packaging и package-smoke прошли.

[Все8 source-pinned fork gates](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41301185203)
сохранены с encrypted raw:7/8, один Alt-Svc readiness test в tls-client production
отказал. Проверка peer handshake не равна публикации клиентского пула.
Детерминированный real-dial control воспроизвёл этот разрыв; runtime форка
не меняется, protocol/count assertions и исходный readiness budget сохраняются.

## Подготовленные исправления

- Идентичный AirPort regression перенесён в
  `network_environment_airport_darwin_test.go`; имя теста и все assertions прежние.
- Go consumer module обновляет опубликованные fork pins; go.work не нужен.
- Notices собирают union реально используемых зависимостей существующего release
  TARGETS; одна inventory для всех поддержанных ОС. Ошибка target graph фатальна.
- Native Linux route/TCP_INFO error paths проверяются отдельно; I/O передаётся
  параметрами, без глобальных подмен или изменения значений политики.

Cross-vet и test-binary compilation Linux/Windows, Darwin regression под race,
полный examples gate и независимость notices от host selection проверены локально.
**Итоговый native CI ещё не принят:** подготовленным commits нужен отдельный
push и завершённый CI. Никаких понижений coverage, таймаутов, skips или allowances.

Новая приёмка не расширяет [исходный ограниченный объём](Network-hints-final.ru.md).
Raw source, первичный CI и controls пока сохранены приватно в
`/private/tmp/tls-forge-a13-native-20261101`; итоговый immutable capsule добавляется
после завершения native-приёмки.
