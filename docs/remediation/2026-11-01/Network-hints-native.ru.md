# Нативная CI-приёмка network hints

**Согласованная ограниченная порция принята на опубликованном `8a616035`.**
[Main CI41304948535](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41304948535)
завершён:28/28 jobs SUCCESS; [fork CI41304949820](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41304949820)
—8/8,11366 тестовых запусков. Полный macOS Go job принят одним повтором на
том же source; первичный ACK timing отказ и неизвестная причина сохранены.
[Точные machine-readable результаты](checks-network-hints-native.json).

Это software CI-приёмка Linux/Windows/macOS. Новых browser-замеров здесь нет;
[конечная Chrome156/macOS сверка R24](Network-hints-final.ru.md) остаётся
отдельной конечной выборкой. Первоначальную широкую программу A13 не расширяем.
Engine остаётся единственным UNRELEASED1.0.0/schema4/daemon3, anchor0.2.2.

## Before и исправления

[Первый CI41300980769](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41300980769)
на ef1f9a62 завершился19/28: Darwin-only regression компилировался на других ОС;
standalone Go-example имел старый dependency lock; notices зависели от host OS.
Исходные полный лог, source archive и job metadata сохранены.

[Первые8 fork gates](https://github.com/Sec-CH-Lemon/tls-forge/actions/runs/41301185203)
на том же source дали7/8: tls-client production test ожидал H3 сразу после
серверного handshake. Он не доказывает публикацию соединения в клиентском пуле.
Детерминированный real-dial control удержал фактический dial после handshake и
воспроизвёл H2 до публикации. Исправление ждёт client HasConn в исходном общем
readiness budget4s; protocol/count assertions сохранены. Новый контроль требует
H2 до публикации, H3 после, ровно одно TCP и одно QUIC соединение.

| Подтверждённая причина | Изменение и проверка |
| --- | --- |
| Darwin CF/AirPort test binding |Тот же тест перенесён в `network_environment_airport_darwin_test.go`, bytes/assertions идентичны; native Go трёх ОС принят. |
| Go consumer lock |Root и standalone example закрепляют публичные зависимости; examples всех трёх ОС приняты с `GOWORK=off`. |
| Host-dependent notices |Union фактических linked module graphs из существующих пяти release TARGETS; ошибка любого graph фатальна. Три host selections дают одинаковый файл; negative control отвергнут. |
| Native Linux metadata boundaries |Route/TCP_INFO I/O передаётся параметрами, исходные OS calls и JSON choices сохранены; формат/ошибки/units и настоящий owned TCP socket проверены. Linux-selected lint и100% native coverage приняты. |
| Linux declaration lint |Тип metric выводится из прежнего `^uint64(0)`; значение и выбор маршрута прежние. |
| Alt-Svc readiness fixture |Опубликован test-only tls-client4d345b0; оба локальных и оба CI graphs по476,32 fixed race-повтора приняты. Runtime-файлы форка не менялись. |

## Коммиты и публикация

В existing `origin/development` опубликованы исходный диапазон024e5c91..ef1f9a62,
затем с отдельным разрешением владельца ровно шесть коммитов:

| Commit | Атомарное изменение |
| --- | --- |
| `edd7bd94` | Scope AirPort regression to Darwin |
| `1825ce01` | Refresh standalone Go example dependencies |
| `1b8fe31f` | Generate notices across existing release targets |
| `2903d046` | Cover native Linux network metadata boundaries |
| `988225a7` | Simplify Linux route metric declaration |
| `8a616035` | Pin client-side Alt-Svc readiness witness |

В `origin/tls-forge` tls-client отдельно разрешён и опубликован
`4d345b04deee9f2888e03975f1f60ec89df967c6` — Wait for client Alt-Svc publication in tests.
Root и example закрепляют `v1.15.2-0.20261101114743-4d345b04deee`.
Source archive root8a616035: SHA256
`9bcc3f469561f637332f4031fe26db012df8a62f72d13d69f302f7fa7ca6c657`.

В этой follow-up порции не менялись profiles/networkquality/engine identity.
Два runtime diff-файла root — Linux parameter seams; macOS runtime R24 прежний.
Никаких новых allowances/exclusions, понижений coverage, изменённых assertions,
таймеров или deadlines. Состояния до исправлений остаются отдельными свидетельствами.

## Итоговые проверки

| Gate | Результат |
| --- | --- |
| Main CI |28/28 jobs SUCCESS; macOS Go attempt2, остальные27 attempt1. |
| Linux `-race` |Root1+остальные23=все24 пакета ровно один раз, cache0. Root961.191s, CLI1004.855s; test timeout20m сохранён. |
| Linux coverage |Все24 пакета по100.0%; native Linux routes/TCP_INFO входят в gate. |
| macOS Go |Полный build/vet/test `./...`;24 пакета PASS, cache0; root325.988s. |
| Windows Go |Полный build/vet/test `./...`;23 пакета PASS; internal/proctree штатно сообщает no test files на Windows. |
| SDK/consumer/distribution |Node/Python compatibility и coverage jobs, examples трёх ОС, wrapper-smoke, packaging и все5 package-smoke приняты. |
| Остальные gates |lint/generated/security/Docker приняты. |
| Fork graphs на macOS/xcode-27 |uTLS696×2,fhttp1905×2,QUIC2606×2,tls-client476×2=11366;8/8 accepted, unexpected0, source SHA совпадают. |

Существующие fork skips на каждый граф: uTLS1,fhttp36,QUIC3,tls-client6.
Они перечислены в JSON и raw; verdict не означает выполнение пропущенных cases.

Информационный browser job CI сохраняет2 различия в H1/H2 header-value vectors:
headless Chromium UA/brand против headed branded Chrome persona профиля.
Он не строгий browser gate и не заменяет отдельную реальную Chrome156 R24-приёмку.

## Сохранённый ACK timing отказ

Первая попытка нового main CI дала27 SUCCESS и один macOS Go failure:
`TestHowLateALonePacketIsAcknowledgedIsTheProfilesToSay`, case none said:
все три наблюдения ACK Delay оказались не меньше28ms. Порог и тест прежние.
Изменений macOS runtime или ACK JSON между ef1f9a62 и8a616035 нет.

Оба исходных ACK controls прошли локально по10 повторов на точном8a616035;
затем один полный неизменённый macOS job прошёл24/24. **Причина исходного
отказа не установлена; устранение причины и гарантированная стабильность не
заявляются.** Исходный RED не заменён успешным логом и может повториться.

## Доказательства и границы

Immutable ignored capsule `/Users/ihar/Personal/net-fp-server/captures/tls-forge-a13-20261031/NATIVE-CI-R25`:
223 файла,150279899 байт,
manifest SHA256 `d780a408689dccb728f62d6bbe21a37fcc7f4653017508faeb99643daaca7410`.
Каждый hash, ignored status и permissions0700/0600 проверены. BEFORE manifest
`c1c7b4d481fde31da1f4f7f350d06493053d544de1998862252a0ca6d8d58991` не менялся.
Сохранены исходные sources, полный main attempt1, успешный macOS job attempt2,
полные encrypted/decrypted8 fork graphs, source hashes, negative controls и
все локальные ACK repeats. Секреты и raw не опубликованы. R24 capsule сохранён.

Утверждённая ограниченная порция завершена. Сохраняются границы R24: finite
Chrome156/macOS witness, без новой исторической/других ОС browser-приёмки,
физической смены сети/passive notifier, полной process-wide NQE или доказательства
равенства RNG/распределений. Полные fork suites здесь выполнялись на macOS;
software native root/SDK/package CI — на трёх ОС.100% statement coverage относится
к Linux gate, не к каждой ОС. Выбранные владельцем close_notify/ACK особенности
и integral Downlink wire form остаются явно документированными отклонениями.
