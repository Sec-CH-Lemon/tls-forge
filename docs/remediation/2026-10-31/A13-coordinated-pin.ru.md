# A13: согласованный standalone pin tls-client

Опубликован с разрешения владельца и закреплён tls-client `30e2710`.
Его собственный go.mod теперь выбирает QUIC `6f655a61`. Ранее standalone
граф выбирал `2484971b`: JSON SCID8 реально уходил как4. Это воспроизведено
через Client.Do и отдельный HTTP3 transport, с сохранением исходных packets.
Root уже выбирал6f напрямую; проблема касалась самостоятельного графа форка.

Постоянный regression читает исходный UDP Initial и проверяет1250/4 и1300/8.
После исправления прошли32 race-повтора и оба source-pinned графа по469
запусков. Новых allowances/exclusions, повторов запросов и изменений deadlines
нет. Изменены dependency metadata, regression и LEMON; runtime source тот же.

Публичный Origin hash и remote head подтверждены. В root прошли tidy, verify,
build, notices и lint0. Сравнение с полной каталожной приёмкой R14 показывает
ровно одну смену module identity — tls-client486→30e; остальные выбранные
версии и runtime source совпадают. Полная R14 normal/race сохраняется как
проверка своего frozen source; metadata follow-up не выдаётся за новый full run.

[Точные receipts](checks-a13-coordinated-pin.json) включают verified private
46-file манифест. Нового browser verdict эта порция не устанавливает.
