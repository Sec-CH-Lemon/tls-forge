# A8/C02: shared JSON Linux/Windows

> Промежуточный отчёт этапа; итоговая приёмка и ограничения: [A8](A8.ru.md).

Ровно30 ключей из исходного profiles-behavior-divergence перенесены из
chrome_155_macos в155 Linux иWindows. Источник сохранён как inherited в
profile/provenance/chrome_155; provenance связывает точные байты SHA256,
прежний SHA256, основу и30 имён. Не перенесены OS-specific QUIC alarm slack,
TCP keepalive и negotiate-auth. Политики не помечены новым замером155.

Исходный wire-контроль на Git archive43b460e7: Linux/Windows отправляют
SETTINGS1=0/7=0; оба отрицательных контроля сохранены. После JSON переноса
тот же публичный Client.Do, нейтральное имя/UA, настоящий H3 peer:65536/100.
Три race-прогона проходят. Profile suite100% statements; отдельно проверены
хеши происхождения и сохранение OS choices. Ошибочно названный текущий
прогон сохранён отдельно и не засчитан как before.

151–154 сохранены как исторические, с отдельным profile/provenance/historical.json;
их текущие байты и происхождение изменений указаны без нового browser verdict.

Это завершение переноса данных и продуктового SETTINGS-контроля. Нативные
Chrome156 Linux/Windows, фактическая динамическая QPACK-последовательность и
общая A8 ещё не приняты. Новый156 должен получить эти shared значения
через тот же builder; одного переноса JSON для этого verdict недостаточно.

Оригиналы приватны в captures/tls-forge-a8-20261029 соседнего net-fp-server.
Хеши: [checks-a8-platforms.json](checks-a8-platforms.json).
