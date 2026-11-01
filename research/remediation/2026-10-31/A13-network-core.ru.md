# A13: bounded state оценщика

В `networkquality` добавлен общий concurrency-safe state: отдельные histories,
RTT corrections, ECT mapping, publication, in-memory network cache, aggregate
receive-counter windows, reset и browser-instance salt. Значения, фильтры,
CIDR-векторы, лимиты, таймеры, thresholds, quantization и доступные правила
задаются полной `Policy`; скрытых Chrome defaults и browser-name dispatch нет.
`Context` содержит только type/identity/generation/optional signal. Ноль и
отсутствие signal различаются; строгий decoder отвергает неоднозначный JSON,
частичные transitions и lossy Unicode. Все mutable vectors и pointers копируются.
Тестовая source-derived policy не является исполняемым browser profile.

В source review и regression controls сохранены два before: общий лимит
ошибочно смешивал eligible и degrading sets; delayed HTTP observation терял
исходный timestamp. Исправлены независимые bounds и original headers-end/activity
время. Один тест задавал ответ в будущем относительно fake clock: исправлена
последовательность часов, quantization/ECT/frozen-generator assertions сохранены.

Полный package race PASS, meaningful statement coverage100% (735 statements),
строгий lint0. Независимый C++ replay прежних128 buffer и188 hash случаев прошёл;
их исходники побайтно сохранены. Context decoder fuzzing —4865028 входов,
event-sequence state fuzzing —649515 последовательностей, по31 секунде без
отказов. Проверяются bounds, reset, hanging/completion, timestamps и hints.
Finite fuzzing не является доказательством отсутствия всех дефектов.

[Точный отчёт и приватный manifest](checks-a13-network-core.json) содержат
before/after source, первоначальные отказы и принятые прогоны. Это приёмка
самостоятельного state-компонента: production integration, JSON migration,
SDK/native и историческая браузерная матрица этим коммитом не закрываются.
В root `Client.Do` новый генератор пока не активирован; A13 остаётся открытым.
