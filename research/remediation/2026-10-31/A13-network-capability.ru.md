# A13: явное объявление network hints

Локальный uTLS `2f8200b` добавляет в строгий registry единственный selector
`headers.network_hints`: `none`, `literal`, `weighted-observations`.
Движок проекта отдельно проверяет соответствие selector и типизированной
конфигурации. Выбор не выводится из имени, UA или browser version.

Оба полных source-pinned gate приняты по 696 запусков, returncodes `[0]`,
unexpected0, без новых allowances/exclusions. Тестовая сеть ограничена
loopback. Production-граф здесь закреплён на опубликованных зависимостях
root6130203c до подключения новых observer forks; конечный граф интеграции
потребует отдельной проверки. Это known-debt regression gate с прежним
учётом обязательств, а не новый browser verdict.

Before bfb5cb3, after2f8200b, исходники, логи и module graphs сохранены
в отдельном R21. Оба frozen legacy JSON побайтно неизменны. Новых browser
measurements этот компонент не устанавливает. Коммит пока не опубликован;
root продолжает закреплять прежнюю версию uTLS.

[Проверки и manifest](checks-a13-network-capability.json). Полная A13,
production profile activation, native CI и историческая приёмка открыты.
