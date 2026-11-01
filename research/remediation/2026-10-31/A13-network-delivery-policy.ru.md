# A13: identity и доставка наблюдений как данные

Самостоятельный `networkquality.Policy` теперь выражает `connection-type`
в дополнение к `route-interface-addresses`, а также доставку start/header
наблюдений в `headers` или `next-step`; немедленный `request` start сохранён.
Выборы независимы, неизвестные значения отвергаются. Числа, таймеры и выборы
остаются в JSON. Выполнение этих callbacks в root — отдельная интеграция.

Основание: pinned Chrome156 `GetCurrentNetworkID` возвращает тип соединения,
пустой ID и неизвестный signal. Поэтому нельзя приписывать ему измеренную SSID
или route identity. В pinned source Chrome152 async/deferred headers включены
по умолчанию; остальные исследованные snapshots имеют иной default. Source
не доказывает effective field trials установленного browser binary.

Before R20 отвергал ту же source-derived policy с `unsupported network identity
rule`; after принят. Полный package race прошёл, 737/737 statements,
lint0; положительные controls проверяют12 независимых сочетаний choices.
Новые allowances/exclusions не вводились. Портированные C++ primitives не менялись.

[Точный отчёт и отдельный R22 manifest](checks-a13-network-delivery-policy.json)
сохраняет before/after source, логи и первичные pinned sources. R20 и его прежний
результат735 statements не переписаны. Root `Client.Do`, shipped profiles,
пассивные OS notifications, physical reset и полная A13 этим коммитом не приняты.
