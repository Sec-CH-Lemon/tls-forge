# A13: H2 all-ones sentinel

Локально принят отдельный компонент. Исходный2dd46064 отклонял12 каталожных
aliases до сети: setting6=4294967295 не проходил общий16MiB guard. Исходный
отказ сохранён; это не успешный before-wire замер этих12 entries.

В pinned fhttp24c1c55 `Transport.maxHeaderListSize` преобразует all-ones в0,
а `Framer.maxHeaderListSize` преобразует0 в16MiB. JSON validation теперь
принимает именно этот безопасный специальный случай. Остальные finite значения
выше16MiB, включая4294967294, по-прежнему отвергаются до I/O. Данные профилей,
форки и release identity этой порцией не меняются.

Проверены actual SETTINGS со значением4294967295, допустимый H2 response,
валидный HPACK block больше16MiB после декодирования и точный отказ header-list
limit. Targeted root/profile race PASS. Полный свежий profile gate100%.
В независимом git-archive fhttp увеличение Framer default до32MiB позволяет
принять oversized response, и исходная проверка падает: mutant killed.
Первая форма большого ответа также упиралась в независимый CONTINUATION guard;
её отказ сохранён. Итоговый compressed block проверяет именно decoded limit.

[Машинный отчёт](checks-a13-h2-sentinel.json). Private before/after, original
source, mutant и raw logs сохранены в A13 evidence. Полная материализация83
entries, F03 estimator и native A13 CI остаются открытыми.
