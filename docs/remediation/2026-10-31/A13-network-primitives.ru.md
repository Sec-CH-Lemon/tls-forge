# A13: примитивы сетевого оценщика

Локально приняты ограниченный weighted observation buffer и явный libc++
host hash. Это самостоятельные механизмы будущего F03: production генерация
сетевых hints пока не подключена.

Буфер сохраняет timestamps, source и signal strength; различает0 и отсутствие,
вытесняет старейшее observation, использует целые секунды возраста и заданные
JSON-параметры capacity, half-life и signal weighting. Параметров Chrome в Go
constants нет. Синхронизация принадлежит будущему enclosing estimator.

Hash реализует оба little-endian64 libc++ варианта4–8-byte input; вариант
выбирается явно. Константы хеш-алгоритма относятся к механизму. Образец salt
не воспроизводится, выбор browser ABI эта порция не утверждает.

Проверены128 случаев независимого source-bound C++ weighted oracle и188
C++ hash vectors. Все inputs и C++ harnesses сохранены в testdata; replay
`python3 networkquality/testdata/verify_oracles.py` проверяет их независимо от Go.
Race и meaningful statement coverage100%, строгий lint0. Тесты включают
вытеснение, reset/source removal, нулевое observation и однобитное расхождение
порядка накопления floating-point weights на100th percentile.

[Машинный отчёт](checks-a13-network-primitives.json) содержит source hashes и
неизменную приватную капсулу. Лицензия LLVM приложена и включена в generator
THIRD-PARTY-NOTICES. Приёмка полного estimator, transport observer, жизненного
цикла и браузерной матрицы этим компонентом не устанавливается.
