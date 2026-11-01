# A13 / F03: публичные inputs NQE

Продолжение [первой кампании](A13-network-observations.ru.md): ещё две когорты
по три fresh headed процесса Chrome156/macOS. Использован существующий
owner-approved `fp.tls-forge.com` с обычной проверкой публичного сертификата;
публичный сервис и host settings не менялись. Private collector на localhost
снимал реальные RTT/Downlink/ECT headers после каждого публичного этапа.

Для изоляции H2 добавлены `--disable-quic` и
`--disable-background-networking`. Эти технические условия отдельно отмечены
и не смешиваются с предыдущими default-flag наблюдениями. До каждого запуска
сохранены SHA бинарника/driver/Local State, фактический CDP browser build,
аргументы, исходные Network events, NetLog и TLS secrets в private capsule.

В каждом процессе выполнены три серии по шесть запросов к существующему
`/delay?ms=20`,500,20; после них — четыре одновременных `/bytes?n=1048576`.
Все108 delay responses имели200; все24 body-size controls вернули ровно1MiB.
Сохранены264 private header-probe requests и полный request sequence.
HTTP duration, transport RTT и throughput не объединены в один input.

Наблюдались header RTT0/50/100/150ms и Downlink1.45..2.90/10Mbps. Один процесс
опубликовал в NetLog throughput101307→134702→274954→361475kbps; его header
Downlink достиг cap10Mbps. Другие процессы имели иные переходы, включая
ранние2.50/2.65Mbps до следующих обновлений. Это сохраняется как временная
последовательность; один начальный literal не объявляется cold fallback.

Отдельный pinned source объясняет ограничение инструмента:
[Chromium156 EventCreator](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/net/nqe/event_creator.cc)
пишет metric-change event при абсолютной разнице от100 и отношении от1.2.
[NetworkQualityEstimatorManager](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.76/services/network/network_quality_estimator_manager.cc)
использует для latency publisher порог20ms и отношение1.2, для bandwidth —
100kbps и1.2; availability/ECT имеют отдельные переходы. Поэтому отсутствие
нового NetLog event не означает неизменный HTTP RTT, доступный заголовкам.
Полная sample-by-sample observer timeline этой кампанией не установлена.

F03 A–B продвинут: есть реальные публичные HTTP/throughput inputs и
воспроизведённые переходы. F03 C–E остаётся открытым: нужен bounded state,
обработчики actual inputs H1/H2/H3, JSON rules и их mutations, independent
instance/Fresh isolation и network reset. Отдельно остаются ECT threshold
transitions, H3, Linux/Windows и исторические151–155. Неполный observer не
подменяется генератором постоянных100/1.45/4g.

[Машинный отчёт и private receipt](checks-a13-network-public.json) содержит
per-process source/build/protocol/IP identities и raw evidence hashes.
Текущий deployment source публичного peer не закреплялся заново: сохранены
реальные responses, размеры, timing и protocol; это ограничивает переносимость
эксперимента. Root production hints этой измерительной порцией не менялись.
