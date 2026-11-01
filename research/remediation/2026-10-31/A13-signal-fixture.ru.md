# A13: готовность дочернего CLI к SIGTERM

R13 full race сохранил `exit status15`: тест посылал SIGTERM через1s после
старта, не устанавливая готовность программы. В controlled before добавлена
только1.5s задержка дочернего test process до main; старый тест воспроизводит
тот же отказ. Это отдельный контроль предусловия, не изменение продукта.

TestMain теперь может обернуть stdin test-only reader. При фактическом Read,
после входа в production main и установки его signal handler, reader сообщает
готовность через отдельный private pipe. Публичные CLI flags/output не меняются.
Родитель ждёт эту готовность вместо sleep; после SIGTERM остаются прежние5s,
exit1 и `tlsforge: context canceled`. Test helper сам signal handler не ставит.

Приняты32 race-повтора и8 повторов с1.5s child startup delay. Negative control
с удалённым production signal handler отвергнут с exit15. Runtime-файлы,
правила остановки и assertions не менялись. До/после и точные источники
сохранены в ignored capsule с проверенным манифестом0700/0600.
[Точный отчёт](checks-a13-signal-fixture.json). Full A13 остаётся открытым.
