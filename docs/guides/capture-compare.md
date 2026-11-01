# Capture and compare

`capture` measures an installed browser through the local measurement server. `compare` measures that browser and the selected profile against the same local fixture and reports differences within its scope.

```bash title="Terminal"
tls-forge capture --browser chrome --save profile.json
tls-forge compare --browser chrome --profile profile.json
tls-forge compare --profile chrome --json
```

For a browser the tool cannot launch, use `--manual` and open the printed URL yourself. `--addr` and `--host` control the local listener and certificate name. A listener on `0.0.0.0` is reachable from the network and has no user authentication.

`capture --policy-from` identifies a full profile whose unmeasured policy choices are inherited. Such an inheritance is provenance, not a fresh measurement. `--set` supplies explicit machine values. A saved profile must be validated for the current engine major before execution; see [profiles](profiles.md).

The Go API exposes measurement functions such as `MeasureBrowser`, `MeasureSelf`, `CompareToBrowser`, and capture types. Node.js and Python SDKs are request clients; invoke the CLI for capture and comparison.

## Interpret the result

A comparison exit status of **0** means the compared fields matched in that run; **3** means the run completed and found differences. An execution failure is different. The command does not establish all browser behaviour, all connection states, every profile platform, or full HTTP/3 fidelity. Repeated Chrome observations and scenario-specific wire checks are needed for those claims. See [scope and limits](../support/limits.md).
