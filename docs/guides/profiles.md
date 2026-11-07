# Profiles and compatibility

A profile is JSON describing a selected browser build and its network behaviour. It contains measured fields and explicit configuration for implemented engine primitives. The profile owns values, ordering, thresholds, timers and choices that can be represented as data. A capture is evidence, not a constant to replay on every connection.

## Select a profile

```bash title="Terminal"
tls-forge profiles
tls-forge fetch --profile chrome_157_macos https://example.com/
tls-forge fetch --profile /absolute/path/custom.json https://example.com/
```

`chrome` selects the newest Chrome profile for this host platform, shipped or kept on this machine under its version, and is what `fetch`, `proxy` and `daemon` wear when no profile is named. A browser measured here with `capture --install` is worn when it is named: `--profile local`. Pin an exact name or file for a reproducible selection. Go uses `WithProfile` or a validated `WithProfileValue`; Node.js and Python take a profile name or path in the `Client` constructor.

## A profile for each request

```bash title="Terminal"
tls-forge fetch --random-profile --input urls.txt > results.jsonl
```

`fetch --random-profile` draws a profile for each request instead of one for the whole run: from every browser measured, shipped or kept on this machine, that this build can wear. A profile made for another engine major is left out, as are the handshakes of tls-client's catalogue, which carry no headers of a browser's own. A request keeps its profile for all of its tries; each repeat under `--repeat` draws its own. The run's header lists what it draws from, and each result line, the run log, a kept request and the report say which profile a request wore.

Profiles that cannot send the run's requests as the newest Chrome sends them are left out of the draw: one that is not a Chromium profile under `--request-kind`, for instance. `--random-profile` cannot be combined with `--profile`, nor with `--reuse-connection`, which keeps one browser's connection for a URL's repeats. The shipped profiles are for macOS, Linux and Windows alike, so most of the draws are another platform's than this machine's, and a server that reads TCP/IP can tell those apart; the header says how many.

## Engine gate

The development source is **engine 1.0.0**, profile **schema 4**, daemon protocol **3**. Every executable profile needs a top-level integer `engine_major: 1`. The engine rejects older, newer, missing or invalid majors **before request-related network I/O**. A schema number, filename, User-Agent or browser alias does not imply compatibility. SDKs also check the daemon engine major.

```json title="JSON"
{
  "schema": 4,
  "engine_major": 1,
  "name": "example-profile"
}
```

This is metadata only, **not** a complete executable profile. The [profile behavior reference](../reference/profile-behavior.md) explains the JSON sections and policy groups; the [generated field inventory](../reference/profile-fields.md) lists keys present in bundled files. Neither replaces profile validation or documents every possible optional field.

`profile.Load` is the execution loader. `profile.Inspect` reads an old file offline. `Save` and `Clone` retain its declared major, including absence. Only explicit `Migrate` creates a current-engine candidate and retains source provenance; migration alone does not establish browser equivalence. Preserve the original capture and remeasure the relevant browser and wire scenarios before relying on a migrated profile.

## Scope of a profile

Shipped Chrome profiles cover multiple builds and platforms, but a current Chrome witness does not freshly validate every historical build and platform. New connection keys, tickets, counters, QPACK state, cookies and request-derived headers must be generated from current context. A renamed file or edited `engine_major` cannot make an incompatible profile equivalent.

Browser-specific behaviour belongs in JSON. A new protocol, algorithm, parser or state-machine primitive is an engine change. The pending 1.0.0 release shares one major for its runtime changes; another change before publication does not create engine 2. See [release status](../support/release-status.md).
