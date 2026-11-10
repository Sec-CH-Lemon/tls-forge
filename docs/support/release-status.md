# Release status and compatibility

This documentation follows the `development` branch. At the time this documentation was prepared, `engine/version.json` declared:

| Field | Development source |
| --- | --- |
| Compiled version | `2.0.0` |
| Latest published stable anchor recorded by the project | `1.0.1` |
| Release status | `unreleased` (an engine change is pending) |
| Profile schema | `4` |
| Daemon protocol | `3` |

An executable profile declares one exact engine major. Engine 2 rejects a profile for major 1 or 3, and the published engine 1 (1.0.1) cannot run an engine 2 profile. Node.js and Python packages must use a matching daemon. Engine 2's Go module path is `github.com/Sec-CH-Lemon/tls-forge/v2`; the v0/v1 path is unsuffixed.

The engine major is anchored to the latest **actually published** stable release, 1.0.1 (published 2026-11-08; 1.0.0 reached PyPI alone): its forks laid over bogdanfinn's latest releases are an engine change, so this source is 2.0.0, unpublished, and stays 2.0.0 for every further engine change until it is published. JSON-only profile updates using implemented primitives do not create another engine major. The bundled profiles are engine 1's, explicitly migrated to engine 2 (`profile/provenance/engine2-migration.json`): the migration alone establishes no browser equivalence, and each is accepted again against its browser where that browser can still be run.

Check [GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases) for the actual published artifacts before installing. The source's release anchor can lag an external publication until it has been verified and updated. The documentation site does not itself publish a software release or validate every profile against every browser build.
