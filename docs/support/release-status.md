# Release status and compatibility

This documentation follows the `development` branch. At the time this documentation was prepared, `engine/version.json` declared:

| Field | Development source |
| --- | --- |
| Compiled version | `1.1.0` |
| Latest published stable anchor recorded by the project | `1.1.0` |
| Release status | `released` |
| Profile schema | `4` |
| Daemon protocol | `3` |

An executable profile declares one exact engine major. Engine 1 rejects a profile for major 0 or 2, and a published 0.x binary cannot run an engine 1 profile. Within major 1, an older engine refuses, before any I/O, a newer profile that uses a key it does not know. Node.js and Python packages must use a matching daemon. The Go v0/v1 module path is unsuffixed; `/v2` starts with major 2.

The engine major goes up only when the profiles of the latest **actually published** stable release, 1.1.0 (published 2026-11-12), can no longer run on the engine as they are; it is then `latest_released_major + 1`, once for the whole next release. 1.1.0 laid the forks over bogdanfinn's latest releases, a change of the engine's own code under which every 1.0.1 profile still ran unchanged, so it stayed engine 1, and its bundled profiles say `engine_major: 1`; Chrome 157's were captured again on the builds Google served on 2026-11-11. JSON-only profile updates using implemented primitives do not create another engine major either.

Check [GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases) for the actual published artifacts before installing. The source's release anchor can lag an external publication until it has been verified and updated. The documentation site does not itself publish a software release or validate every profile against every browser build.
