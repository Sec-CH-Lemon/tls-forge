# Release status and compatibility

This documentation follows the `development` branch. At the time this documentation was prepared, `engine/version.json` declared:

| Field | Development source |
| --- | --- |
| Compiled version | `1.0.1` |
| Latest published stable anchor recorded by the project | `1.0.1` |
| Release status | `released` |
| Profile schema | `4` |
| Daemon protocol | `3` |

An executable profile declares one exact engine major. Engine 1 rejects a profile for major 0 or 2, and a published 0.x binary cannot run an engine 1 profile. Node.js and Python packages must use a matching daemon. The Go v0/v1 module path is unsuffixed; `/v2` is reserved for an actual future major 2.

The next engine major is anchored to the latest **actually published** stable release, 1.0.1 (published 2026-11-08; 1.0.0 reached PyPI alone): the next engine change targets 2.0.0. JSON-only profile updates using implemented primitives do not create another engine major.

Check [GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases) for the actual published artifacts before installing. The source's release anchor can lag an external publication until it has been verified and updated. The documentation site does not itself publish a software release or validate every profile against every browser build.
