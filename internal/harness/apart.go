package harness

import "maps"

// apart are the scenarios Chrome sends otherwise on a platform than on macOS,
// where the fixtures were measured, by the platform's name as profiles say it
// (macos, linux, windows): why. A check there passes them over, and so do the
// replays wearing that platform's profile.
var apart = map[string]map[string]string{
	"windows": {
		"auth-digest-negotiate": "Chrome on Windows answers Negotiate, through SSPI, where on macOS it passes it " +
			"over and answers Digest (measured: Chrome 155.0.8059.85 on GitHub's Windows Server 2025 runner never " +
			"asked for the scenario's end page)",
		"auth-digest-ntlm": "Chrome on Windows writes NTLM's first message through SSPI, with the system's flags " +
			"and version, where on macOS its own (measured: TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw== " +
			"on GitHub's Windows Server 2025 runner, build 26100)",
	},
}

// Apart are the scenarios Chrome sends otherwise on platform than on macOS,
// and why.
func Apart(platform string) map[string]string { return maps.Clone(apart[platform]) }
