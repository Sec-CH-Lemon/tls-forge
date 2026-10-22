package tlsforge

import "github.com/Sec-CH-Lemon/tls-forge/v2/engine"

// Version is the actual compiled engine version.
func Version() string { return engine.Version() }

// EngineMajor is the exact profile compatibility major.
func EngineMajor() int { return engine.Major() }
