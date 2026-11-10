package daemon

import "github.com/Sec-CH-Lemon/tls-forge/engine"

func majorForTest() *int { n := engine.Major(); return &n }
