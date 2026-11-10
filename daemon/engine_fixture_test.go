package daemon

import "github.com/Sec-CH-Lemon/tls-forge/v2/engine"

func majorForTest() *int { n := engine.Major(); return &n }
