package main

import (
	"os"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// TestMain takes the waiting out of the suite.
//
// A failed URL is retried three times by default, and the pauses between those
// tries are seconds that most of these tests spend on something they are not
// about. TestRepeatBackoff checks the schedule itself, and the one test that
// cares that a pause happens at all puts it back.
//
// It also points the profile directory at one of its own. Every command now
// reports which profile it is wearing, and that reads the directory, so without
// this the suite would answer differently on a machine that has run
// `capture --install` — measured, when a leftover profile there turned a
// warning assertion in another file red.
func TestMain(m *testing.M) {
	repeatWait = func(int) time.Duration { return 0 }

	dir, err := os.MkdirTemp("", "tls-forge-profiles-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("TLSFORGE_PROFILES", dir)
	profile.Default.SetDir(dir)

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
