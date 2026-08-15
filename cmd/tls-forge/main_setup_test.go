package main

import (
	"os"
	"testing"
	"time"
)

// TestMain takes the waiting out of the suite.
//
// A failed URL is retried three times by default, and the pauses between those
// tries are seconds that most of these tests spend on something they are not
// about. TestRepeatBackoff checks the schedule itself, and the one test that
// cares that a pause happens at all puts it back.
func TestMain(m *testing.M) {
	repeatWait = func(int) time.Duration { return 0 }
	os.Exit(m.Run())
}
