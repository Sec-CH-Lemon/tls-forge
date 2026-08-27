package profile

import (
	"fmt"
	"sync"
	"testing"
)

// TestRegistryIsSafeUnderConcurrentUse races Register against the readers.
//
// Registry guards r.added with an RWMutex, and until this test existed nothing
// in the package ran two goroutines: every call in profile/*_test.go was on the
// test goroutine, so the lock had full line coverage and no race coverage. A
// Registry is reachable from more than one goroutine in ordinary use — batch
// resolves a profile per worker — so the lock needs a test that would notice if
// it went away.
func TestRegistryIsSafeUnderConcurrentUse(t *testing.T) {
	r := NewRegistry()
	r.SetDir(t.TempDir())

	base, err := r.Get("chrome")
	if err != nil {
		t.Fatalf("Get(chrome): %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 256)

	// Writers registering distinct names, so they contend on the map itself.
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 8 {
				p := base.Clone()
				p.Name = fmt.Sprintf("racer_%d_%d", i, j)
				if err := r.Register(p); err != nil {
					errs <- err
				}
			}
		}()
	}

	// Readers going through every path that touches the guarded map.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				if _, err := r.Get("chrome"); err != nil {
					errs <- err
				}
				_ = r.Names()
				_ = r.HasHandshake("chrome")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent registry use: %v", err)
	}

	// Every write landed: a lost update would mean the lock is not doing its job
	// even when the race detector happens not to catch the interleaving.
	for i := range 8 {
		for j := range 8 {
			name := fmt.Sprintf("racer_%d_%d", i, j)
			if _, err := r.Get(name); err != nil {
				t.Errorf("Get(%s) after concurrent registration: %v", name, err)
			}
		}
	}
}
