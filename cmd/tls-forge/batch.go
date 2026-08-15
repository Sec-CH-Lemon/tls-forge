package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// result is one line of the output. JSON lines rather than a JSON array so the
// output can be read as it is produced, and appended to across runs.
type result struct {
	URL      string `json:"url"`
	Proxy    string `json:"proxy,omitempty"`
	Status   int    `json:"status,omitempty"`
	FinalURL string `json:"final_url,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Body     string `json:"body,omitempty"`
	File     string `json:"file,omitempty"`
	Millis   int64  `json:"ms"`
	Attempts int    `json:"attempts,omitempty"`
	Error    string `json:"error,omitempty"`
}

// batchInput is os.Stdin, named so a test can supply a list.
var batchInput io.Reader = os.Stdin

// numCPU is runtime.NumCPU, named so a test can answer for it. A machine's core
// count is not something a test can choose, and the warning below is worth
// checking on more than whatever the runner happens to have.
var numCPU = runtime.NumCPU

// warnAboutConcurrency says something when more workers were asked for than
// there are CPUs to run them on.
//
// A warning and not a limit. Fetching waits on the network far more than on a
// core, so more workers than cores is often the right answer and capping it
// would make the tool slower for the thing it is for. What it usually means
// instead is a number typed without thinking, and past a point the extra
// workers only queue behind the same connections and the same exit IP.
//
// To stderr, so it cannot land in the middle of the JSON lines on stdout.
func warnAboutConcurrency(errOut *printer, workers int) {
	cpus, limited := cpuLimit()
	if workers <= cpus {
		return
	}
	// Named for where the number came from. "cores on this machine" would be a
	// puzzle to read on a 64-core host inside a container allowed two of them.
	where := "CPU cores on this machine"
	if limited {
		where = "CPUs this process is allowed"
	}
	errOut.printf("WARN: --concurrency %d is more than the %d %s.\n", workers, cpus, where)
	errOut.println("      Fetching waits on the network rather than on a core, so this may " +
		"be what you want.")
}

func runBatch(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("batch", out)
	common := addClientFlags(fs)
	input := fs.StringP("input", "i", "", "file of URLs (default: standard input)")
	inline := fs.StringP("urls", "u", "", "URLs as a comma-separated list, instead of a file")
	format := fs.StringP("format", "F", formatAuto,
		"how to read the list: auto, lines, json or csv")
	workers := fs.IntP("concurrency", "c", 4, "how many requests to run at once")
	output := fs.StringP("output", "o", "", "write the JSON lines here instead of standard output")
	bodyDir := fs.StringP("body-dir", "d", "",
		"write bodies to this directory and reference them instead of inlining")
	retry := fs.Int("retry", 1, "attempts per URL before giving up")
	setUsage(fs, out, "usage: tls-forge batch [flags] [urls...]")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *workers < 1 {
		return fmt.Errorf("%w: --concurrency must be at least 1", errUsage)
	}
	if *retry < 1 {
		return fmt.Errorf("%w: --retry must be at least 1", errUsage)
	}
	warnAboutConcurrency(errOut, *workers)

	jobs, err := readJobs(*inline, *input, *format, fs.Args(), batchInput)
	if err != nil {
		return err
	}
	// The whole list is checked before anything is fetched, so a typo costs a
	// message rather than half a scrape.
	if err := validate(jobs); err != nil {
		return err
	}

	if *bodyDir != "" {
		if err := os.MkdirAll(*bodyDir, 0o755); err != nil {
			return fmt.Errorf("batch: %w", err)
		}
	}

	sink := io.Writer(out)
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("batch: %w", err)
		}
		defer func() { _ = file.Close() }()
		sink = file
	}

	clients := newPool(common, *common.proxy)
	defer clients.close()

	failures := runJobs(ctx, jobs, clients, *workers, sink, *retry, *bodyDir)

	if *output != "" {
		out.printf("%d of %d succeeded, written to %s\n", len(jobs)-failures, len(jobs), *output)
	}
	if failures > 0 {
		// Non-zero exit: a batch that half worked is not a batch that worked,
		// and a shell loop needs to be able to tell.
		return fmt.Errorf("batch: %d of %d URLs failed", failures, len(jobs))
	}
	return nil
}

// pool hands out one client per proxy.
//
// One per proxy rather than one per worker, because the proxy is the identity.
// Two pages fetched through one exit IP sharing a cookie jar is what a browser
// does; two pages sharing a jar across two exit IPs is what none does. Clients
// are safe for concurrent use, so several workers can share one.
type pool struct {
	mu       sync.Mutex
	clients  map[string]*tlsforge.Client
	flags    clientFlags
	fallback string
}

func newPool(flags clientFlags, fallback string) *pool {
	return &pool{clients: map[string]*tlsforge.Client{}, flags: flags, fallback: fallback}
}

// get returns the client for a proxy, building it on first use.
//
// Built lazily so that a list naming twenty proxies of which the run only
// reaches three opens three, and so that a proxy URL that will not parse fails
// against the URL that asked for it rather than at start-up against nothing.
func (p *pool) get(proxy string) (*tlsforge.Client, error) {
	if proxy == "" {
		proxy = p.fallback
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[proxy]; ok {
		return client, nil
	}
	client, err := p.flags.clientVia(proxy)
	if err != nil {
		return nil, err
	}
	p.clients[proxy] = client
	return client, nil
}

func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		_ = client.Close()
	}
}

// runJobs fetches the list and returns how many entries failed. A failure is
// reported on its line rather than returned, so one dead host does not end the
// run.
func runJobs(ctx context.Context, jobs []job, clients *pool, workers int,
	sink io.Writer, retry int, bodyDir string,
) (failures int) {
	queue := make(chan job)
	var writeMu sync.Mutex
	encoder := json.NewEncoder(sink)
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				r := fetchOne(ctx, clients, j, retry, bodyDir)
				writeMu.Lock()
				if r.Error != "" {
					failures++
				}
				_ = encoder.Encode(r)
				writeMu.Unlock()
			}
		}()
	}

	for _, j := range jobs {
		select {
		case <-ctx.Done():
			// Interrupted. Stop handing out work; what is in flight finishes.
		case queue <- j:
			continue
		}
		break
	}
	close(queue)
	wg.Wait()
	return failures
}

func fetchOne(ctx context.Context, clients *pool, j job, attempts int, bodyDir string) result {
	started := time.Now()
	r := result{URL: j.URL, Proxy: j.Proxy}

	client, err := clients.get(j.Proxy)
	if err != nil {
		r.Error = err.Error()
		r.Millis = time.Since(started).Milliseconds()
		return r
	}

	var res *tlsforge.Response
	for attempt := 1; attempt <= attempts; attempt++ {
		r.Attempts = attempt
		res, err = client.Get(j.URL)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	r.Millis = time.Since(started).Milliseconds()

	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Status = res.Status
	r.FinalURL = res.URL
	r.Bytes = len(res.Body)

	if bodyDir == "" {
		r.Body = string(res.Body)
		return r
	}
	// Named from the URL rather than from a counter, so a re-run overwrites the
	// same file instead of producing a second copy under a new number.
	sum := sha256.Sum256([]byte(j.URL))
	path := filepath.Join(bodyDir, hex.EncodeToString(sum[:8])+".html")
	if err := os.WriteFile(path, res.Body, 0o644); err != nil {
		r.Error = err.Error()
		return r
	}
	r.File = path
	return r
}
