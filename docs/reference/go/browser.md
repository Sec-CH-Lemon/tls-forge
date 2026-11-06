# Go package `browser`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/browser"
```

Package browser finds and launches a locally installed Chromium browser.

It exists so a capture can be taken from the browser the user actually has, rather than from a downloaded one that might differ from it. A profile is only as good as the browser it was measured from, and "some Chrome" is not the same claim as "this Chrome".

Nothing here touches the user's real browser profile. Every launch gets a fresh temporary user-data directory, which keeps their history, cookies and extensions out of it — and, just as importantly, keeps the ignore-certificate-errors flag this capture needs from ever being applied to a profile they browse with.

## Types

<div class="tf-ref" markdown>

### Browser { .tf-symbol }

<div class="tf-ref__code" markdown>

```go linenums="0"
type Browser struct {
	// Name is the key it was found under, e.g. "chrome".
	Name string
	// Path is the executable.
	Path string
}
```

</div>

<div class="tf-ref__docs" markdown>

Browser is a launchable browser found on this machine.

</div>

</div>

<div class="tf-ref" markdown>

#### Find() { .tf-member }

<div class="tf-ref__code" markdown>

```go linenums="0"
func Find(name string) (*Browser, error)
```

</div>

<div class="tf-ref__docs" markdown>

Find locates a browser. An empty name searches; a name containing a path separator is taken as an executable path and used as given.

</div>

</div>

<div class="tf-ref" markdown>

#### Browser.Open() { .tf-member }

<div class="tf-ref__code" markdown>

```go linenums="0"
func (b *Browser) Open(ctx context.Context, url string, opts Options) (close func(), err error)
```

</div>

<div class="tf-ref__docs" markdown>

Open launches the browser at a URL and returns a function that closes it.

The temporary profile directory is removed by the returned function. The context kills the browser; the caller should still call the close function to clean up the directory. Either ends every process the browser started, not only its own: a browser is many processes.

</div>

</div>

<div class="tf-ref" markdown>

### Options { .tf-symbol }

<div class="tf-ref__code" markdown>

```go linenums="0"
type Options struct {
	// Headless runs without a window. Chrome's modern headless mode shares the
	// network stack with headed Chrome, and the handshakes were measured
	// identical — same JA4, same HTTP/2 fingerprint, same header order. Headed is
	// still the default for capture, because "identical today" is a measurement,
	// not a guarantee, and the browser the user is impersonating is a headed one.
	Headless bool

	// Args are appended last, so a caller can override anything below.
	Args []string
}
```

</div>

<div class="tf-ref__docs" markdown>

Options controls a launch.

</div>

</div>
