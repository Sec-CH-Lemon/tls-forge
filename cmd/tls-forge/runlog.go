package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
	"github.com/spf13/pflag"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

// A run's log: everything it did, written down as it did it, for whoever has to
// work out afterwards what went wrong.
//
// Not the trace, which is a picture of where the time went, and not the log
// kept beside each request, which is written when the request is over. This
// one is written as things happen, a line at a time, and holds what neither
// does: every lookup and dial, what a proxy said to CONNECT, the handshake and
// the certificates of every connection, the header fields that went out, the
// HTTP/2 frames that came back, and every connection the transport opened for
// no request in particular. A run that never ended has it up to where it
// stopped.

// logFlags are where the log goes and how much it says.
type logFlags struct {
	path  *string
	level *string
}

func addLogFlags(fs *pflag.FlagSet) logFlags {
	return logFlags{
		path: fs.String("log", "",
			"write every step of the run here as it happens: each request, the connections it went out on and "+
				"what came back; - is standard error, and a name ending in .json, .jsonl or .ndjson gets JSON lines. "+
				"With --output, a run-<time>.log in it unless this names another"),
		level: fs.String("log-level", "trace",
			"how much the log says: error, warn, info, debug, or trace, which adds every TLS handshake, "+
				"certificate and HTTP/2 frame"),
	}
}

// logLevels are what --log-level takes.
var logLevels = map[string]slog.Level{
	"error": slog.LevelError, "warn": slog.LevelWarn, "info": slog.LevelInfo,
	"debug": slog.LevelDebug, "trace": tlsforge.LevelTrace,
}

// levelOf is the level --log-level names.
func (f logFlags) levelOf() (slog.Level, error) {
	level, ok := logLevels[strings.ToLower(*f.level)]
	if !ok {
		return 0, badValue("--log-level", *f.level, "error, warn, info, debug or trace")
	}
	return level, nil
}

// runLog is the log a run writes. Nil writes nothing, and everything asked of
// it is then nothing.
type runLog struct {
	log *slog.Logger
	// path is where it goes, "-" for standard error; out is what it is written
	// through, and file what is closed when the run is over.
	path string
	out  *logWriter
	file io.Closer
	// stderr is standard error, when that is where it goes.
	stderr *stderrLines
}

// openLogFile opens the file a log goes to: added to rather than replaced, as
// a log is, so that a run does not lose the one before it. A variable so a test
// can hand back something that will not be written to.
//
// 0600, as with a trace: it names every URL a run asked for and every address
// it went through.
var openLogFile = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

// runLogPath is the file a run's log goes to: the one --log names, or one
// named after the moment the run began in the --output directory when --log
// names none. Nothing for no log, and for one on standard error.
func runLogPath(path, output string, when time.Time) string {
	switch {
	case path == "-":
		return ""
	case path == "" && output != "":
		return filepath.Join(output, "run-"+stamp(when)+".log")
	}
	return path
}

// openRunLog opens the log of a run: the file runLogPath names, or standard
// error for "-". Nil when there is neither.
//
// That it is no file another flag names is the run's file plan's to say.
func openRunLog(path string, level slog.Level, output string, when time.Time, errOut *printer) (*runLog, error) {
	file := runLogPath(path, output, when)
	if file == "" && path != "-" {
		return nil, nil
	}

	l := &runLog{path: either(file, path)}
	var w io.Writer
	if file == "" {
		l.stderr = &stderrLines{out: errOut}
		w = l.stderr
	} else {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}
		opened, err := openLogFile(file)
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}
		l.file, w = opened, opened
	}
	l.out = &logWriter{w: w}

	options := &slog.HandlerOptions{Level: level, ReplaceAttr: logAttr}
	var handler slog.Handler = slog.NewTextHandler(l.out, options)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonl", ".ndjson":
		handler = slog.NewJSONHandler(l.out, options)
	}
	l.log = slog.New(handler)
	transportLines.add(l.log)
	return l, nil
}

// logAttr writes a record's time to the microsecond, which is the scale a
// handshake is measured on, and LevelTrace as TRACE rather than as DEBUG-4.
func logAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch {
	case a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime:
		a.Value = slog.StringValue(a.Value.Time().Format("2006-01-02T15:04:05.000000Z07:00"))
	case a.Key == slog.LevelKey:
		if level, _ := a.Value.Any().(slog.Level); level <= tlsforge.LevelTrace {
			a.Value = slog.StringValue("TRACE")
		}
	}
	return a
}

// logger is what the run's clients and requests write to, or nil for none.
func (l *runLog) logger() *slog.Logger {
	if l == nil {
		return nil
	}
	return l.log
}

// say writes one record of the run's own.
func (l *runLog) say(level slog.Level, msg string, args ...any) {
	if l == nil {
		return
	}
	l.log.Log(context.Background(), level, msg, args...)
}

// shareStderr has the log go around a status line drawn on standard error,
// when that is where it goes, as everything else said there does.
func (l *runLog) shareStderr(line *statusLine) {
	if l == nil || l.stderr == nil {
		return
	}
	l.stderr.mu.Lock()
	defer l.stderr.mu.Unlock()
	l.stderr.line = line
}

// closeStatus closes a status line with nothing of the log written while it
// does: a record written past a closed line would draw it again.
func (l *runLog) closeStatus(line *statusLine) {
	if l == nil || l.stderr == nil {
		line.Close()
		return
	}
	l.stderr.mu.Lock()
	defer l.stderr.mu.Unlock()
	line.Close()
	l.stderr.line = nil
}

// close ends the log with how the run ended, and says what kept it from being
// written, if anything did.
func (l *runLog) close(runErr error) error {
	if l == nil {
		return nil
	}
	if runErr != nil {
		l.say(slog.LevelWarn, "run ended", "error", redact.Text(runErr.Error()))
	} else {
		l.say(slog.LevelInfo, "run ended")
	}
	transportLines.remove(l.log)
	var closeErr error
	if l.file != nil {
		closeErr = l.file.Close()
	}
	if err := errors.Join(l.out.failed(), closeErr); err != nil {
		return fmt.Errorf("fetch: writing the log %s: %w", l.path, err)
	}
	return nil
}

// runAttrs are what a record of the run says: extra, as pairs, those of them
// that say anything, and then what the trace says of the same thing, by name.
func runAttrs(about traceArgs, extra ...any) []any {
	var attrs []any
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] != "" {
			attrs = append(attrs, extra[i], extra[i+1])
		}
	}
	for _, key := range slices.Sorted(maps.Keys(about)) {
		attrs = append(attrs, key, about[key])
	}
	return attrs
}

// withLog is a logger with more to say on every record, or nil when there is
// none to say it on.
func withLog(log *slog.Logger, args ...any) *slog.Logger {
	if log == nil {
		return nil
	}
	return log.With(args...)
}

// logWriter keeps the first error the log met and writes nothing after it: a
// log that cannot be written is said once, when the run is over, rather than
// stopping every request that had something to say.
type logWriter struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil {
		_, w.err = w.w.Write(p)
	}
	return len(p), nil
}

func (w *logWriter) failed() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// stderrLines is standard error as the log writes to it: a record at a time,
// and above the status line while one is drawn there.
type stderrLines struct {
	mu   sync.Mutex
	out  *printer
	line *statusLine
}

func (s *stderrLines) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.line != nil {
		s.line.Log(strings.TrimSuffix(string(p), "\n"))
		return len(p), nil
	}
	return s.out.Write(p)
}

// The transport says what HTTP/2 frames it reads only through the standard
// logger, and only when http2.VerboseLogs says to. It reads that from every
// connection's goroutine, so it is set once, before any of them start, and
// the standard logger then goes to the logs of the runs open at the time. It
// says nothing there of which request a frame belongs to: with one request at
// a time, a frame is the one around it.
func init() {
	http2.VerboseLogs = true
	log.SetFlags(0)
	log.SetOutput(transportLines)
}

// transportLines are the logs what the transport says goes to.
var transportLines = &transportLog{unlogged: os.Stderr}

type transportLog struct {
	mu   sync.Mutex
	logs []*slog.Logger
	// unlogged is where what the transport says without being asked goes when
	// no log is open, as it always went: standard error, as the standard
	// logger writes it.
	unlogged io.Writer
}

func (t *transportLog) add(log *slog.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logs = append(t.logs, log)
}

func (t *transportLog) remove(log *slog.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logs = slices.DeleteFunc(t.logs, func(l *slog.Logger) bool { return l == log })
}

// Write is one line of what the transport says.
func (t *transportLog) Write(p []byte) (int, error) {
	level, ok := transportLevel(strings.TrimSuffix(string(p), "\n"))
	if !ok {
		return len(p), nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	line := transportSaid(strings.TrimSuffix(string(p), "\n"))
	if len(t.logs) == 0 && level >= slog.LevelWarn {
		_, _ = fmt.Fprintf(t.unlogged, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), line)
	}
	for _, l := range t.logs {
		l.Log(context.Background(), level, "transport", "said", line)
	}
	return len(p), nil
}

// verboseLines begin what the transport says only because http2.VerboseLogs
// asks it to: the frames it reads, and the connections it opens and closes.
var verboseLines = []string{
	"http2: Transport received ", "http2: Transport creating client conn ", "http2: Transport closing idle conn ",
	"http2: Transport readFrame error ", "http2: Transport conn ", "http2: Transport failed to get client conn ",
	"http2: handling push promise", "http2: decoded hpack field ", "RoundTrip failure: ",
	"transport got GOAWAY ", "Unhandled Setting: ",
}

// hpackField is how the transport says a header field it decoded, which it
// does only when GODEBUG=http2debug=2 asks it to: the name and the value,
// quoted, and whether the field was sent as sensitive.
var hpackField = regexp.MustCompile(`^(http2: decoded hpack field header field )("(?:[^"\\]|\\.)*") = ("(?:[^"\\]|\\.)*")(.*)$`)

// transportSaid is a line of what the transport says as it may be written
// down: a header field's value without its secret, as every request's record
// of what it sent has it, and no URL with its password.
func transportSaid(line string) string {
	if field := hpackField.FindStringSubmatch(line); field != nil {
		name, _ := strconv.Unquote(field[2])
		value, _ := strconv.Unquote(field[3])
		return field[1] + strconv.Quote(name) + " = " + strconv.Quote(redact.Value(name, value)) + field[4]
	}
	return redact.Text(line)
}

// transportLevel is the level a line of what the transport says is logged at,
// and whether it is logged at all: what it says only when asked, at the trace
// level, and anything else, a cookie it would not keep or a server breaking the
// protocol, as a warning. Not the header fields it encodes, which it says
// value and all, secrets included, and which every request's record of what
// it sent has already.
func transportLevel(line string) (slog.Level, bool) {
	if strings.HasPrefix(line, "http2: Transport encoding header ") {
		return 0, false
	}
	if strings.Contains(line, "unsolicited") {
		return slog.LevelWarn, true
	}
	for _, verbose := range verboseLines {
		if strings.HasPrefix(line, verbose) {
			return tlsforge.LevelTrace, true
		}
	}
	return slog.LevelWarn, true
}
