package main

import "strings"

// shellQuote makes a value safe to paste into the shell commands this program
// prints.
//
// A printed command is an invitation to copy it, and a path is not a word: the
// default place for the proxy's authority on macOS is under `Application
// Support`, so the obvious `--cacert /Users/me/Library/Application
// Support/tls-forge/ca.pem` reaches curl as two arguments and fails on both.
// The same goes for a `--name` somebody gave a profile.
//
// Quoting only what needs it, because a command nobody can read is its own kind
// of broken, and almost every path needs nothing. The safe set is the one
// Python's shlex.quote uses, which is conservative on purpose: anything outside
// it is quoted rather than reasoned about.
func shellQuote(s string) string {
	if s == "" {
		// Not nothing: an empty argument still has to arrive as an argument.
		return "''"
	}
	if strings.IndexFunc(s, unsafeInShell) < 0 {
		return s
	}
	// Single quotes suspend every shell meaning except their own ending, so the
	// only thing to handle is a quote in the value: close, escape it outside,
	// open again.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func unsafeInShell(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune("_@%+=:,./-", r)
}
