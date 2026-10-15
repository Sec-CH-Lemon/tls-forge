package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// What a kept page's file ends in.
//
// What the server said it sent, in Content-Type, decides, so that the file
// opens as what it is: JSON kept as .html is shown by a browser as one long
// line of text, and an error page kept as .json opens as nothing at all. The
// header wins even when the body looks like something else, since it is what
// a browser would have gone by, and it is read as a browser reads it: of every
// type it names, the last. The bytes are looked at only when the header names
// nothing a file can be called: no Content-Type, one that says no more than
// "bytes", or a type this list does not know.

// pageExtensions is the extension for a media type, without its parameters.
var pageExtensions = map[string]string{
	"text/html":                     ".html",
	"application/xhtml+xml":         ".xhtml",
	"application/json":              ".json",
	"text/json":                     ".json",
	"application/x-ndjson":          ".ndjson",
	"application/xml":               ".xml",
	"text/xml":                      ".xml",
	"image/svg+xml":                 ".svg",
	"application/javascript":        ".js",
	"application/x-javascript":      ".js",
	"application/ecmascript":        ".js",
	"text/javascript":               ".js",
	"text/ecmascript":               ".js",
	"text/css":                      ".css",
	"text/plain":                    ".txt",
	"text/csv":                      ".csv",
	"text/markdown":                 ".md",
	"application/pdf":               ".pdf",
	"application/zip":               ".zip",
	"application/gzip":              ".gz",
	"application/x-gzip":            ".gz",
	"application/wasm":              ".wasm",
	"application/protobuf":          ".pb",
	"application/x-protobuf":        ".pb",
	"application/x-google-protobuf": ".pb",
	"application/ogg":               ".ogg",
	"image/png":                     ".png",
	"image/jpeg":                    ".jpg",
	"image/gif":                     ".gif",
	"image/webp":                    ".webp",
	"image/avif":                    ".avif",
	"image/bmp":                     ".bmp",
	"image/tiff":                    ".tiff",
	"image/x-icon":                  ".ico",
	"image/vnd.microsoft.icon":      ".ico",
	"font/woff":                     ".woff",
	"font/woff2":                    ".woff2",
	"font/ttf":                      ".ttf",
	"font/otf":                      ".otf",
	"audio/mpeg":                    ".mp3",
	"audio/ogg":                     ".ogg",
	"audio/wav":                     ".wav",
	"audio/wave":                    ".wav",
	"video/mp4":                     ".mp4",
	"video/webm":                    ".webm",
}

// saysOnlyBytes are the types a server sends when it does not know or will not
// say: the body is looked at instead.
var saysOnlyBytes = map[string]bool{
	"application/octet-stream":   true,
	"binary/octet-stream":        true,
	"application/unknown":        true,
	"application/x-unknown":      true,
	"unknown/unknown":            true,
	"application/download":       true,
	"application/force-download": true,
}

// pageExtension is the extension a page is kept under, with its dot.
func pageExtension(header map[string][]string, body []byte) string {
	if ext := extensionOf(contentTypeOf(header)); ext != "" {
		return ext
	}
	return sniffedExtension(body)
}

// contentTypeOf is the media type a browser goes by: of every type the
// Content-Type fields name, the last, as the Fetch standard and Chrome read a
// response that sends two. "*/*" names none.
func contentTypeOf(header map[string][]string) string {
	last := ""
	for _, item := range contentTypeItems(header) {
		if mediaType := mediaTypeOf(item); mediaType != "" && mediaType != "*/*" {
			last = mediaType
		}
	}
	return last
}

// contentTypeItems are the values of every Content-Type field, split at the
// commas between types, in the order a browser reads them. Fields whose names
// differ only in case are read in the order of their names, so that the answer
// does not change with the order a map is read in.
func contentTypeItems(header map[string][]string) []string {
	var names []string
	for name := range header {
		if strings.EqualFold(name, "Content-Type") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	var items []string
	for _, name := range names {
		for _, value := range header[name] {
			items = append(items, splitOutsideQuotes(value, ',')...)
		}
	}
	return items
}

// splitOutsideQuotes is a field value split at every sep, a comma between the
// items of a list or a semicolon between parameters, but not at one inside a
// quoted string, which a parameter's value can be. A backslash in a quoted
// string keeps the character after it in; one outside is a character like any
// other. A quote that is never closed runs to the end.
func splitOutsideQuotes(value string, sep byte) []string {
	var items []string
	start, quoted, escaped := 0, false, false
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = quoted
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			items = append(items, value[start:i])
			start = i + 1
		}
	}
	return append(items, value[start:])
}

// leadingType is the type and subtype a Content-Type value begins with: two
// tokens and the slash between them, after any whitespace.
var leadingType = regexp.MustCompile("^[\t ]*([!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+)")

// mediaTypeOf is the type and subtype a Content-Type value begins with, in
// lower case, or nothing when it begins with none. Whatever follows them is
// passed over, broken or not, as Chrome passes it over: "text/html;;charset="
// and "text/html (cached)" are text/html.
func mediaTypeOf(value string) string {
	if match := leadingType.FindStringSubmatch(value); match != nil {
		return strings.ToLower(match[1])
	}
	return ""
}

// extensionOf is the extension a media type names, or nothing when the body
// has to say.
func extensionOf(mediaType string) string {
	if ext, ok := pageExtensions[mediaType]; ok {
		return ext
	}
	switch {
	case saysOnlyBytes[mediaType]:
		return ""
	case strings.HasSuffix(mediaType, "+json"):
		return ".json"
	case strings.HasSuffix(mediaType, "+xml"):
		return ".xml"
	case strings.HasPrefix(mediaType, "text/"):
		return ".txt"
	}
	return ""
}

// sniffedExtension names a body by how it begins. JSON is tried first, since
// http.DetectContentType does not know it and calls it text; what that names
// is read as a header's type would be, and what it does not know is bytes.
func sniffedExtension(body []byte) string {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		return ".json"
	}
	if ext := extensionOf(mediaTypeOf(http.DetectContentType(body))); ext != "" {
		return ext
	}
	return ".bin"
}
