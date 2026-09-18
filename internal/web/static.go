package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// The dashboard's static assets are embedded, immutable for the lifetime of the
// process, and served by http.FileServer up to now. That combination has a
// specific and expensive consequence: embed.FS reports a zero modification time,
// http.ServeContent omits Last-Modified when the time is zero, and FileServer
// never generates an ETag — so no browser could ever revalidate. Every reload of
// the panel re-downloaded every byte of every asset, uncompressed, including the
// vendored chart and icon libraries. On the link an Iranian VPS actually has to a
// browser at home, that is the difference between a panel that opens and a panel
// the operator waits for.
//
// staticServer fixes both halves at startup rather than per request. Each asset
// is hashed once for a strong ETag, and each compressible asset is gzipped once
// and held next to the original, so a request costs a map lookup and a write.
// Assets cannot change while the process runs — they came out of the binary — so
// there is nothing to invalidate and no cache to keep coherent.

// compressibleExts are the extensions worth gzipping. Everything else — fonts,
// images, anything already compressed — would grow or gain a few bytes for real
// CPU, so it is stored once and served as-is.
var compressibleExts = map[string]bool{
	".html": true, ".css": true, ".js": true, ".mjs": true,
	".json": true, ".svg": true, ".txt": true, ".map": true,
	".xml": true, ".webmanifest": true,
}

// staticAsset is one embedded file, prepared for serving.
type staticAsset struct {
	contentType string
	body        []byte // the identity encoding, always present
	gzipped     []byte // nil when compression was skipped or did not pay
	etag        string // strong validator over body, already quoted
	gzipETag    string // the same, marked as a different representation
}

// staticServer holds every embedded asset, keyed by its slash path with no
// leading slash — exactly the form fs.WalkDir produces and http.Request paths
// reduce to.
type staticServer struct {
	assets map[string]*staticAsset
	index  *staticAsset

	// prefixedIndex caches the dashboard document rewritten for one admin
	// namespace. Since v2.1 the SPA is served below a generated 16-hex path,
	// but index.html was written when the panel lived at the host root: its
	// stylesheet and script tags name /css/... and /js/... absolutely, and a
	// browser landing on /<admin-path>/dash/ resolved them against the host
	// root — where nothing has been mounted since v2.1 — and drew a styled-
	// nothing page full of 404s. The fix serves the document with those
	// references rewritten below the live prefix. Only one namespace is live
	// at a time (a regeneration retires the old one along with every session),
	// so a single slot is the whole cache; a miss costs one pass of string
	// replacement over the document.
	prefixMu sync.Mutex
	prefix   string
	prefixed *staticAsset

	// loginRaw is the pristine embedded login document; loginDoc is the copy
	// rewritten for one admin namespace, cached the same way the dashboard
	// document is. login.html is self-contained (no external asset requests),
	// so the only rewrite is the __HDNS_ADMIN_BASE__ placeholder.
	loginRaw    *staticAsset
	loginDoc    *staticAsset
	loginPrefix string
}

// newStaticServer reads the whole asset tree once. A file that cannot be read is
// skipped rather than fatal: a missing icon should not stop the resolver from
// starting, and the handler answers 404 for it like any other unknown path.
func newStaticServer(fsys fs.FS) *staticServer {
	s := &staticServer{assets: make(map[string]*staticAsset)}
	if fsys == nil {
		return s
	}

	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return nil
		}
		s.assets[p] = newStaticAsset(p, body)
		return nil
	})

	s.index = s.assets["index.html"]
	return s
}

// newStaticAsset prepares one file: content type, strong validator, and a gzip
// body when it is worth carrying.
func newStaticAsset(name string, body []byte) *staticAsset {
	sum := sha256.Sum256(body)
	tag := base64.RawURLEncoding.EncodeToString(sum[:12])

	a := &staticAsset{
		contentType: contentTypeFor(name),
		body:        body,
		etag:        `"` + tag + `"`,
		gzipETag:    `"` + tag + `+gz"`,
	}

	if gz, ok := gzipIfSmaller(name, body); ok {
		a.gzipped = gz
	}
	return a
}

// staticTypes is consulted before mime.TypeByExtension, which reads the system
// registry on Windows and the shared MIME database on Linux — both of which the
// operator can have wrong. A host that reports text/plain for .js serves a panel
// that does not run at all, and a host that omits .woff2 serves fonts the browser
// refuses. Answering from this table first makes the daemon behave identically
// everywhere, and the registry lookup remains only as a fallback for extensions
// the dashboard does not currently ship.
var staticTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".svg":         "image/svg+xml",
	".ico":         "image/x-icon",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".otf":         "font/otf",
	".txt":         "text/plain; charset=utf-8",
	".xml":         "application/xml; charset=utf-8",
	".webmanifest": "application/manifest+json",
}

func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct, ok := staticTypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	// Unknown content is declared opaque rather than sniffable. The response also
	// carries X-Content-Type-Options: nosniff from the outer middleware, so a
	// mislabelled asset fails visibly instead of being guessed at.
	return "application/octet-stream"
}

// gzipIfSmaller compresses body once, at startup, and reports whether the result
// is worth keeping. Two floors apply. Below 1 KiB the gzip header and trailer are
// a large fraction of the payload and a round trip is dominated by latency anyway,
// so the identity body is the better answer. Above it, the compressed copy is kept
// only when it saves at least a tenth — otherwise the process would hold two
// nearly identical buffers for the life of the daemon to spare a few hundred bytes
// on the wire.
//
// BestCompression is the right level here precisely because this runs once: the
// CPU is spent at startup, and every request afterwards is a write of a finished
// buffer. A per-request compressor would have to trade the other way.
func gzipIfSmaller(name string, body []byte) ([]byte, bool) {
	if !compressibleExts[strings.ToLower(path.Ext(name))] || len(body) < 1024 {
		return nil, false
	}

	var buf bytes.Buffer
	buf.Grow(len(body) / 3)
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, false
	}
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return nil, false
	}
	if err := zw.Close(); err != nil {
		return nil, false
	}

	if buf.Len() >= len(body)-len(body)/10 {
		return nil, false
	}
	return buf.Bytes(), true
}

// ServeHTTP answers a request for one embedded asset. The surface is deliberately
// narrower than http.FileServer's: no directory listings, no automatic redirect
// from /dir to /dir/, no range requests, and no filesystem underneath — the map
// either holds the exact key or the request is a 404.
func (s *staticServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a := s.lookup(r.URL.Path)
	if a == nil {
		http.NotFound(w, r)
		return
	}
	s.write(w, r, a)
}

// lookup maps a request path onto an asset key. path.Clean resolves "." and ".."
// before the map is consulted, so a traversal attempt like /css/../../etc/passwd
// collapses to /etc/passwd and simply misses. There is no directory to escape onto
// in the first place — these bytes came out of the binary — but the request path is
// attacker-controlled and cleaning it costs nothing.
func (s *staticServer) lookup(p string) *staticAsset {
	if p == "" || p == "/" {
		return s.index
	}
	key := strings.TrimPrefix(path.Clean("/"+p), "/")
	if key == "" {
		return s.index
	}
	return s.assets[key]
}

// assetPathPrefixes are the root-absolute prefixes inside index.html that name
// the panel's own assets. The document was written for the pre-v2.1 root
// mount; every reference below these prefixes has to be moved under the
// install's admin namespace or the browser resolves it against the host root,
// where the dashboard's assets have not been served since v2.1. Only the five
// literal tags the document actually carries are rewritten — see
// TestDashboardDocumentReferencesAssetsUnderTheAdminPrefix.
var assetPathPrefixes = []string{
	"/css/", "/js/", "/fonts/", "/swagger/",
}

// prefixDocument rewrites index.html's root-absolute asset references to sit
// below the given admin namespace, returning the result as an asset that
// carries its own validator and pre-compressed body. The input is the server's
// own embedded document, so the exact byte pattern of each reference is known:
// attribute opens with `="`, the value is root-absolute, and the attribute
// closes at the next `"`. Anything that does not match that shape — data: URIs,
// ?lang= links, scheme and protocol-relative URLs — is passed through
// untouched.
func (s *staticServer) prefixDocument(adminPath string) *staticAsset {
	if adminPath == "" {
		return s.index
	}
	prefix := "/" + adminPath
	html := string(s.index.body)
	for _, p := range assetPathPrefixes {
		html = strings.ReplaceAll(html, `="`+p, `="`+prefix+p)
	}
	// The docs anchor is the one absolute reference that is not an asset, and
	// app.js also rewrites it at runtime; rewriting it here keeps the link
	// correct before any script runs.
	html = strings.ReplaceAll(html, `href="/api/v1/docs"`, `href="`+prefix+`/api/v1/docs"`)
	return newStaticAsset("index.html", []byte(html))
}

// assets map, so a build that carries the embed cannot miss it; newStaticServer
// fails loudly at compile time if the file is not in the embed list.
var loginDocName = "login.html"

// adminBasePlaceholder is the marker in login.html the server replaces with the
// install's hidden namespace. A literal token, not template syntax, because the
// document is a plain embedded file rather than a parsed template.
const adminBasePlaceholder = "__HDNS_ADMIN_BASE__"

// serveLogin writes the standalone sign-in document rewritten below the given
// admin namespace. It reports false when the login document was not embedded,
// which lets the caller answer 404 rather than an empty 200.
func (s *staticServer) serveLogin(w http.ResponseWriter, r *http.Request, adminPath string) bool {
	s.prefixMu.Lock()
	if s.loginRaw == nil {
		raw := s.assets[loginDocName]
		if raw == nil {
			s.prefixMu.Unlock()
			return false
		}
		s.loginRaw = raw
		s.loginPrefix = "\x00" // force a rewrite on the first call
	}
	if s.loginPrefix != adminPath {
		base := "/" + adminPath
		if adminPath == "" {
			base = ""
		}
		// Always rewrite from the pristine copy: rewriting the already-rewritten
		// body would leave nothing to replace after the first regeneration.
		s.loginDoc = newStaticAsset(loginDocName, []byte(strings.ReplaceAll(string(s.loginRaw.body), adminBasePlaceholder, base)))
		s.loginPrefix = adminPath
	}
	doc := s.loginDoc
	s.prefixMu.Unlock()

	s.write(w, r, doc)
	return true
}

// serveIndex answers one of the SPA's client-side routes with index.html, with the
// same validator and compression as any other asset. It reports false when the
// dashboard was not embedded at all, which lets the caller answer 404 rather than
// an empty 200.
//
// The document is served rewritten below the given admin namespace: index.html
// names its stylesheets and scripts root-absolute, and since v2.1 those paths
// resolve against the host root where nothing is mounted. adminPath comes from
// the caller because the static server has no access to the settings record.
func (s *staticServer) serveIndex(w http.ResponseWriter, r *http.Request, adminPath string) bool {
	if s.index == nil {
		return false
	}

	// One cached rewrite per namespace. The slot changes only when an operator
	// regenerates the admin path, and that flow invalidates every session, so a
	// stale entry cannot be observed by a browser that would still load it.
	s.prefixMu.Lock()
	if s.prefixed == nil || s.prefix != adminPath {
		s.prefixed = s.prefixDocument(adminPath)
		s.prefix = adminPath
	}
	doc := s.prefixed
	s.prefixMu.Unlock()

	s.write(w, r, doc)
	return true
}

// write emits one asset, negotiating the encoding and honouring a conditional
// request. The order matters: the validator has to describe the representation
// actually being sent, so the gzip decision is made before the ETag is written and
// the compressed copy carries its own tag. A cache that stored the gzip body under
// the identity tag would hand a client the wrong bytes after an upgrade.
func (s *staticServer) write(w http.ResponseWriter, r *http.Request, a *staticAsset) {
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	// The URLs are not content-addressed — /js/app.js keeps its name across builds —
	// so the browser must revalidate rather than trust a lifetime. no-cache means
	// "reuse it, but ask first", which turns a repeat visit into a 304 with no body
	// instead of a fresh download of every asset. Neither max-age nor immutable is
	// safe here: an operator who upgrades the binary would keep the old panel.
	h.Set("Cache-Control", "no-cache")
	// Two representations share this URL, so any shared cache has to key on the
	// request's encoding.
	h.Set("Vary", "Accept-Encoding")

	body, etag := a.body, a.etag
	if a.gzipped != nil && acceptsGzip(r) {
		body, etag = a.gzipped, a.gzipETag
		h.Set("Content-Encoding", "gzip")
	}
	h.Set("ETag", etag)

	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		// A 304 carries no body. Dropping these two keeps the response from
		// contradicting the entry the client already holds.
		h.Del("Content-Type")
		h.Del("Content-Length")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set explicitly rather than leaving it to the chunked writer: the length is
	// known, and a browser that knows it can show real progress.
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// acceptsGzip reads Accept-Encoding far enough to be correct about the one case
// that matters. Every browser sends "gzip, deflate, br" or similar, so a substring
// check would work in practice; what it would get wrong is "gzip;q=0", which is how
// a client — or a debugging proxy — explicitly asks for the identity encoding.
// Honouring that is the difference between a diagnosable server and one that
// insists on compressing.
func acceptsGzip(r *http.Request) bool {
	for part := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		for _, param := range fields[1:] {
			// Parameter names are case-insensitive per RFC 9110 §5.6.6, and curl's
			// own docs write "q=", so a case-sensitive check would honour one spelling
			// and silently ignore the other.
			p := strings.ToLower(strings.TrimSpace(param))
			if !strings.HasPrefix(p, "q=") {
				continue
			}
			if v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64); err == nil && v <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

// etagMatches implements the If-None-Match comparison of RFC 9110 §13.1.2. Three
// details are easy to get wrong and all three break real clients: "*" matches any
// representation the server has, the header is a comma-separated list rather than a
// single value, and the comparison for If-None-Match is *weak*, so a "W/" prefix on
// either side is ignored. A server that compares the raw strings answers 200 to
// every revalidation from a proxy that added the prefix, which silently undoes the
// whole point of sending a validator.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}

	want := strings.TrimPrefix(etag, "W/")
	for candidate := range strings.SplitSeq(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == want {
			return true
		}
	}
	return false
}
