package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdns/internal/database"
)

// TestResolvePortalThemeCSS covers the three v2.4 CSS sources: inline text and a
// server-local file both become a sanitised <style>, and a URL becomes a <link>
// the browser loads. Bad or missing sources render nothing rather than erroring.
func TestResolvePortalThemeCSS(t *testing.T) {
	// inline
	got := string(resolvePortalThemeCSS(database.SubscriptionSnapshot{
		ThemeCSSSource: "inline", ThemeCSS: ".portal{color:red}",
	}))
	if !strings.Contains(got, "<style>") || !strings.Contains(got, "color:red") {
		t.Errorf("inline source did not wrap CSS in <style>: %q", got)
	}

	// inline empty -> nothing
	if got := string(resolvePortalThemeCSS(database.SubscriptionSnapshot{ThemeCSSSource: "inline"})); got != "" {
		t.Errorf("empty inline should render nothing, got %q", got)
	}

	// url -> <link>, href escaped
	got = string(resolvePortalThemeCSS(database.SubscriptionSnapshot{
		ThemeCSSSource: "url", ThemeCSSURL: "https://cdn.example.com/sub.css",
	}))
	if !strings.Contains(got, `<link rel="stylesheet"`) || !strings.Contains(got, "https://cdn.example.com/sub.css") {
		t.Errorf("url source did not emit a link: %q", got)
	}

	// local file -> sanitised <style>
	dir := t.TempDir()
	cssPath := filepath.Join(dir, "sub.css")
	if err := os.WriteFile(cssPath, []byte(".portal{background:#000}\n@import url(https://evil.example/x.css);"), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}
	got = string(resolvePortalThemeCSS(database.SubscriptionSnapshot{
		ThemeCSSSource: "local", ThemeCSSPath: cssPath,
	}))
	if !strings.Contains(got, "background:#000") {
		t.Errorf("local source did not inline the file: %q", got)
	}
	if strings.Contains(got, "@import") {
		t.Errorf("local source did not sanitise @import out: %q", got)
	}

	// local missing file -> nothing, no panic
	if got := string(resolvePortalThemeCSS(database.SubscriptionSnapshot{
		ThemeCSSSource: "local", ThemeCSSPath: filepath.Join(dir, "does-not-exist.css"),
	})); got != "" {
		t.Errorf("missing local file should render nothing, got %q", got)
	}
}

// TestSanitizeSubscriptionCSSSource pins the save-time validation of the source
// selector and its value.
func TestSanitizeSubscriptionCSSSource(t *testing.T) {
	ws := &WebServer{settings: &database.ServerSettings{WebPort: 8080}}

	base := SubscriptionSettingsInput{URIPath: "/sub", Title: "X"}

	// url: absolute http(s) required.
	in := base
	in.ThemeCSSSource = "url"
	in.ThemeCSSURL = "ftp://example.com/x.css"
	if _, problem := ws.sanitizeSubscriptionSnapshot(in); problem == "" {
		t.Error("ftp URL should be rejected")
	}
	in.ThemeCSSURL = "https://example.com/x.css"
	out, problem := ws.sanitizeSubscriptionSnapshot(in)
	if problem != "" {
		t.Errorf("valid https URL rejected: %s", problem)
	}
	if out.ThemeCSSSource != "url" || out.ThemeCSSPath != "" {
		t.Errorf("url source did not clear the path field: %+v", out)
	}

	// local: absolute path required.
	in = base
	in.ThemeCSSSource = "local"
	in.ThemeCSSPath = "relative/sub.css"
	if _, problem := ws.sanitizeSubscriptionSnapshot(in); problem == "" {
		t.Error("relative local path should be rejected")
	}
	in.ThemeCSSPath = "/root/css/sub.css"
	out, problem = ws.sanitizeSubscriptionSnapshot(in)
	if problem != "" || out.ThemeCSSURL != "" {
		t.Errorf("valid local path rejected or url not cleared: %s %+v", problem, out)
	}

	// unknown source rejected.
	in = base
	in.ThemeCSSSource = "teleport"
	if _, problem := ws.sanitizeSubscriptionSnapshot(in); problem == "" {
		t.Error("unknown source should be rejected")
	}

	// empty source normalises to inline.
	in = base
	out, problem = ws.sanitizeSubscriptionSnapshot(in)
	if problem != "" || out.ThemeCSSSource != "inline" {
		t.Errorf("empty source should normalise to inline: %s %+v", problem, out)
	}
}
