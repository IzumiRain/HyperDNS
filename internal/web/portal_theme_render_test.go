package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// The v2.4 custom-portal-CSS feature shipped inert: the wrapped <style> was typed
// template.CSS and rendered in an HTML element context, where html/template
// escapes it to visible &lt;style&gt; text so no theme ever reached the browser.
// v2.6 types it template.HTML so it renders active. This pins that it renders raw
// AND that a breakout attempt is still defanged by SanitizeThemeCSS first.
func TestPortalThemeCSSRendersActive(t *testing.T) {
	tmpl := template.Must(template.New("head").Parse(`<head>{{.ThemeCSS}}</head>`))
	render := func(css template.HTML) string {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, struct{ ThemeCSS template.HTML }{css}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return buf.String()
	}

	// A normal stylesheet renders as a live <style> element, not escaped text.
	out := render(wrapThemeCSS(SanitizeThemeCSS("body{background:#101}")))
	if !strings.Contains(out, "<style>") || strings.Contains(out, "&lt;style&gt;") {
		t.Fatalf("theme CSS did not render as an active <style> element: %s", out)
	}
	if !strings.Contains(out, "body{background:#101}") {
		t.Fatalf("theme CSS body was lost: %s", out)
	}

	// A breakout attempt is defanged before it is embedded, so even rendered raw
	// it can neither close the <style> early nor open a <script>.
	evil := render(wrapThemeCSS(SanitizeThemeCSS("</style><script>alert(1)</script>body{color:red}")))
	if strings.Contains(evil, "</style><script>") || strings.Contains(evil, "<script>alert") {
		t.Fatalf("breakout survived into the rendered page: %s", evil)
	}

	// An empty stylesheet emits no element at all.
	if got := render(wrapThemeCSS(SanitizeThemeCSS("   "))); strings.Contains(got, "<style>") {
		t.Fatalf("empty theme CSS still emitted a <style> element: %s", got)
	}
}
