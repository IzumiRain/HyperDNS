package web

import (
	"regexp"
	"strings"
	"testing"
)

// Accessible names for the dashboard's controls.
//
// A placeholder is not a label. A screen reader does not announce it as the
// field's name, and it disappears the moment the field has content — so an
// operator who tabs back into a half-filled Settings form has nothing left to
// identify it by. Thirty-three controls shipped that way: every LDAP field,
// every subscription field, both certificate fields, the three rule-list inputs,
// both static-record inputs, all four two-factor fields, the three search boxes,
// the stream filter, the expiry hour/minute selects, and the four icon-only
// dialog buttons, which had no text node at all.
//
// The rule this pins is narrow and mechanical: a control the operator can type
// into, choose from, or click must carry a name in the markup. Which mechanism
// supplies it — a <label for>, a wrapping <label>, aria-label, aria-labelledby —
// is not this test's business.

var (
	// controlRe finds form controls and buttons with an id, capturing the whole
	// opening tag so the attributes can be inspected together.
	controlRe = regexp.MustCompile(`(?is)<(input|select|textarea|button)\b[^>]*\bid="([^"]+)"[^>]*>`)
	// labelForRe collects every id a <label for> points at.
	labelForRe = regexp.MustCompile(`(?i)<label\b[^>]*\bfor="([^"]+)"`)
)

func TestDashboardControlsCarryAccessibleNames(t *testing.T) {
	doc := readAsset(t, "index.html")

	labelled := map[string]bool{}
	for _, m := range labelForRe.FindAllStringSubmatch(doc, -1) {
		labelled[m[1]] = true
	}

	var missing []string
	matches := controlRe.FindAllStringSubmatchIndex(doc, -1)
	for _, idx := range matches {
		tag := doc[idx[0]:idx[1]]
		kind := strings.ToLower(doc[idx[2]:idx[3]])
		id := doc[idx[4]:idx[5]]

		// Hidden inputs carry no user-facing identity.
		if kind == "input" && strings.Contains(strings.ToLower(tag), `type="hidden"`) {
			continue
		}
		if labelled[id] ||
			strings.Contains(tag, "aria-label=") ||
			strings.Contains(tag, "aria-labelledby=") ||
			strings.Contains(tag, "title=") {
			continue
		}
		// A wrapping <label> is the other legitimate mechanism: the control sits
		// inside a label element, so the label's own text names it. Detect it by
		// looking back for an unclosed <label> before this control.
		if lastOpen := strings.LastIndex(doc[:idx[0]], "<label"); lastOpen >= 0 {
			if strings.LastIndex(doc[:idx[0]], "</label>") < lastOpen {
				continue
			}
		}
		// A button with visible text names itself.
		if kind == "button" {
			if end := strings.Index(doc[idx[1]:], "</button>"); end >= 0 {
				inner := doc[idx[1] : idx[1]+end]
				if strings.TrimSpace(stripTagsAndEntities(inner)) != "" {
					continue
				}
			}
		}
		missing = append(missing, kind+"#"+id)
	}

	if len(missing) != 0 {
		t.Errorf("%d dashboard control(s) have no accessible name: %v\n"+
			"Give each one an aria-label (or a <label for>): a placeholder is not a "+
			"name, and it vanishes once the field has content.",
			len(missing), missing)
	}
	if len(matches) < 100 {
		t.Errorf("only %d controls were scanned — the extractor is broken and this "+
			"test is passing in silence", len(matches))
	}
}

// stripTagsAndEntities reduces inner markup to its text, so an icon-only button
// (an <i>/<svg> and nothing else) reads as empty.
func stripTagsAndEntities(s string) string {
	s = regexp.MustCompile(`(?s)<[^>]*>`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`&[a-zA-Z#0-9]+;`).ReplaceAllString(s, "")
	return s
}
