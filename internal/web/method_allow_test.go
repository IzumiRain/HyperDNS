package web

// Every Allow header in this package is a string literal someone typed beside the guard that
// rejects the request. The REST API's version of this property is checked by behaviour — probe
// every verb, treat "answered something other than 405" as the endpoint's own statement that it
// serves that verb — and that is the stronger test, because it cannot agree with a mistake the
// way a second reading of the same source can.
//
// That approach is not available here. Probing the dashboard means sending POST /api/tls/issue,
// which can start a background ACME issuance against a real certificate authority, and POST
// /api/benchmark, which opens real connections to upstream resolvers. A test suite must not do
// either, and a test that skipped those two routes would be checking everything except the ones
// worth worrying about.
//
// So this reads the source, as a parse tree rather than as text: for every 405 in the package it
// finds the guard that produced it — an `if r.Method != …` chain, or the default of a
// `switch r.Method` — and requires the Allow value to name exactly the verbs that guard admits.
// The two sides come from different places, a condition and a string literal, so a list that
// drifted from its guard fails.
//
// Completeness matters as much as the comparison. A 405 written in a shape this file does not
// recognise is not silently skipped — it is reported by position, because an unrecognised guard
// is exactly where a mismatch would hide.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowSourceFiles are the files in this package that answer a request with 405.
// TestNoOther405SitesEscapeTheCheck keeps the list honest.
var allowSourceFiles = []string{"server.go", "auth.go", "static.go", "portal.go", "tls.go", "landing.go", "auth2fa.go", "sse_ticket.go", "preset_update.go"}

// methodVerbs maps the net/http constant to the token that belongs in an Allow header. Only
// these nine exist, so a guard naming anything else is a guard this file does not understand
// rather than one it can quietly assume something about.
var methodVerbs = map[string]string{
	"MethodGet":     "GET",
	"MethodHead":    "HEAD",
	"MethodPost":    "POST",
	"MethodPut":     "PUT",
	"MethodPatch":   "PATCH",
	"MethodDelete":  "DELETE",
	"MethodConnect": "CONNECT",
	"MethodOptions": "OPTIONS",
	"MethodTrace":   "TRACE",
}

// verbOf reads http.MethodGet and answers "GET". Anything else — a bare string, a constant from
// elsewhere — is not recognised, which makes the caller report the site rather than conclude the
// guard admits nothing.
func verbOf(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return "", false
	}
	v, ok := methodVerbs[sel.Sel.Name]
	return v, ok
}

// isRequestMethod matches r.Method, which is the left-hand side of every guard here.
func isRequestMethod(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Method" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "r"
}

// verbsFromCond reads `r.Method != http.MethodGet && r.Method != http.MethodHead` and answers
// {GET, HEAD}: the verbs the guard lets past, which is precisely the set its Allow header owes
// the caller. It returns nil — not an empty set — for a condition it does not understand, so an
// unfamiliar guard is reported instead of compared against nothing.
func verbsFromCond(cond ast.Expr) map[string]bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	switch bin.Op {
	case token.LAND:
		left, right := verbsFromCond(bin.X), verbsFromCond(bin.Y)
		if left == nil || right == nil {
			return nil
		}
		for v := range right {
			left[v] = true
		}
		return left
	case token.NEQ:
		var (
			verb  string
			known bool
		)
		switch {
		case isRequestMethod(bin.X):
			verb, known = verbOf(bin.Y)
		case isRequestMethod(bin.Y):
			verb, known = verbOf(bin.X)
		}
		if !known {
			return nil
		}
		return map[string]bool{verb: true}
	}
	return nil
}

// switchGuard reads a `switch r.Method` and answers the verbs its cases serve together with the
// default clause's statements. It gives up when a case names something other than an http.Method
// constant: an understated set would fail the comparison below for the wrong reason, and the
// point of the exercise is that a failure names the real mistake.
func switchGuard(sw *ast.SwitchStmt) (map[string]bool, []ast.Stmt, bool) {
	if sw.Tag == nil || !isRequestMethod(sw.Tag) {
		return nil, nil, false
	}
	verbs := map[string]bool{}
	var def []ast.Stmt
	for _, st := range sw.Body.List {
		clause, ok := st.(*ast.CaseClause)
		if !ok {
			return nil, nil, false
		}
		if clause.List == nil {
			def = clause.Body
			continue
		}
		for _, e := range clause.List {
			v, ok := verbOf(e)
			if !ok {
				return nil, nil, false
			}
			verbs[v] = true
		}
	}
	return verbs, def, true
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// isNotAllowedCall reports whether a call answers a request with 405, by either route in use
// here: the shared JSON helper, or http.Error with the status handed straight to it.
func isNotAllowedCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name == "WriteMethodNotAllowed" {
		return true
	}
	if sel.Sel.Name != "Error" {
		return false
	}
	for _, arg := range call.Args {
		if s, ok := arg.(*ast.SelectorExpr); ok && s.Sel.Name == "StatusMethodNotAllowed" {
			return true
		}
	}
	return false
}

// notAllowedSites is every place in a file that answers 405, keyed by position so the walk below
// can tick each one off against the guard that owns it. Whatever is left over is a 405 nothing
// checked.
func notAllowedSites(f *ast.File) map[token.Pos]bool {
	sites := map[token.Pos]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isNotAllowedCall(call) {
			sites[call.Pos()] = true
		}
		return true
	})
	return sites
}

// siteIn finds the 405 answer among a block's own statements. Only direct statements are read, so
// an outer if cannot be mistaken for the guard that owns an inner one — which matters, because
// two of the guards here sit inside an `if clientID, ok := strings.CutSuffix(…)` that has nothing
// to do with methods.
func siteIn(stmts []ast.Stmt) (token.Pos, bool) {
	for _, st := range stmts {
		expr, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := expr.X.(*ast.CallExpr); ok && isNotAllowedCall(call) {
			return call.Pos(), true
		}
	}
	return token.NoPos, false
}

// allowArgOf finds the Allow value a block announces. Two shapes appear in this package: the
// shared helper, which sets the header itself from its argument, and — on the two routes that
// answer for a page and for an embedded asset, where the body is plain text rather than JSON — a
// hand-written header Set beside an http.Error.
func allowArgOf(stmts []ast.Stmt) (string, bool) {
	for _, st := range stmts {
		expr, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		switch sel.Sel.Name {
		case "WriteMethodNotAllowed":
			if v, ok := stringLit(call.Args[1]); ok {
				return v, true
			}
		case "Set":
			if name, ok := stringLit(call.Args[0]); !ok || name != "Allow" {
				continue
			}
			if v, ok := stringLit(call.Args[1]); ok {
				return v, true
			}
		}
	}
	return "", false
}

func sortedVerbs(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func TestEveryAllowHeaderMatchesItsOwnGuard(t *testing.T) {
	for _, name := range allowSourceFiles {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		sites := notAllowedSites(file)
		if len(sites) == 0 {
			t.Fatalf("%s answers nothing with 405, though it did when this test was written. Either a "+
				"guard was removed or allowSourceFiles is stale — and a file with nothing to check "+
				"would otherwise pass here by default.", name)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			var (
				verbs map[string]bool
				body  []ast.Stmt
			)
			switch stmt := n.(type) {
			case *ast.IfStmt:
				verbs, body = verbsFromCond(stmt.Cond), stmt.Body.List
			case *ast.SwitchStmt:
				v, def, ok := switchGuard(stmt)
				if !ok {
					return true
				}
				verbs, body = v, def
			default:
				return true
			}
			if verbs == nil || body == nil {
				return true
			}
			pos, ok := siteIn(body)
			if !ok {
				return true
			}
			delete(sites, pos)
			where := fset.Position(pos)

			allow, ok := allowArgOf(body)
			if !ok {
				t.Errorf("%s: a 405 with no Allow header. RFC 9110 §15.5.6 requires one, and without "+
					"it the response says only that the verb was wrong — leaving the caller to guess "+
					"which verb it should have sent.", where)
				return true
			}
			claimed := map[string]bool{}
			for m := range strings.SplitSeq(allow, ",") {
				if m = strings.TrimSpace(m); m != "" {
					claimed[m] = true
				}
			}
			if sortedVerbs(claimed) != sortedVerbs(verbs) {
				t.Errorf("%s: the guard admits [%s] and the header advertises [%s]. A verb advertised "+
					"but not served sends an integrator off to write a request that 405s; a verb "+
					"served but not advertised hides working functionality behind the one response "+
					"whose whole job is to say what to use instead.",
					where, sortedVerbs(verbs), sortedVerbs(claimed))
			}
			return true
		})

		for pos := range sites {
			t.Errorf("%s: this 405 is not inside a guard this test recognises — neither an `if "+
				"r.Method != http.MethodX` chain nor the default of a `switch r.Method`. It is "+
				"reported rather than skipped, because an unrecognised guard is where a wrong Allow "+
				"header would survive. Either reshape the guard or teach verbsFromCond the new shape.",
				fset.Position(pos))
		}
	}
}

// The check above is only as wide as allowSourceFiles, and that list is hand-written. A new
// handler file with a method guard in it would be checked by nothing at all, and nothing about the
// passing test would say so — the failure mode of a list is that it looks complete. So the list is
// derived against the directory: any non-test file in this package that refuses a method has to be
// named above.
func TestNoOther405SitesEscapeTheCheck(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	known := map[string]bool{}
	for _, name := range allowSourceFiles {
		known[name] = true
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || known[name] || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src := readGoSource(t, name)
		if strings.Contains(src, "StatusMethodNotAllowed") || strings.Contains(src, "WriteMethodNotAllowed") {
			t.Errorf("%s answers a request with 405 but is not in allowSourceFiles, so no test read "+
				"its Allow headers. Add it to the list.", name)
		}
	}
}
