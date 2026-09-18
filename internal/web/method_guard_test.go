package web

// method_allow_test.go proves that every 405 in this package advertises the verbs its own guard
// admits. It cannot prove the other half, and the other half is the one that went wrong: a
// handler with no guard has no 405 to check, so it is not a mismatch to be found — it is an
// absence, and a walk that starts from the 405s goes straight past it. Seven handlers here were
// in exactly that state, five of them mutating; one emptied the whole DNS cache on a bare GET.
//
// So this test starts from the mux instead. It reads every route registration in the package,
// follows the handler expression through its wrappers to the functions that actually run, and
// requires that something along that path both reads r.Method and refuses at least one verb.
// What it demands is a decision; which verbs belong in the Allow header is the other test's
// question. Together they say: every route decides, and every refusal names the alternative.
//
// Two limits, stated rather than hidden. The REST API's routes are registered inside
// internal/api by ws.api.RegisterRoutes(mux) and are invisible to a walk of this package's
// source; they are probed behaviourally, verb by verb, in internal/api/router_test.go, which is
// the stronger check and is possible there because none of those routes dial anything. And a
// function that read r.Method for some unrelated reason and answered 405 for another would
// satisfy this test without guarding anything — no such shape exists here, and the Allow-header
// test would catch it if one appeared.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// guardExemptions are registered patterns whose method decision provably lives outside this
// package, with the reason it does. The list is checked against the routes actually found, so an
// exemption whose route is gone fails rather than lingering as permission nobody needs.
var guardExemptions = map[string]string{
	"/dns-query": "ws.dohHandler is built in internal/core/dns. Its switch on r.Method and the " +
		"Allow: GET, POST it sets live in doh.go — RFC 8484 defines exactly those two verbs — and " +
		"are covered by that package's own tests.",
}

// minRegisteredRoutes is a floor under the walk itself. There were 32 registrations when this
// was written; if a refactor moves the mux somewhere this parse cannot see, the loop below would
// find nothing to check and pass in silence, which is the failure mode every source-reading test
// has to answer for.
const minRegisteredRoutes = 20

// answers405 reports whether anything inside n refuses a method. It reuses the same two shapes
// method_allow_test.go recognises, so the two tests cannot disagree about what a refusal is.
func answers405(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if found {
			return false
		}
		if call, ok := x.(*ast.CallExpr); ok && isNotAllowedCall(call) {
			found = true
		}
		return !found
	})
	return found
}

// readsRequestMethod reports whether anything inside n looks at r.Method — the other half of
// "there is a guard here". A 405 with no read of the method would be a refusal for some other
// reason; a read with no 405 would be a branch that serves every verb anyway.
func readsRequestMethod(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if found {
			return false
		}
		if e, ok := x.(ast.Expr); ok && isRequestMethod(e) {
			found = true
		}
		return !found
	})
	return found
}

// calledNames is every function or method name invoked inside n, by last identifier. That is
// enough to walk from a wrapper to the thing it wraps, which is how a guard that lives one hop
// away — requireAuthStream's, for instance — is credited to the route that goes through it.
func calledNames(n ast.Node) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			out[fn.Name] = true
		case *ast.SelectorExpr:
			out[fn.Sel.Name] = true
		}
		return true
	})
	return out
}

// guardIndex is the package read once: every declared function by name, every local variable's
// assigned expression, the call graph between them, and the resolved answer to "does going
// through this name mean a method was checked".
//
// Names are flattened across receivers, so two methods of the same name on different types would
// merge. Nothing in this package does that, and the consequence of the simplification would be a
// route wrongly credited with a guard rather than a route wrongly failed — worth saying out loud,
// since a completeness test that can be fooled is worth less than it looks.
type guardIndex struct {
	locals map[string]ast.Expr
	calls  map[string]map[string]bool
	guards map[string]bool
}

func newGuardIndex(files []*ast.File) *guardIndex {
	idx := &guardIndex{
		locals: map[string]ast.Expr{},
		calls:  map[string]map[string]bool{},
		guards: map[string]bool{},
	}

	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			// A guard inside a returned closure counts: that is where a middleware's check
			// necessarily sits, and the whole body is searched so it is found there too.
			if readsRequestMethod(fn.Body) && answers405(fn.Body) {
				idx.guards[name] = true
			}
			idx.calls[name] = calledNames(fn.Body)
		}

		// Local assignments, flattened without regard to scope. This exists for one shape —
		// `spaHandler := http.HandlerFunc(func(...))` and then `mux.Handle("/", spaHandler)` —
		// where the handler is a literal bound to a name before it is registered.
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				idx.locals[id.Name] = as.Rhs[0]
			}
			return true
		})
	}

	idx.propagate()
	return idx
}

// propagate credits a function with a guard when something it calls has one, to a fixed point.
// requireAuthStream is why: it checks nothing itself, it returns authGate(streamGetOnly(next)),
// and the check is in streamGetOnly. Without this the two SSE routes would read as unguarded.
func (idx *guardIndex) propagate() {
	for changed := true; changed; {
		changed = false
		for name, callees := range idx.calls {
			if idx.guards[name] {
				continue
			}
			for callee := range callees {
				if idx.guards[callee] {
					idx.guards[name] = true
					changed = true
					break
				}
			}
		}
	}
}

// exprGuards answers the question the test is built around: does registering this expression as a
// handler mean some verb gets refused? It credits an inline literal that guards, a named function
// that guards directly or through what it calls, and a local variable holding either.
func (idx *guardIndex) exprGuards(e ast.Expr, seen map[string]bool) bool {
	var names []string
	guarded := false

	ast.Inspect(e, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.FuncLit:
			if readsRequestMethod(t.Body) && answers405(t.Body) {
				guarded = true
			}
		case *ast.SelectorExpr:
			names = append(names, t.Sel.Name)
		case *ast.Ident:
			names = append(names, t.Name)
		}
		return !guarded
	})
	if guarded {
		return true
	}

	for _, n := range names {
		if idx.guards[n] {
			return true
		}
	}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if rhs, ok := idx.locals[n]; ok && idx.exprGuards(rhs, seen) {
			return true
		}
	}
	return false
}

// routeRegistration is one call to Handle or HandleFunc: the path it claims and the handler it
// binds there.
type routeRegistration struct {
	pattern string
	handler ast.Expr
	pos     token.Pos
}

// routeRegistrations matches on the method name rather than on the receiver, so a mux built or
// named differently is still read. A registration whose pattern is not a literal is skipped —
// none exist, and one that appeared would be reported by the floor check rather than assumed
// harmless.
func routeRegistrations(f *ast.File) []routeRegistration {
	var out []routeRegistration
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
			return true
		}
		pattern, ok := stringLit(call.Args[0])
		if !ok {
			return true
		}
		out = append(out, routeRegistration{pattern: pattern, handler: call.Args[1], pos: call.Pos()})
		return true
	})
	return out
}

// parseWebPackage parses every non-test source file in this directory, in name order so a failure
// list reads the same way twice.
func parseWebPackage(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return files
}

func TestEveryRegisteredRouteHasAMethodGuard(t *testing.T) {
	fset := token.NewFileSet()
	files := parseWebPackage(t, fset)
	idx := newGuardIndex(files)

	var routes []routeRegistration
	for _, f := range files {
		routes = append(routes, routeRegistrations(f)...)
	}
	if len(routes) < minRegisteredRoutes {
		t.Fatalf("the walk found %d route registrations and there were 32 when it was written. "+
			"Either the mux moved out of this package or the pattern this test matches on changed; "+
			"with nothing found there is nothing to check, and a test that checks nothing passes.",
			len(routes))
	}

	registered := map[string]bool{}
	for _, route := range routes {
		registered[route.pattern] = true
		if _, exempt := guardExemptions[route.pattern]; exempt {
			continue
		}
		if idx.exprGuards(route.handler, map[string]bool{}) {
			continue
		}
		t.Errorf("%s: nothing on the path from the mux to the handler for %q reads r.Method, so "+
			"every verb reaches the same code. If the route is read-only it answers a POST, a PUT "+
			"and a DELETE with its payload; if it writes, a GET performs the write — and a GET is "+
			"what a prefetch, a link-preview fetcher, a stray retry and an address bar all send. "+
			"Add a guard with the verbs the handler means, or name the pattern in guardExemptions "+
			"with the reason its decision lives elsewhere.", fset.Position(route.pos), route.pattern)
	}

	for pattern := range guardExemptions {
		if !registered[pattern] {
			t.Errorf("guardExemptions excuses %q, which nothing registers any more. An exemption "+
				"outliving its route is permission held open for whatever takes the path next.",
				pattern)
		}
	}
}
