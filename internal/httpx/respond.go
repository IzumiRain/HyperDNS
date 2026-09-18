// Package httpx holds the JSON response helpers shared by the dashboard handlers
// and the REST API, so an error looks the same and parses the same whichever
// front-end produced it.
package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
)

// WriteJSONError sends a JSON error body and declares it as JSON.
//
// It replaces two habits that were spread across every handler in both packages.
//
// The first was http.Error, which sets Content-Type to text/plain — so a body that
// was JSON went out declared as text. Nothing sniffs it back, and the dashboard is
// lenient, but the response contradicted itself and a strict client was entitled to
// refuse it. Dropping http.Error also drops the X-Content-Type-Options header it
// sets, which costs nothing here: both front-ends are mounted on the mux that the
// web server's security middleware wraps, and that middleware sets nosniff on every
// response.
//
// The second was fmt.Sprintf(`{"error":"%v"}`, err). An error string containing a
// double quote, a backslash or a newline produced a body that is not JSON at all,
// so the dashboard's res.json() threw and the operator was shown a generic "the
// request failed" in place of the reason. That is not hypothetical here: the error
// text quotes operator input back — a rejected address, a refused username — and
// %q-formatted input is exactly what breaks a hand-built JSON string. Encoding the
// value instead makes the quoting the encoder's problem.
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// WriteJSONErrorFor is WriteJSONError for a Go error, with one guard: a nil error
// must not become the empty message `{"error":""}`, which reads to the dashboard as
// a failure with no reason given.
func WriteJSONErrorFor(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = errors.New("request failed")
	}
	WriteJSONError(w, status, err.Error())
}

// WriteMethodNotAllowed answers a request whose method the target endpoint has no meaning
// for, and names the methods it does accept.
//
// The Allow header is not decoration: RFC 9110 §15.5.6 requires a 405 to carry one. Without
// it the response says "not that verb" and leaves the caller to guess which verb it should
// have used — and a 405 is very often being read by someone writing an integration right now,
// who would rather be told. WriteJSONError cannot set the header itself, because it has no
// idea which endpoint it is answering for; the verbs have to come from the guard that rejected
// the request.
//
// allow is the header value verbatim: "GET, HEAD", "POST", "GET, PUT, DELETE".
func WriteMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	WriteJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
}
