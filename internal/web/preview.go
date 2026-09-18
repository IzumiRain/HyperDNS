// Link-preview and prefetch detection for the two portal routes whose GET is a
// write. See isLinkPreviewFetch.
package web

import (
	"net/http"
	"strings"
)

// prefetchIntentHeaders are the request headers a client uses to say "this fetch is
// speculative, not a navigation". Sec-Purpose is the standardised one; the other
// three are what Chrome, Safari and Firefox sent before it and still send.
var prefetchIntentHeaders = [...]string{"Sec-Purpose", "Purpose", "X-Purpose", "X-Moz"}

var prefetchIntents = [...]string{"prefetch", "prerender", "preview", "instant"}

// previewAgents are User-Agent fragments, lower-cased, that identify a fetch made on
// somebody's behalf rather than by them: a messenger unfurling a pasted link, a
// search crawler, an SEO scanner.
//
// The list is deliberately specific at the top and only cautiously generic at the
// bottom. "+http" and "bot/" are in it because a well-behaved crawler puts a contact
// URL or a versioned bot name in its agent string and no mobile browser does; "curl"
// and "wget" are deliberately absent, because a subscriber's router script binding
// its new address is exactly the caller this must not suppress.
var previewAgents = []string{
	"telegrambot", "whatsapp", "facebookexternalhit", "facebot", "twitterbot",
	"slackbot", "slack-imgproxy", "discordbot", "skypeuripreview", "linkedinbot",
	"vkshare", "redditbot", "pinterest", "embedly", "quora link preview",
	"nuzzel", "viber", "bitlybot", "applebot", "googlebot", "bingbot",
	"yandexbot", "duckduckbot", "baiduspider", "petalbot", "semrushbot",
	"ahrefsbot", "mj12bot", "dotbot", "seznambot", "gptbot", "claudebot",
	"crawler", "spider", "unfurl", "linkpreview", "urlpreview", "bot/", "+http",
}

// isLinkPreviewFetch reports whether a request looks like it was made *about* a
// subscription link rather than *by* the subscriber holding it.
//
// Opening a /sub/ link is a write: it re-binds the account's one allowed address to
// whoever asked. That is the entire value of the link to a subscriber whose home IP
// just changed, and a defect for every other kind of fetch. Paste the link into a
// group chat and the messenger's unfurler takes the subscription; hover it in a
// browser that prefetches and the same thing happens from the subscriber's own
// machine but with no page ever shown. Either way their DNS stops answering, they did
// nothing wrong, and nothing tells them why.
//
// The method guard on those routes does not help — these are ordinary GETs, and the
// crawler is not misrepresenting itself. What is left is what the fetch says about
// itself, which is advisory: this returns a guess. So a suppressed fetch still
// renders the real page and says the address was not registered, because the sync
// button on it always registers (see handleSubDataAPI). A misjudged browser therefore
// costs one click; a missed crawler costs a subscription until the next visit.
func isLinkPreviewFetch(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, name := range prefetchIntentHeaders {
		v := strings.ToLower(r.Header.Get(name))
		if v == "" {
			continue
		}
		for _, intent := range prefetchIntents {
			if strings.Contains(v, intent) {
				return true
			}
		}
	}

	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		// Not treated as a preview. A browser always sends one, but so does every
		// crawler in the list above — and a bare HTTP client that sends none is far more
		// likely to be a subscriber's own router script asking for this registration.
		return false
	}
	for _, fragment := range previewAgents {
		if strings.Contains(ua, fragment) {
			return true
		}
	}
	return false
}
