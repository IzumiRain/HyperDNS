package matcher

// The forced-direct plane: names this daemon must not answer with the proxy.
//
// An ActionProxy verdict does not forward anything by itself. The DNS handler
// answers A with the VPS address and sinks AAAA to stop the IPv6 bypass
// (internal/core/dns/handler.go), and the client then opens a connection to that
// address — which only reaches the operator's proxy if the proxy happens to be
// listening on the port the client chose, and only produces a relay if the first
// bytes the client sends name the destination. internal/core/proxy/sni.go binds
// TCP and nothing else, on six ports — HTTPSPort, HTTPPort, 5223, 5222, 2099,
// 8393 — and reads the destination out of a TLS SNI extension or an HTTP Host
// header.
//
// Two ways a name can fail that, both with the same symptom:
//
//   - Wrong transport. Proxying a hostname whose real traffic is UDP does not
//     slow that traffic down, it removes it. The client is handed an address
//     where nothing answers.
//   - Wrong port, or no readable destination. A TCP service on a port outside
//     that list reaches a closed port — a refusal on a bare host, a connect
//     timeout behind the default-deny firewall every VPS ships with. A service
//     that does land on 443 but does not speak TLS has no SNI to read, so the
//     relay drops it.
//
// In every case the substitution happened in DNS, so the client cannot discover
// that the name it looked up is not the service: it resolves successfully,
// connects to a real address, and finds nothing that answers it.
//
// forcedDirectGroups lists the names for which that is known to be true, each
// with the label the query log should carry for it. They are indexed into their
// own rule set and consulted ahead of every proxy rule, so the invariant lives in
// one place that a test can assert, rather than as an absence in a thousand-line
// preset file that the next person to add a domain will never know about.
//
// A name listed here behaves exactly as it would with no rule at all, which is
// already what the matcher returns for anything it does not recognise — so adding
// to this list is the safe direction. Taking the wrong name out of it silently
// breaks a game.
//
// Reviewed and deliberately left proxied:
//
//   - *.pvp.net — League of Legends chat and the PVP.net RTM service run on
//     5222, 5223 and 2099, which the proxy does listen on.
//   - *.steamserver.net, *.demonware.net — the addresses a client sends game
//     traffic to arrive from matchmaking as literal IPs rather than through these
//     names, so proxying the names does not touch the game plane. Steam's
//     WebSocket connection managers are the exception that argues for keeping
//     them: those are real TLS on 443 under this zone, they carry SNI, and they
//     are the path a current client logs in over — see cm.steampowered.com below.
//   - router.discordapp.net — reachable over the wildcard for that zone in any
//     case, and it is the discovery call, not the media path.
type forcedDirectGroup struct {
	rule    string
	domains []string
}

var forcedDirectGroups = []forcedDirectGroup{
	{
		rule: RuleRealtimeDirect,
		domains: []string{
			// Discord voice and video: WebRTC media over UDP in the ephemeral
			// range. Removed from PresetDiscord in favour of this list.
			//
			// The wildcard also covers latency.discord.media, which is how the
			// client measures each voice region before picking one. Proxying that
			// name makes every region measure as the distance to the VPS, so the
			// client keeps selecting a region on the wrong continent even in the
			// cases where voice does eventually connect.
			"discord.media",
			"*.discord.media",

			// Vivox — the voice backend for Valorant, League of Legends, Rainbow
			// Six Siege and other Unity titles. Media is RTP over UDP. Removed
			// from PresetRiot in favour of this list, which also covers the
			// bop.vivox.com and v5.vivox.com hosts that preset named individually.
			"vivox.com",
			"*.vivox.com",
		},
	},
	{
		rule: RuleUnproxyableDirect,
		domains: []string{
			// Steam's connection manager: the client's control channel for login,
			// friends, chat and presence. Covered by *.steampowered.com in
			// PresetSteam, and the last name in the presets whose port assumption
			// was recorded as untested rather than settled.
			//
			// Settled here from this daemon's side rather than Valve's, which is
			// the half that can be checked. The connection manager is reached on
			// TCP 27017-27019 with 443 as the fallback. Nothing binds 27017-27019
			// on the VPS, so those attempts reach a closed port and cost the client
			// a connect timeout each behind any default-deny firewall; and the
			// fallback on 443 is Valve's own binary framing, not TLS, so there is
			// no SNI for the relay to read and the connection is dropped. Neither
			// outcome is the degradation the preset was assuming.
			//
			// Forcing it direct costs nothing that the operator wanted. What the
			// Steam preset is for is the store, the community pages and the CDN,
			// all HTTPS with SNI and all still proxied; and a current client does
			// not log in through this name at all — it fetches a connection-manager
			// list from api.steampowered.com over HTTPS and connects to a
			// WebSocket manager under *.steamserver.net on 443, both of which carry
			// SNI and both of which stay proxied. So the censored path to logging
			// in is untouched, and the path that this proxy cannot carry stops
			// being advertised as one it can.
			"cm.steampowered.com",

			// Google's update CDNs (v2.2.0 Google preset). *.google.com in
			// PresetGoogle unavoidably covers these subdomains, and proxying them
			// buys an operator nothing: they serve large package downloads —
			// Chrome installers, Android SDK parts — whose bytes land on the VPS
			// NIC for traffic nobody buys a subscription to unblock. gvt1/gvt2
			// are the download redirectors of the same plane. They are excluded
			// the same way Discord's voice zone is: forced direct, ahead of every
			// proxy rule, so the exclusion cannot be lost to a wildcard again.
			"dl.google.com",
			"*.dl.google.com",
			"gvt1.com",
			"*.gvt1.com",
			"gvt2.com",
			"*.gvt2.com",
		},
	},
}
