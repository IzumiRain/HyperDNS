package matcher

// The bulk-download plane: the content and patch CDNs a game store pulls its
// multi-gigabyte payloads from.
//
// This answers a question an operator asked before anyone else did — when a
// subscriber installs a 100 GB game, does that install come down the VPS uplink or
// their own line? Today it comes down the VPS, because the CDN hostnames live
// inside the same zones the game presets proxy: *.steampowered.com covers the
// store page and the depot server alike. Every byte the relay carries is a byte
// the operator pays for at VPS bandwidth prices, at whatever speed the route to a
// datacentre on another continent happens to offer.
//
// So this is a veto, not a claim. The names below are indexed into their own rule
// set, consulted between the forced-direct plane and the proxy index, and the only
// thing the switch can do is take a name *out* of the proxy path:
//
//	enabled  → nothing happens; the game preset proxies its CDN exactly as before.
//	disabled → the CDN resolves to its real address and the download goes direct.
//
// Two consequences follow from that shape, and both are why it was chosen over
// indexing these names as a proxy rule of their own:
//
//   - The switch cannot proxy anything the operator did not already ask for. With
//     "Steam & Valve" off, a Steam depot is direct whatever this is set to — there
//     is nothing to subtract from.
//   - Nothing here can be the only rule covering a name. Every domain below is
//     already inside an enabled-by-default proxy preset, which
//     TestEveryDownloadDomainIsProxiedWhenEnabled asserts. A CDN this daemon does
//     not proxy today has nothing to veto and belongs in a game preset first.
//
// Default: OFF — downloads go direct. That is the cheaper default for the operator
// and the faster one for most subscribers, and unlike the alternative it is not the
// one that quietly bills them for a game library.
//
// # The failure this can cause
//
// A subscriber whose own line cannot reach the CDN at all — a block rather than a
// throttle — does not get a slower download with this off. They get a failed one,
// and a launcher that retries forever without saying why. That is the case where
// enabling it is correct, and it is why the switch is per-client as well as global:
// the plan that needs it can have it without every plan paying for it. A client
// policy cannot turn it on when the server has it off; the operator paying for the
// bandwidth keeps the final say.
const RuleDownloads = "Game & App Downloads"

// PresetDownloads is the vetoable set: bulk payload, and only names whose sole job
// is bulk payload.
//
// A veto that strands anything else re-censors what the proxy was installed to open
// up, and the symptom — a launcher that resolves, connects and then does nothing —
// is indistinguishable from the proxy being broken. So a name earns a place here
// only if a subscriber on a censored line loses nothing but download speed by
// having it direct. Reviewed and deliberately left proxied:
//
//   - steamstatic.com, eaassets-a.akamaihd.net, blzstatic.com — storefront images
//     and library art. Small files, and precisely what the game preset was switched
//     on for.
//   - rbxcdn.com beyond setup. — per-play asset streaming, which is latency work,
//     not an install.
//   - riotcdn.net beyond dyn. — the client's own images and the web store.
//   - updates.discord.com, dl.discordapp.net — discord.com is blocked in Iran and a
//     client that cannot reach its updater refuses to launch, so a veto there breaks
//     the application rather than slowing a download.
//   - ttvnw.net, jtvnw.net, twitchcdn.net, scdn.co, sndcdn.com — for a streaming
//     service the CDN is the product. There is no install to separate out.
//   - steamcdn-a.akamaihd.net, blzddist1-a.akamaihd.net, ubistatic-a.akamaihd.net,
//     *.dl.delivery.mp.microsoft.com — no preset proxies these today, so there is
//     nothing to subtract. If one is added to a game preset, add it here in the same
//     commit.
var PresetDownloads = []string{
	// Steam — SteamPipe depot content and Workshop payloads. Both zones are
	// covered by PresetSteam's wildcards, and neither serves anything the store
	// needs in order to open.
	"steamcontent.com",
	"*.steamcontent.com",
	"steamusercontent-a.akamaihd.net",
	"*.steamusercontent-a.akamaihd.net",

	// Epic Games Launcher — chunked installs and patches. The numbered hosts are
	// separate names rather than a wildcard because download*.epicgames.com sits
	// beside ol., account. and tracking., which carry login and entitlement.
	"download.epicgames.com",
	"download2.epicgames.com",
	"download3.epicgames.com",
	"download4.epicgames.com",
	"fastly-download.epicgames.com",
	"epicgames-download.akamaized.net",
	"*.epicgames-download.akamaized.net",
	"epicgames-download1.akamaized.net",
	"*.epicgames-download1.akamaized.net",

	// Xbox app and Microsoft Store game payloads. All under xboxlive.com, which
	// PresetXbox wildcards; the sign-in, presence and title services live on other
	// hosts in that zone and stay proxied.
	"dlassets.xboxlive.com",
	"dlassets-ssl.xboxlive.com",
	"assets1.xboxlive.com",
	"assets2.xboxlive.com",
	"d1.xboxlive.com",
	"d2.xboxlive.com",
	"xvcf1.xboxlive.com",
	"xvcf2.xboxlive.com",
	"xvcf3.xboxlive.com",

	// PlayStation Network — the whole dl. tree is package and system-software
	// delivery. PresetPlayStation already names psn.dl.playstation.net for this
	// reason; the wildcard below covers the regional gs2.ww.prod. hosts a current
	// console actually fetches from.
	"dl.playstation.net",
	"*.dl.playstation.net",

	// Battle.net — the CASC content servers. Covered by PresetBlizzard's
	// *.blizzard.com; battle.net itself, which carries login and the launcher's own
	// API, is untouched.
	"cdn.blizzard.com",
	"*.cdn.blizzard.com",
	"level3.blizzard.com",
	"edge.blizzard.com",
	"dist.blizzard.com",
	"llnw.blizzard.com",

	// Riot's patcher. Only the dynamic-content tree — dyn.riotcdn.net is where the
	// League and Valorant patchers pull their bundles from, while the rest of
	// riotcdn.net serves client art and the web store.
	"dyn.riotcdn.net",
	"*.dyn.riotcdn.net",

	// EA app / Origin install content. PresetEA lists this host explicitly, so the
	// veto has something to subtract from with the preset on.
	"origin-a.akamaihd.net",
	"*.origin-a.akamaihd.net",

	// Ubisoft Connect. static-asset-delivery.cloud.ubi.com stays proxied — that is
	// the launcher's own UI content, not the game.
	"cdn.ubi.com",
	"*.cdn.ubi.com",

	// Rockstar Games Launcher patches. Social Club, the entitlement service and
	// prod.ros.rockstargames.com all stay proxied.
	"patches.rockstargames.com",
	"*.patches.rockstargames.com",

	// Roblox client installer and version bootstrap only. Everything else under
	// rbxcdn.com is the per-play asset stream.
	"setup.rbxcdn.com",
	"*.setup.rbxcdn.com",

	// GOG Galaxy installers, under the gog.com wildcard PresetPlatformsExtra owns.
	"cdn.gog.com",
	"*.cdn.gog.com",
}
