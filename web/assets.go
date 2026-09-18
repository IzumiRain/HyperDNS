package web

import "embed"

// The asset list is written out file by file rather than as css/* js/*, and the
// reason is not tidiness. The wildcard form compiled every file that happened to
// be sitting in those directories into the binary, and one of them —
// css/tailwind.min.css, 2.9 MB — is a Tailwind v2.2.19 build that this dashboard
// cannot use at all: v2 has no slate palette, so every bg-slate-*, text-slate-*
// and border-slate-* class in index.html would be undefined by it. Nothing links
// it, nothing can link it, and it was still shipped inside every binary and
// written to every VPS.
//
// Naming each file makes that class of mistake impossible to repeat quietly: a new
// asset has to be added here to be served, and a stale one stops being carried the
// moment it is dropped from the list. The build fails loudly if a named file is
// missing, which is the failure mode to want — an asset silently absent from the
// binary is a dashboard that half-renders in production.
//
// css/portal.css and js/portal.js are the subscriber portal's two assets. They are
// separate from the dashboard's pair on purpose: the portal is the page a reseller's
// customer opens on a phone, and it must not pay for the dashboard's 407 KB Tailwind
// JIT engine, its charts, or its icon set. Note what happens if either line is
// dropped — the portal keeps rendering, unstyled and inert, because a missing
// stylesheet is not an error to a browser. That is why they are listed here and
// pinned by portal_assets_test.go rather than left to a wildcard.
//
// fonts/ carries the two self-hosted webfont files. They must be named here for the
// same reason as everything else — an asset absent from the binary is not an error the
// browser reports, it is a panel that quietly renders in Tahoma — but note the file
// names as well. Upstream ships both variable fonts with the axis in brackets —
// "Vazirmatn[wght].woff2" — and an embed pattern is matched with path.Match, where [
// opens a character class, so the literal names cannot be embedded without renaming
// them. Hence the -var.woff2 suffix on both.
//
// The two LICENSE-*.txt beside them are not embedded. The OFL requires the licence to
// travel with the font, and it does — in the repository, next to the files it covers —
// but nothing serves it, so there is no reason to carry 9 KB of licence text in every
// binary and write it to every VPS.
//
// js/i18n.js is the dashboard's Persian translation table and theme controller. It is
// listed after js/app.js because that is also the order the two <script> tags appear in,
// and the order matters: i18n.js calls window.safeFeatherReplace(), which app.js defines.
// Dropping this line does not break the panel — it silently reverts to English-only with
// a theme toggle that does nothing, which is precisely the kind of quiet regression the
// explicit list exists to prevent.
//
// login.html is the standalone sign-in document (v2.1.0 Phase A). It is served at
// /<admin-path>/login with the namespace spliced in at serve time, and it replaces the
// old practice of handing the full dashboard shell to unauthenticated visitors.

//go:embed index.html
//go:embed login.html
//go:embed css/tailwind.purged.css
//go:embed css/style.css
//go:embed css/portal.css
//go:embed js/app.js
//go:embed js/i18n.js
//go:embed js/modules/twofa.js
//go:embed swagger/swagger-ui.css
//go:embed swagger/swagger-ui-bundle.js
//go:embed js/portal.js
//go:embed js/feather.min.js
//go:embed js/chart.umd.min.js
//go:embed fonts/vazirmatn-var.woff2
//go:embed fonts/jetbrains-mono-var.woff2
var StaticFS embed.FS
