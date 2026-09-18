package web

import (
	"net/http"
	"strconv"
	"strings"
)

// The subscriber portal is the one page in this project a customer sees, and the two
// things it could not do until now were speak English and render in light. Both were
// blocked by the same fact: every string on it was a Persian literal inside the two
// template constants, and the page has no JavaScript it can rely on — the error page
// deliberately carries no <script> at all, because a portal that cannot report a bad
// token without scripting is a portal that reports nothing to the person most likely
// to have scripting off. So the language and the theme are both resolved on the
// server, before the template runs, and every literal moved in here.
//
// Persian stays the default. That is not sentiment: internal/web/portal_test.go builds
// every request with nothing but a RemoteAddr — no Accept-Language, no cookie, no
// query — and asserts Persian in the rendered body, which is the encoded form of the
// real audience. English is what a request asks for, never what it gets by accident.

const (
	portalLangFa = "fa"
	portalLangEn = "en"

	portalThemeDark  = "dark"
	portalThemeLight = "light"

	// Both preferences are stored client-side and read back on the next visit. They are
	// deliberately not HttpOnly — nothing secret is in them and a future script may want
	// to read them. Secure is set only when the page was reached over TLS: a Secure
	// cookie on a plain-http panel would never be stored, silently undoing the choice on
	// every page load, so it is gated on r.TLS rather than unconditional.
	portalLangCookie  = "hdns_lang"
	portalThemeCookie = "hdns_theme"

	// A subscriber sets this once. The cookie outliving the subscription is harmless;
	// the cookie expiring inside it means the page flips language on its own.
	portalPrefMaxAge = 365 * 24 * 60 * 60
)

// portalText is every word the portal shows, in one language. Two rules hold it
// together, both checked by TestPortalTextBundlesAreCompleteAndUsed:
//
//   - no field may be empty in either bundle, and the slices must be the same length in
//     both. A missing translation on this page is not a blank — it is a step of a DNS
//     setup guide that silently is not there, which is worse than the English original.
//   - purely technical strings are NOT here. "Primary DNS (IPv4)", "DNS over TLS (DoT)"
//     and the address values themselves stay literal in the template, because they are
//     the same in both languages and a translated copy of each is one more thing to
//     drift.
type portalText struct {
	// Page chrome.
	DocTitle    string // <title> of the portal page
	ErrDocTitle string // <title> of the error page
	// Subtitle is the line under the brand heading. It names the product and the
	// engine, with the running version templated in at render time so a released
	// build never advertises a stale one. The heading itself is the operator's own
	// Title from the subscription settings (see portalData.Title), not a translated
	// string — a reseller's brand is the same in every language they sell in.
	Subtitle     string
	PillActive   string
	ThemeToLight string // label of the link that switches TO light
	ThemeToDark  string // label of the link that switches TO dark
	ThemeHint    string // title/aria-label on the theme link
	LangHint     string // title/aria-label on the language link

	// What just happened, shown as the line under the topbar or on the error card.
	StatusRegistered string
	StatusConfirmed  string
	StatusPreview    string
	ErrExpiredTitle  string
	ErrExpiredNote   string
	ErrInvalidTitle  string
	ErrInvalidNote   string
	ErrIPLabel       string

	// Identity card.
	CardIdentity string
	LabelAccount string
	LabelUUID    string
	CopiedUUID   string
	BtnCopy      string

	// IP card.
	CardIPStatus    string
	PillBound       string
	LabelDetectedIP string
	HintModem       string

	// Traffic card. WordRemaining, Unlimited, LifetimeLabel and the three cycle names are
	// formatted in Go rather than in the template, because each is glued to a number.
	CardTraffic    string
	LabelRemaining string
	LabelAutoRenew string
	PillQuotaSpent string
	WordRemaining  string
	Unlimited      string
	LifetimeLabel  string
	CycleDaily     string
	CycleWeekly    string
	CycleMonthly   string

	// Countdown card.
	CardCountdown string
	UnitDays      string
	UnitHours     string
	UnitMins      string
	LabelEndDate  string

	// Policies card.
	CardPolicies string
	PolicyAll    string

	// Endpoints card.
	CardEndpoints   string
	HintTapCopy     string
	CopiedPrimary   string
	CopiedSecondary string
	CopiedDoH       string
	CopiedDoT       string

	// Setup guide. One slice per device, one element per numbered step; the DNS values
	// live in a .snippet block after the list rather than mid-sentence, which is what
	// lets a step be a plain translatable string and keeps every address LTR-isolated
	// and copy-shaped instead of buried in prose.
	CardGuide      string
	GuideArrowNote string
	GuideTabsAria  string
	TabPs          string
	TabXbox        string
	TabSwitch      string
	TabWindows     string
	TabApple       string
	TabAndroid     string
	TabRouter      string

	PsTitle     string
	PsSteps     []string
	XboxTitle   string
	XboxSteps   []string
	SwitchTitle string
	SwitchSteps []string
	WinTitle    string
	WinSteps    []string
	RouterTitle string
	RouterSteps []string

	// Apple and Android are two platforms each, not two ordered procedures, so they read
	// as paragraphs. Android's first line is the one that matters: Private DNS takes a
	// hostname and refuses an IP address, and the old markup offered it "<server>:853",
	// which cannot work on any Android device at all.
	AppleTitle     string
	ApplePhone     string
	AppleMac       string
	AndroidTitle   string
	AndroidPrivate string
	// AndroidNoDomain replaces the hostname snippet when no domain is configured.
	// Android's Private DNS field rejects an IP address, so printing one there
	// would be an instruction that cannot be followed.
	AndroidNoDomain string
	AndroidStatic   string

	// The four strings js/portal.js shows. They are bundle fields rather than literals
	// inside the script for the same reason the rest of this file exists — the script is
	// one file served to a Persian and an English reader alike, and it cannot ask the
	// server which one it is talking to. The template renders them onto data- attributes
	// (#toast and #traffic-remaining) and the script reads them back, so there is one
	// spelling of each message and it is chosen by the same negotiation as the page.
	//
	// WordRemaining and Unlimited above are deliberately *not* duplicated here: the
	// script re-renders the traffic figures after a sync, and reusing the very fields Go
	// used for the first paint is what stops the wording changing under the subscriber
	// when they press the button.
	MsgCopied   string
	MsgCopyFail string

	// The register card (Phase B): where the subscriber pastes the
	// out-of-band secret and presses the one write the portal still offers.
	CardRegister      string
	LabelSecret       string
	PlaceholderSecret string
	BtnRegister       string
	HintSecret        string
	MsgRegisterOK     string
	MsgRegisterFail   string
	MsgRegisterDenied string
	// One line per machine-readable `reason` the registration API can return.
	// The portal is bilingual and the API answers in English, so these are what
	// the subscriber actually reads when a bind is refused: telling someone with
	// a lapsed plan that their secret was wrong sends them to the wrong problem.
	MsgRegisterSuspended string
	MsgRegisterExpired   string
	MsgRegisterQuota     string
	MsgRegisterConflict  string
	StatusOverview       string
}

// portalFa is the default bundle. Where a term is one an operator will also read in
// English inside a console menu — Account Name, Detected IP, Days — it is kept
// alongside the Persian rather than replaced by it, because the subscriber is about to
// go looking for that exact English word in a PlayStation settings screen.
var portalFa = portalText{
	DocTitle:     "اشتراک هوشمند",
	ErrDocTitle:  "خطا در اشتراک",
	Subtitle:     "HyperDNS %s • سرویس دامنه‌شکن کم‌تأخیر",
	PillActive:   "فعال",
	ThemeToLight: "حالت روشن",
	ThemeToDark:  "حالت تیره",
	ThemeHint:    "تغییر پوستهٔ روشن/تیره",
	LangHint:     "Switch this page to English",

	StatusRegistered: "آی‌پی جدید شما با موفقیت ثبت و همگام شد!",
	StatusConfirmed:  "آی‌پی شما تأیید شد و اشتراک فعال است.",
	StatusPreview: "این لینک توسط پیش‌نمایش پیام‌رسان یا مرورگر باز شده و آی‌پی شما ثبت نشد. " +
		"برای اتصال، دکمهٔ «بروزرسانی آی‌پی من» را در بالای همین صفحه بزنید.",
	ErrExpiredTitle: "اعتبار اشتراک شما به پایان رسیده است",
	ErrExpiredNote:  "Your subscription plan has expired. Please contact support.",
	ErrInvalidTitle: "لینک اشتراک نامعتبر است",
	ErrInvalidNote:  "Invalid or unknown subscription token.",
	ErrIPLabel:      "آی‌پی شناسایی‌شده شما:",

	CardIdentity: "مشخصات اشتراک",
	LabelAccount: "نام کاربر (Account Name):",
	LabelUUID:    "شناسه UUID:",
	CopiedUUID:   "UUID کپی شد!",
	BtnCopy:      "کپی",

	CardIPStatus:    "وضعیت اتصال آی‌پی (IP Status)",
	PillBound:       "ثبت شده",
	LabelDetectedIP: "آی‌پی شناسایی‌شده (Detected IP):",
	HintModem: "هر بار که مودم یا اینترنت شما قطع و وصل شود، آی‌پی عوض می‌شود. " +
		"در آن صورت کافی است همین صفحه را باز کنید و دکمهٔ «بروزرسانی آی‌پی من» را بزنید.",

	CardTraffic:    "مصرف ترافیک (Traffic Usage)",
	LabelRemaining: "حجم باقیمانده:",
	LabelAutoRenew: "تمدید خودکار حجم",
	PillQuotaSpent: "حجم مصرفی این دوره به پایان رسیده است",
	WordRemaining:  "باقیمانده",
	Unlimited:      "نامحدود (Unlimited)",
	LifetimeLabel:  "نامحدود (Lifetime)",
	CycleDaily:     "روزانه",
	CycleWeekly:    "هفتگی",
	CycleMonthly:   "ماهانه",

	CardCountdown: "زمان باقیمانده اشتراک",
	UnitDays:      "روز (Days)",
	UnitHours:     "ساعت (Hours)",
	UnitMins:      "دقیقه (Mins)",
	LabelEndDate:  "تاریخ پایان:",

	CardPolicies: "سرویس‌ها و بازی‌های فعال روی این اشتراک:",
	PolicyAll:    "تمام بازی‌ها و سرویس‌های فعال سرور (Full Inherit)",

	CardEndpoints:   "آدرس‌های اختصاصی سرور DNS شما",
	HintTapCopy:     "روی هر آدرس بزنید تا کپی شود",
	CopiedPrimary:   "Primary DNS کپی شد!",
	CopiedSecondary: "Secondary DNS کپی شد!",
	CopiedDoH:       "لینک DoH کپی شد!",
	CopiedDoT:       "آدرس DoT کپی شد!",

	CardGuide:      "راهنمای تنظیم DNS روی دستگاه‌های مختلف",
	GuideArrowNote: "با کلیدهای ← و → هم می‌توانید بین تب‌ها جابه‌جا شوید",
	GuideTabsAria:  "راهنمای دستگاه‌ها",
	TabPs:          "PlayStation (PS4/PS5)",
	TabXbox:        "Xbox (Series / One)",
	TabSwitch:      "Nintendo Switch",
	TabWindows:     "Windows 10 / 11",
	TabApple:       "iOS و macOS",
	TabAndroid:     "Android",
	TabRouter:      "مودم و روتر",

	PsTitle: "تنظیم DNS روی PlayStation",
	PsSteps: []string{
		"از منوی Settings کنسول وارد بخش Network شوید.",
		"گزینهٔ Set Up Internet Connection را بزنید و نوع اتصال خود (Wi-Fi یا LAN) را انتخاب کنید.",
		"حالت Custom را انتخاب کنید تا تنظیمات دستی باز شود.",
		"مقدار IP Address را روی Automatic و DHCP Host Name را روی Do Not Specify بگذارید.",
		"در DNS Settings گزینهٔ Manual را انتخاب کنید و دو مقدار زیر را وارد کنید.",
		"MTU را روی Automatic و Proxy Server را روی Do Not Use بگذارید و در پایان Test Internet Connection را بزنید.",
	},
	XboxTitle: "تنظیم DNS روی Xbox",
	XboxSteps: []string{
		"دکمهٔ Xbox را بزنید و وارد Settings شوید.",
		"مسیر General ➔ Network settings ➔ Advanced settings را باز کنید.",
		"گزینهٔ DNS settings را انتخاب کرده و روی Manual بگذارید.",
		"دو مقدار زیر را به‌عنوان Primary و Secondary IPv4 DNS وارد کنید و ذخیره کنید.",
	},
	SwitchTitle: "تنظیم DNS روی Nintendo Switch",
	SwitchSteps: []string{
		"مسیر System Settings ➔ Internet ➔ Internet Settings را باز کنید.",
		"شبکهٔ وای‌فای متصل را انتخاب کنید و Change Settings را بزنید.",
		"مقدار DNS Settings را روی Manual بگذارید و دو مقدار زیر را وارد کنید.",
	},
	WinTitle: "تنظیم DNS روی ویندوز ۱۰ و ۱۱",
	WinSteps: []string{
		"وارد Settings ➔ Network & Internet شوید.",
		"روی کانکشن فعال (Wi-Fi یا Ethernet) بزنید و در بخش DNS server assignment دکمهٔ Edit را انتخاب کنید.",
		"حالت را از Automatic به Manual تغییر دهید و کلید IPv4 را روشن کنید.",
		"دو مقدار زیر را در Preferred DNS و Alternate DNS بنویسید و Save را بزنید.",
	},
	RouterTitle: "تنظیم DNS روی مودم و روتر",
	RouterSteps: []string{
		"با مرورگر وارد پنل مودم شوید (معمولاً ۱۹۲.۱۶۸.۱.۱ یا ۱۹۲.۱۶۸.۰.۱).",
		"به بخش WAN یا Internet یا DHCP بروید و گزینهٔ DNS را از Automatic به Manual/Static تغییر دهید.",
		"دو مقدار زیر را وارد کنید، ذخیره کنید و یک بار مودم را ری‌استارت کنید. از این پس همهٔ دستگاه‌های خانه بدون تنظیم جداگانه از این DNS استفاده می‌کنند.",
	},
	AppleTitle: "تنظیم DNS روی iOS و macOS",
	ApplePhone: "آیفون و آیپد: مسیر Settings ➔ Wi-Fi ➔ آیکن (i) کنار نام شبکه ➔ Configure DNS ➔ Manual را باز کنید، " +
		"همهٔ آدرس‌های قبلی را با Delete پاک کنید و با Add Server آدرس زیر را اضافه کنید.",
	AppleMac:     "مک: مسیر System Settings ➔ Network ➔ Details ➔ تب DNS را باز کنید، با دکمهٔ (+) آدرس زیر را اضافه کنید و OK را بزنید.",
	AndroidTitle: "تنظیم DNS روی اندروید",
	AndroidPrivate: "روش اول — Private DNS (پیشنهادی، رمزنگاری‌شده): مسیر Settings ➔ Network & internet ➔ Private DNS را باز کنید، " +
		"گزینهٔ «Private DNS provider hostname» را انتخاب کنید و نام دامنهٔ زیر را وارد کنید. " +
		"دقت کنید که این فیلد فقط نام دامنه می‌پذیرد؛ اگر سرور شما دامنه و گواهی TLS ندارد، از روش دوم استفاده کنید.",
	AndroidNoDomain: "این سرور هنوز دامنه و گواهی TLS ندارد، پس Private DNS اندروید قابل استفاده نیست " +
		"(این فیلد آدرس IP را نمی‌پذیرد). از روش دوم استفاده کنید یا از مدیر سرور بخواهید دامنه اضافه کند.",
	AndroidStatic: "روش دوم — تنظیم دستی وای‌فای: مسیر Settings ➔ Wi-Fi ➔ نگه‌داشتن نام شبکه ➔ Modify network ➔ Advanced را باز کنید، " +
		"IP settings را روی Static بگذارید و دو مقدار زیر را در DNS 1 و DNS 2 بنویسید.",

	MsgCopied: "کپی شد!",
	// Said only when the copy genuinely failed, which over plain http is the common
	// case rather than the edge one: navigator.clipboard does not exist outside a
	// secure context and execCommand can be refused. The instruction is the useful
	// half of the message — the subscriber can still select the text by hand.
	MsgCopyFail: "کپی خودکار ممکن نشد — متن را دستی انتخاب کنید",

	CardRegister:         "ثبت یا بروزرسانی آی‌پی",
	LabelSecret:          "رمز ثبت (Registration Secret):",
	PlaceholderSecret:    "رمز ثبت خود را اینجا وارد کنید",
	BtnRegister:          "ثبت آی‌پی من",
	HintSecret:           "رمز ثبت را اپراتور شما هنگام فروش اشتراک تحویل داده است. با هر بار رزرو مودم، همین صفحه را باز کنید، رمز را وارد کنید و دکمه را بزنید.",
	MsgRegisterOK:        "آی‌پی جدید با موفقیت ثبت شد!",
	MsgRegisterFail:      "ثبت آی‌پی ناموفق بود — رمز و آدرس را بررسی کنید.",
	MsgRegisterDenied:    "رمز ثبت اشتباه است یا لینک نامعتبر است.",
	MsgRegisterSuspended: "این اشتراک توسط اپراتور غیرفعال شده است. با پشتیبانی تماس بگیرید.",
	MsgRegisterExpired:   "این اشتراک منقضی شده است. برای تمدید با پشتیبانی تماس بگیرید.",
	MsgRegisterQuota:     "حجم این اشتراک به پایان رسیده است. برای شارژ با پشتیبانی تماس بگیرید.",
	MsgRegisterConflict:  "این آی‌پی قبلاً برای اشتراک دیگری ثبت شده است. با پشتیبانی تماس بگیرید.",
	StatusOverview:       "این صفحه نمای کلی اشتراک شماست؛ آی‌پی شناسایی‌شده‌ی شما در پایین نمایش داده شده است.",
}

// portalEn is what a request has to ask for. The console menu names are the same strings
// as in portalFa on purpose — they are what is printed on the device, not prose.
var portalEn = portalText{
	DocTitle:     "Smart Subscription",
	ErrDocTitle:  "Subscription Error",
	Subtitle:     "HyperDNS %s • Low-Latency SmartDNS Engine",
	PillActive:   "ACTIVE",
	ThemeToLight: "Light mode",
	ThemeToDark:  "Dark mode",
	ThemeHint:    "Switch between light and dark",
	LangHint:     "نمایش این صفحه به فارسی",

	StatusRegistered: "Your new IP address has been registered and synced.",
	StatusConfirmed:  "Your IP address is confirmed and the subscription is active.",
	StatusPreview: "This link was opened by a messenger or browser preview, so your IP was not registered. " +
		"To connect, press the “Update my IP” button at the top of this page.",
	ErrExpiredTitle: "Your subscription has expired",
	ErrExpiredNote:  "Your subscription plan has expired. Please contact support.",
	ErrInvalidTitle: "This subscription link is not valid",
	ErrInvalidNote:  "Invalid or unknown subscription token.",
	ErrIPLabel:      "Your detected IP address:",

	CardIdentity: "Subscription details",
	LabelAccount: "Account name:",
	LabelUUID:    "UUID:",
	CopiedUUID:   "UUID copied.",
	BtnCopy:      "Copy",

	CardIPStatus:    "IP status",
	PillBound:       "Registered",
	LabelDetectedIP: "Detected IP:",
	HintModem: "Your IP changes every time your modem or connection restarts. " +
		"When that happens, open this page again and press “Update my IP”.",

	CardTraffic:    "Traffic usage",
	LabelRemaining: "Remaining:",
	LabelAutoRenew: "Quota resets automatically",
	PillQuotaSpent: "The quota for this period is used up",
	WordRemaining:  "remaining",
	Unlimited:      "Unlimited",
	LifetimeLabel:  "Lifetime",
	CycleDaily:     "daily",
	CycleWeekly:    "weekly",
	CycleMonthly:   "monthly",

	CardCountdown: "Time left on this subscription",
	UnitDays:      "Days",
	UnitHours:     "Hours",
	UnitMins:      "Mins",
	LabelEndDate:  "Expires on:",

	CardPolicies: "Games and services enabled on this subscription:",
	PolicyAll:    "Every game and service enabled on the server (Full Inherit)",

	CardEndpoints:   "Your dedicated DNS endpoints",
	HintTapCopy:     "tap any address to copy it",
	CopiedPrimary:   "Primary DNS copied.",
	CopiedSecondary: "Secondary DNS copied.",
	CopiedDoH:       "DoH URL copied.",
	CopiedDoT:       "DoT address copied.",

	CardGuide:      "How to set this DNS up on your device",
	GuideArrowNote: "you can also move between tabs with the ← and → keys",
	GuideTabsAria:  "Device setup guides",
	TabPs:          "PlayStation (PS4/PS5)",
	TabXbox:        "Xbox (Series / One)",
	TabSwitch:      "Nintendo Switch",
	TabWindows:     "Windows 10 / 11",
	TabApple:       "iOS & macOS",
	TabAndroid:     "Android",
	TabRouter:      "Modem / router",

	PsTitle: "Setting the DNS on a PlayStation",
	PsSteps: []string{
		"Open Settings on the console and go to Network.",
		"Choose Set Up Internet Connection and pick how you connect (Wi-Fi or LAN).",
		"Choose Custom so the manual settings appear.",
		"Leave IP Address on Automatic and DHCP Host Name on Do Not Specify.",
		"Under DNS Settings choose Manual and enter the two values below.",
		"Leave MTU on Automatic and Proxy Server on Do Not Use, then run Test Internet Connection.",
	},
	XboxTitle: "Setting the DNS on an Xbox",
	XboxSteps: []string{
		"Press the Xbox button and open Settings.",
		"Go to General ➔ Network settings ➔ Advanced settings.",
		"Open DNS settings and switch it to Manual.",
		"Enter the two values below as the primary and secondary IPv4 DNS, then save.",
	},
	SwitchTitle: "Setting the DNS on a Nintendo Switch",
	SwitchSteps: []string{
		"Go to System Settings ➔ Internet ➔ Internet Settings.",
		"Select the Wi-Fi network you are on and choose Change Settings.",
		"Set DNS Settings to Manual and enter the two values below.",
	},
	WinTitle: "Setting the DNS on Windows 10 / 11",
	WinSteps: []string{
		"Open Settings ➔ Network & Internet.",
		"Click the connection you are using (Wi-Fi or Ethernet) and press Edit next to DNS server assignment.",
		"Change Automatic to Manual and turn the IPv4 switch on.",
		"Enter the two values below as Preferred DNS and Alternate DNS, then press Save.",
	},
	RouterTitle: "Setting the DNS on a modem or router",
	RouterSteps: []string{
		"Open your modem's admin page in a browser (usually 192.168.1.1 or 192.168.0.1).",
		"Find the WAN, Internet or DHCP section and change DNS from Automatic to Manual/Static.",
		"Enter the two values below, save, and restart the modem once. Every device in the house then uses this DNS with no setup of its own.",
	},
	AppleTitle: "Setting the DNS on iOS and macOS",
	ApplePhone: "iPhone and iPad: go to Settings ➔ Wi-Fi ➔ the (i) icon next to your network ➔ Configure DNS ➔ Manual, " +
		"delete the addresses already listed, then use Add Server to add the address below.",
	AppleMac:     "Mac: go to System Settings ➔ Network ➔ Details ➔ the DNS tab, add the address below with the (+) button, and press OK.",
	AndroidTitle: "Setting the DNS on Android",
	AndroidPrivate: "Option 1 — Private DNS (recommended, encrypted): go to Settings ➔ Network & internet ➔ Private DNS, " +
		"choose “Private DNS provider hostname” and enter the hostname below. " +
		"This field accepts a domain name only, so if your server has no domain and TLS certificate, use option 2 instead.",
	AndroidNoDomain: "This server has no domain and TLS certificate yet, so Android's Private DNS " +
		"cannot be used (the field will not accept an IP address). Use option 2 below, or ask " +
		"the server administrator to add a domain.",
	AndroidStatic: "Option 2 — static Wi-Fi settings: go to Settings ➔ Wi-Fi ➔ long-press your network ➔ Modify network ➔ Advanced, " +
		"set IP settings to Static and enter the two values below as DNS 1 and DNS 2.",

	MsgCopied:   "Copied.",
	MsgCopyFail: "Could not copy automatically — please select the text by hand.",

	CardRegister:         "Register or update your IP",
	LabelSecret:          "Registration secret:",
	PlaceholderSecret:    "Paste your registration secret here",
	BtnRegister:          "Register my IP",
	HintSecret:           "Your provider handed you the registration secret when you bought the plan. After a modem reset, open this page, paste the secret, and press the button.",
	MsgRegisterOK:        "Your new IP address was registered!",
	MsgRegisterFail:      "Registration failed — check the secret and try again.",
	MsgRegisterDenied:    "Wrong registration secret, or an invalid link.",
	MsgRegisterSuspended: "This subscription has been suspended by the operator. Please contact support.",
	MsgRegisterExpired:   "This subscription has expired. Please contact support to renew it.",
	MsgRegisterQuota:     "This subscription's traffic allowance is used up. Please contact support to top it up.",
	MsgRegisterConflict:  "This IP address is already registered to a different subscription. Please contact support.",
	StatusOverview:       "This is your subscription overview; the address this device was seen from is shown below.",
}

// portalBundle resolves a language code to its strings. Anything unrecognised is Persian,
// which is the same rule as the negotiation below and keeps a corrupted cookie from
// rendering a page with no words on it.
func portalBundle(lang string) portalText {
	if lang == portalLangEn {
		return portalEn
	}
	return portalFa
}

// portalStatus is what the handler worked out actually happened, kept as a value rather
// than a sentence so the handler never touches a translated string. Two of the five render
// the error card instead of the portal.
type portalStatus int

const (
	portalStatusRegistered portalStatus = iota // a new address was bound
	portalStatusConfirmed                      // the address was already the bound one
	portalStatusPreview                        // an unfurler opened the link; nothing was bound
	portalStatusExpired                        // the subscription is over
	portalStatusInvalid                        // no such token
	// portalStatusOverview is the read-only portal (Phase B): the page rendered
	// without any binding having happened, which is now the normal case for
	// every visit to /sub/<token>.
	portalStatusOverview
)

// ok reports whether this status renders the portal. The preview counts: the record was
// read, everything on the page is real, and only the binding did not happen.
func (s portalStatus) ok() bool {
	return s == portalStatusRegistered || s == portalStatusConfirmed || s == portalStatusPreview || s == portalStatusOverview
}

// warn reports whether the status line should be marked as a caveat rather than a success.
// It selects between two literal icon branches in the template, because a class attribute
// on this page may not contain a template action.
func (s portalStatus) warn() bool { return s == portalStatusPreview }

// httpStatus is the HTTP status the page carries. An unknown token answered
// 200 for its whole life — a friendly error page wearing a success code —
// which reads as "resource exists" to every prober, prefetcher and cache, and
// is what the T3MP3ST external-attacker pass flagged. The body stays the
// friendly error card; only the status tells the truth now: 404 for a token
// that does not exist, 410 for a plan that is over.
func (s portalStatus) httpStatus() int {
	switch s {
	case portalStatusExpired:
		return http.StatusGone
	case portalStatusInvalid:
		return http.StatusNotFound
	default:
		return http.StatusOK
	}
}

// line is the sentence under the topbar. It used to be computed in the handler and then
// dropped on the floor — the template rendered a fixed heading and never read it — so the
// difference between "your new address is registered" and "your address was already the
// registered one" reached nobody.
func (s portalStatus) line(t portalText) string {
	switch s {
	case portalStatusConfirmed:
		return t.StatusConfirmed
	case portalStatusPreview:
		return t.StatusPreview
	case portalStatusOverview:
		return t.StatusOverview
	default:
		return t.StatusRegistered
	}
}

// errText is the headline and the second line of the error card.
func (s portalStatus) errText(t portalText) (title, note string) {
	if s == portalStatusExpired {
		return t.ErrExpiredTitle, t.ErrExpiredNote
	}
	return t.ErrInvalidTitle, t.ErrInvalidNote
}

// portalDir is the writing direction that goes with a language. It ends up on <html>,
// where it drives both the layout and the arrow keys in js/portal.js.
func portalDir(lang string) string {
	if lang == portalLangEn {
		return "ltr"
	}
	return "rtl"
}

// portalPref reads one preference in the order query → cookie → default, and stores the
// query form so the choice survives the next visit. A link, not a form: the query param
// is what makes both toggles work with JavaScript disabled, which the error page needs
// because it has no script at all.
func portalPref(w http.ResponseWriter, r *http.Request, param, cookie string, valid func(string) bool, def string) string {
	if v := r.URL.Query().Get(param); valid(v) {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie,
			Value:    v,
			Path:     "/",
			MaxAge:   portalPrefMaxAge,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
		return v
	}
	if c, err := r.Cookie(cookie); err == nil && valid(c.Value) {
		return c.Value
	}
	return def
}

// negotiatePortalLang picks the page language: ?lang= wins, then the stored choice, then
// the browser's own preference, then Persian.
func negotiatePortalLang(w http.ResponseWriter, r *http.Request) string {
	isLang := func(v string) bool { return v == portalLangFa || v == portalLangEn }
	if lang := portalPref(w, r, "lang", portalLangCookie, isLang, ""); lang != "" {
		return lang
	}
	if prefersEnglishOverPersian(r.Header.Get("Accept-Language")) {
		return portalLangEn
	}
	return portalLangFa
}

// negotiatePortalTheme picks the palette: ?theme= wins, then the stored choice, then dark.
//
// There is deliberately no third "auto" state that follows prefers-color-scheme. Honouring
// the OS would mean a second copy of all 25 colour tokens inside a media query — the same
// palette written twice, with nothing keeping the two in step — and it would make the
// toggle's own label unanswerable: with no script on the error page, the server cannot know
// which way "auto" resolved, so a link saying "Light mode" would sometimes point at the
// palette already on screen. Two states, both explicit, both always correctly labelled.
func negotiatePortalTheme(w http.ResponseWriter, r *http.Request) string {
	isTheme := func(v string) bool { return v == portalThemeDark || v == portalThemeLight }
	return portalPref(w, r, "theme", portalThemeCookie, isTheme, portalThemeDark)
}

// prefersEnglishOverPersian reads Accept-Language and reports whether English outranks
// Persian in it. Quality values are parsed rather than assumed from order, because
// "en;q=0.5, fa;q=0.9" and "fa;q=0.5, en;q=0.9" are listed the same way round and mean
// opposite things. A header naming neither language, or ranking them equally, leaves the
// Persian default in place.
func prefersEnglishOverPersian(header string) bool {
	faQ, enQ := -1.0, -1.0
	for part := range strings.SplitSeq(header, ",") {
		tag, params, hasParams := strings.Cut(part, ";")
		q := 1.0
		if hasParams {
			trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(params)), "q=")
			if v, err := strconv.ParseFloat(trimmed, 64); err == nil {
				q = v
			}
		}
		primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
		switch primary {
		case portalLangFa:
			faQ = max(faQ, q)
		case portalLangEn:
			enQ = max(enQ, q)
		}
	}
	return enQ > faQ
}
