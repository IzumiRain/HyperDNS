/* HyperDNS panel localisation — Persian / English.
 *
 * The dictionary is keyed on the English source text rather than on data-i18n
 * attributes, and that choice is worth defending because the obvious alternative
 * looks tidier. index.html holds 355 translatable strings and app.js builds another
 * ~200 inside template literals; tagging every one of them would mean touching some
 * 550 sites in 6,200 lines of markup and JS, and every future line of UI copy would
 * have to remember to carry a tag or it would silently stay English. Keying on the
 * source text means the markup does not change at all, a string with no entry here
 * falls back to English (which is legible, not broken), and adding a translation
 * later is one line in this file.
 *
 * The cost is that translation is a DOM pass rather than a render-time lookup. Two
 * consequences follow. First, every translated text node caches its original English
 * on the node itself (I18N_ORIG), so switching back to English restores the exact
 * source rather than trying to reverse the Persian — a reverse map would collide the
 * moment two English strings share a Persian translation, which several do here.
 * Second, this panel re-renders constantly — the query stream, the client grid, the
 * upstream list — so a MutationObserver re-translates whatever appears. The observer
 * has to ignore its own writes or it feeds itself forever; the `applying` flag is
 * that guard.
 *
 * Numbers stay Western (2.189.86.32, 8443, 12 ms). Persian-Indic digits would be
 * wrong here: an operator copies IPs and ports out of this panel into a terminal.
 */

(function () {
  'use strict';

  /* Exact matches, trimmed. Whitespace inside a node is preserved by the walker —
     only the trimmed core is looked up — so an entry never needs padding. */
  var FA = {
    /* --- shell, auth, login --- */
    'HyperDNS — Next-Gen Gaming & Anti-Sanction SmartDNS Controller':
      'HyperDNS — کنترلر هوشمند DNS برای گیم و دور زدن تحریم',
    'STANDALONE CONTROLLER': 'کنترلر مستقل',
    'ADMIN USERNAME': 'نام کاربری مدیر',
    'PASSWORD': 'رمز عبور',
    'Invalid username or password.': 'نام کاربری یا رمز عبور نادرست است.',
    'AUTHENTICATE & ACCESS': 'ورود به پنل',
    'Enter your admin password': 'رمز عبور مدیر را وارد کنید',
    'Sign Out': 'خروج',
    'ONLINE · SMARTDNS': 'آنلاین · SMARTDNS',
    'HyperDNS Smart Controller — Low-Latency SmartDNS Engine ·':
      'کنترلر هوشمند HyperDNS — موتور SmartDNS با تأخیر پایین ·',

    /* --- security setup modal --- */
    'Security Setup': 'تنظیم امنیتی',
    'WEAK ADMIN PASSWORD DETECTED': 'رمز عبور مدیر ضعیف است',
    'This account is still on a password that fails the current policy. Anyone who can reach this dashboard may be able to log in with it. Set a new administrator password now:':
      'رمز این حساب سیاست فعلی را رد می‌کند. هر کسی که به این پنل دسترسی داشته باشد ممکن است بتواند با آن وارد شود. همین حالا یک رمز عبور تازه برای مدیر بگذارید:',
    'CURRENT PASSWORD': 'رمز عبور فعلی',
    'NEW ADMIN USERNAME': 'نام کاربری جدید مدیر',
    'NEW PASSWORD': 'رمز عبور جدید',
    'At least 10 characters, not a common password, and not the same as the username. A short passphrase of unrelated words is both stronger and easier to type.':
      'حداقل ۱۰ کاراکتر، نه یک رمز رایج و نه برابر با نام کاربری. یک عبارت کوتاه از چند کلمهٔ بی‌ربط هم قوی‌تر است و هم راحت‌تر تایپ می‌شود.',
    'At least 10 characters': 'حداقل ۱۰ کاراکتر',
    'Confirm with your current password': 'با رمز عبور فعلی تأیید کنید',
    'SAVE NEW CREDENTIALS': 'ذخیرهٔ اطلاعات جدید',
    'CANCEL': 'انصراف',
    'Cancel': 'انصراف',
    'Save': 'ذخیره',
    'SAVE': 'ذخیره',
    'CONFIRM': 'تأیید',
    'Confirm': 'تأیید',
    'OK': 'تأیید',
    'Add': 'افزودن',
    'Clear': 'پاک کردن',
    'Set': 'ثبت',
    'Regenerate': 'تولید مجدد',
    'Restart': 'ری‌استارت',
    'Block': 'مسدود کن',
    'Pause': 'توقف',
    'Resume': 'ادامه',
    'Failed': 'ناموفق',
    'Saved': 'ذخیره شد',
    'Copied!': 'کپی شد!',
    'VALUE': 'مقدار',
    'No result': 'نتیجه‌ای نیست',
    'Requesting…': 'در حال درخواست…',

    /* --- sidebar / tabs --- */
    'Dashboard': 'داشبورد',
    'Policy': 'سیاست‌ها',
    'Rules': 'قوانین',
    'Clients': 'کلاینت‌ها',
    'Stream': 'جریان زنده',
    'Connect': 'اتصال',
    'API': 'API',
    'Clients & Whitelist': 'کلاینت‌ها و لیست سفید',
    'Gaming Policies': 'سیاست‌های گیم',
    'Live Query Log': 'لاگ زندهٔ کوئری',
    'REST API Gateway': 'درگاه REST API',
    'Settings & SSL': 'تنظیمات و SSL',
    'Connect Guide': 'راهنمای اتصال',
    'Dash': 'داشبورد',
    'Logs': 'لاگ‌ها',
    'SSL': 'SSL',
    'Guide': 'راهنما',
    /* --- dashboard header + stat cards --- */
    'Server Public IP': 'IP عمومی سرور',
    'Diagnostics': 'عیب‌یابی',
    'Run Diagnostics': 'اجرای عیب‌یابی',
    'Restart Server': 'راه‌اندازی مجدد سرور',
    'Logout': 'خروج از حساب',
    'Click to copy server IP': 'برای کپی IP سرور کلیک کنید',
    'Copy server IP address': 'کپی آدرس IP سرور',
    'Copy DNS-over-TLS hostname': 'کپی هاست DNS-over-TLS',
    'Copy DNS-over-HTTPS URL': 'کپی آدرس DNS-over-HTTPS',
    'Restart Core Engine & Reload Rules': 'ری‌استارت موتور و بارگذاری مجدد قوانین',
    'Restart Engine': 'ری‌استارت موتور',
    'Flush DNS Cache': 'خالی کردن کش DNS',
    'Total Queries': 'کل پرس‌وجوها',
    'Query Rate': 'نرخ پرس‌وجوها (QPS)',
    'Total:': 'مجموع:',
    'Total': 'مجموع',
    'Limit: —': 'سقف مجاز: —',
    'Limit: off': 'محدودیت: خاموش',
    'Limit': 'سقف مجاز',
    'Cache Hits': 'پاسخ‌های موفق کش',
    'No misses': 'پاسخ‌دهی کامل از کش (بدون Miss)',
    'Limit: off': 'محدودیت: خاموش',
    'Per-source query rate limit': 'محدودیت نرخ کوئری برای هر مبدأ',
    'Per-source rate limiting is disabled (access.rate_limit_qps = 0)':
      'محدودیت نرخ برای هر مبدأ خاموش است (access.rate_limit_qps = 0)',
    'RAM Cache': 'کش رم (RAM Cache)',
    'hit': 'هیت',
    'Items:': 'تعداد موارد:',
    'Items': 'تعداد موارد',
    'SNI Proxy': 'پروکسی SNI',
    'Active': 'فعال',
    'Inactive': 'غیرفعال',
    'relays': 'رله',
    'no drops': 'بدون افت',
    'Connections that reached the proxy and never became relays':
      'اتصال‌هایی که به پروکسی رسیدند و هرگز به رله تبدیل نشدند',
    'Every connection that reached the proxy named a destination and was relayed':
      'هر اتصالی که به پروکسی رسید مقصدش را اعلام کرد و رله شد',
    'CPU Usage': 'مصرف پردازنده (CPU)',
    'Cores:': 'هسته‌ها:',
    'Cores': 'هسته‌ها',
    'thr': 'ترد',
    'Threads': 'رشته‌ها (تردها)',
    'RAM Usage': 'مصرف حافظه RAM',
    'Sys:': 'سیستم:',
    'System': 'سیستم',
    'Live Traffic': 'ترافیک زنده',
    'Resolver Latency': 'تأخیر ریزالور',
    'Service time for queries the cache did not answer':
      'زمان پاسخ‌دهی برای پرس‌وجوهایی که در کش نبودند',
    'no data yet': 'هنوز داده‌ای نیست',
    'The resolver has not answered a query yet': 'ریزالور هنوز به هیچ کوئری پاسخ نداده',
    'p50 median': 'میانهٔ p50',
    'p99 worst 1%': 'p99 بدترین ۱٪',
    'Peak': 'اوج',
    'All queries:': 'همهٔ کوئری‌ها:',
    'Cache refresh: —': 'نوسازی کش: —',
    'Cache refresh: healthy': 'نوسازی کش: سالم',
    'No background refresh has run yet, no stale answer has been served':
      'هنوز هیچ نوسازی پس‌زمینه‌ای اجرا نشده و هیچ پاسخ کهنه‌ای سرو نشده',
    'every answer from cache': 'همهٔ پاسخ‌ها از کش',
    'No query has needed an upstream resolver yet':
      'هنوز هیچ کوئری‌ای به ریزالور بالادست نیاز پیدا نکرده',
    'Queries answered by an upstream rather than from cache, since the daemon started':
      'کوئری‌هایی که از زمان شروع سرویس، به‌جای کش از یک بالادست پاسخ گرفتند',
    /* --- chart + upstreams --- */
    'Live QPS & Telemetry': 'QPS زنده و تلمتری',
    'Queries Per Second (Live)': 'پرس‌وجو در ثانیه (لحظه‌ای)',
    'Rolling DNS query load · last 60 seconds · 1 Hz':
      'بار کوئری DNS · ۶۰ ثانیهٔ گذشته · ۱ هرتز',
    'LIVE ENGINE': 'موتور زنده',
    'The dashboard is receiving live telemetry': 'پنل در حال دریافت تلمتری زنده است',
    'Telemetry stopped': 'تلمتری قطع شده',
    'STALE — NO TELEMETRY': 'کهنه — بدون تلمتری',
    'The dashboard cannot reach the daemon': 'پنل نمی‌تواند به سرویس دسترسی پیدا کند',
    'Upstream Racers': 'سرورهای بالادست رقابتی',
    'Benchmark': 'بنچمارک',
    'Parallel DNS queries across fastest global upstreams':
      'کوئری موازی روی سریع‌ترین بالادست‌های جهانی',
    'Reading upstream health…': 'در حال خواندن سلامت بالادست‌ها…',
    'Racing Policy:': 'سیاست مسابقه:',
    'Fastest Wins': 'سریع‌ترین برنده است',
    '● Validated': '● تأیید شده',
    'No upstreams configured': 'هیچ بالادستی تنظیم نشده',
    'Remove upstream': 'حذف بالادست',
    /* Both of these are labels on controls that carry an icon and no text: the language
       group in the sidebar, mobile header and login card, and the ✕ on a policy tag. An
       icon-only control has no accessible name of its own, so the attribute *is* the
       label — leaving it untranslated leaves a Persian panel with an English button. */
    'Interface language': 'زبان رابط',
    'Remove policy': 'حذف سیاست',
    'Last measured round-trip': 'آخرین رفت‌وبرگشت اندازه‌گیری‌شده',
    'Not measured yet — no answer has been timed from this upstream':
      'هنوز اندازه‌گیری نشده — هیچ پاسخی از این بالادست زمان‌سنجی نشده',
    'not timed yet': 'هنوز زمان‌سنجی نشده',
    'Listening': 'در حال شنود',

    /* --- diagnostics modal --- */
    'Gaming Diagnostic Suite': 'مجموعهٔ عیب‌یابی گیم',
    'Verifying VPS route latency & handshake': 'بررسی تأخیر مسیر VPS و هندشیک',
    'GAMING SUITABILITY SCORE': 'امتیاز مناسب‌بودن برای گیم',
    'Ready to test': 'آمادهٔ تست',
    'Run Test': 'اجرای تست',
    'Click "Run Test" to benchmark routes to Riot, Epic, Steam, Discord, EA, Battle.net, PUBG and Spotify.':
      'برای بنچمارک مسیرها به Riot، Epic، Steam، Discord، EA، Battle.net، PUBG و Spotify روی «اجرای تست» بزنید.',
    'Testing routes...': 'در حال تست مسیرها…',
    'Test failed': 'تست ناموفق بود',
    'The diagnostic run was refused': 'اجرای عیب‌یابی رد شد',
    'The server answered the diagnostic run with a response that is not JSON.':
      'سرور به اجرای عیب‌یابی پاسخی داد که JSON نیست.',
    'Could not reach the server to run diagnostics.':
      'برای اجرای عیب‌یابی نمی‌توان به سرور دسترسی پیدا کرد.',
    'The server reported no diagnostic targets.': 'سرور هیچ هدف عیب‌یابی‌ای اعلام نکرد.',

    /* --- access mode --- */
    'Client Access Whitelist Mode': 'حالت لیست سفید دسترسی کلاینت',
    'PUBLIC ACCESS': 'دسترسی عمومی',
    'PUBLIC ACCESS': 'دسترسی عمومی',
    'WHITELIST ENFORCED': 'لیست سفید فعال',
    'When Enabled (Shelter / Shecan Style):': 'وقتی فعال باشد (سبک شلتر / شکن):',
    'Only whitelisted client IP addresses can resolve DNS and access gaming routes. Unregistered IPs are refused access.':
      'فقط IP‌های ثبت‌شده در لیست سفید می‌توانند DNS بگیرند و به مسیرهای گیم دسترسی داشته باشند. IP‌های ثبت‌نشده رد می‌شوند.',
    'Public Mode': 'حالت عمومی',
    'Whitelist Mode (Only Registered Clients)': 'حالت لیست سفید (فقط کلاینت‌های ثبت‌شده)',
    'Public Mode (Anyone can connect)': 'حالت عمومی (همه می‌توانند وصل شوند)',
    /* --- client list + cards --- */
    'Add New Client': 'افزودن کلاینت جدید',
    'Add Client': 'افزودن کلاینت جدید',
    'Add New Client Account': 'ساخت حساب کلاینت جدید',
    'Search clients...': 'جست‌وجوی کلاینت‌ها...',
    'Display Name': 'نام نمایشی',
    'Username (for login)': 'نام کاربری (جهت ورود)',
    'Username': 'نام کاربری',
    'Password': 'رمز عبور',
    'Traffic Limit (GB, 0 = unlimited)': 'سقف ترافیک (گیگابایت، ۰ = نامحدود)',
    'Expiration Date': 'تاریخ انقضا',
    'Never expires': 'بدون تاریخ انقضا (دائمی)',
    'Enabled Policies': 'سیاست‌های فعال',
    'Edit Client': 'ویرایش کلاینت',
    'Update': 'به‌روزرسانی',
    'Share Links': 'اشتراک‌گذاری لینک‌های اتصال',
    'Share': 'اشتراک‌گذاری لینک‌ها',
    'Edit': 'ویرایش',
    'Delete': 'حذف',
    'Name': 'نام',
    'Traffic': 'حجم مصرفی (ترافیک)',
    'Expires': 'تاریخ انقضا',
    'Status': 'وضعیت',
    'Actions': 'عملیات',
    'Expired': 'منقضی‌شده',
    'Disabled': 'غیرفعال',
    'Create': 'ایجاد',
    'Close': 'بستن',
    'Copy': 'کپی',
    'DoH (DNS-over-HTTPS)': 'DoH (DNS-over-HTTPS)',
    'DoT (DNS-over-TLS)': 'DoT (DNS-over-TLS)',
    'Plain DNS': 'دی‌ان‌اس ساده (بدون رمزنگاری)',
    'Loading clients…': 'در حال بارگذاری کلاینت‌ها…',
    'Reading the subscriber list from the server.': 'در حال خواندن لیست مشترکین از سرور.',
    'Could not load clients': 'کلاینت‌ها بارگذاری نشدند',
    'Could not reach the server': 'دسترسی به سرور برقرار نشد',
    'The subscriber list could not be read. Nothing has been changed — this is a failed read, not an empty list.':
      'لیست مشترکین خوانده نشد. چیزی تغییر نکرده — این یک خواندن ناموفق است، نه لیست خالی.',
    'Could not reach the server to load the client list.':
      'برای بارگذاری لیست کلاینت‌ها نمی‌توان به سرور دسترسی پیدا کرد.',
    'Search client name, ID, or IP...': 'جست‌وجوی نام، شناسه یا IP کلاینت…',
    'Clear search': 'پاک کردن جست‌وجو',
    'No Clients Yet': 'هنوز کلاینتی نیست',
    'Generate IP whitelist registration slug': 'ساخت لینک ثبت IP در لیست سفید',
    'Lifetime (No Expiry)': 'همیشگی (بدون انقضا)',
    '(Expired)': '(منقضی)',
    'EXPIRED': 'منقضی',
    'NO QUOTA': 'بدون حجم',
    'Unlimited': 'نامحدود',
    'Never': 'هیچ‌وقت',
    'just now': 'همین حالا',
    'ACTIVE': 'فعال',
    'DISABLED': 'غیرفعال',
    'Disable Client': 'غیرفعال کردن کلاینت',
    'Enable Client': 'فعال کردن کلاینت',
    'Edit Client': 'ویرایش کلاینت',
    'Delete Client': 'حذف کلاینت',
    'delete this client': 'این کلاینت را حذف کنی',
    'Copy UUID': 'کپی UUID',
    'Remove IP': 'حذف IP',
    'set IP': 'ثبت IP',
    'No IPs registered yet (Share link below)': 'هنوز IP‌ای ثبت نشده (لینک پایین را بفرستید)',
    '· Slug:': '· اسلاگ:',
    'UUID:': 'UUID:',
    'Registered IP (Max 1):': 'IP ثبت‌شده (حداکثر ۱):',
    'Plan Expiry': 'انقضای پلن',
    'Traffic Limit': 'محدودیت ترافیک',
    'Queries': 'کوئری‌ها',
    'Reg Link': 'لینک ثبت',
    'Bot Card': 'کارت بات',
    '+30 Days': '+۳۰ روز',
    'Click "Add New Client" above to create client accounts & registration links.':
      'برای ساخت حساب کلاینت و لینک ثبت، بالا روی «افزودن کلاینت جدید» بزنید.',
    'you have no subscribers': 'هیچ مشترکی ندارید',
    'the grid is showing a notice': 'شبکه در حال نمایش یک اطلاعیه است',
    ', which for this panel means': '، که برای این پنل یعنی',
    /* --- client create / edit forms --- */
    'Manage account properties, traffic limits & policy exceptions':
      'مدیریت مشخصات حساب، محدودیت ترافیک و استثناهای سیاست',
    'Email / Client Name': 'ایمیل / نام کلاینت',
    'Traffic Limit (GB)': 'محدودیت ترافیک (گیگابایت)',
    'TRAFFIC LIMIT (GB)': 'محدودیت ترافیک (گیگابایت)',
    'Auto Reset': 'بازنشانی خودکار',
    'AUTO RESET': 'بازنشانی خودکار',
    'Never (manual)': 'هیچ‌وقت (دستی)',
    'Daily': 'روزانه',
    'Weekly': 'هفتگی',
    'Monthly': 'ماهانه',
    'Resets the volume only — never the expiry date.':
      'فقط حجم را صفر می‌کند — هرگز تاریخ انقضا را.',
    'Expiry (Gregorian)': 'انقضا (میلادی)',
    'Clear (Lifetime)': 'پاک کردن (همیشگی)',
    'Time:': 'ساعت:',
    'Now (+30d)': 'الان (+۳۰ روز)',
    'Manual IP Address (Optional)': 'آدرس IP دستی (اختیاری)',
    'INITIAL IP ADDRESS (OPTIONAL)': 'آدرس IP اولیه (اختیاری)',
    'If blank, client can self-register using their personal URL.':
      'اگر خالی باشد، کلاینت می‌تواند با لینک شخصی خودش ثبت‌نام کند.',
    'UUID (RFC 4122 v4)': 'UUID (RFC 4122 v4)',
    'Comment / Note': 'توضیح / یادداشت',
    'Attached DNS Policies': 'سیاست‌های DNS متصل',
    'Leave empty to inherit all global policies, or select specific games.':
      'خالی بگذارید تا همهٔ سیاست‌های کلی ارث برسد، یا بازی‌های خاصی را انتخاب کنید.',
    'Select all': 'انتخاب همه',
    'select all': 'انتخاب همه',
    'Clear all (Inherit)': 'پاک کردن همه (ارث‌بری)',
    'Account Status': 'وضعیت حساب',
    'Reset Traffic': 'صفر کردن ترافیک',
    'CLIENT NAME / LABEL': 'نام / برچسب کلاینت',
    'PLAN DURATION / EXPIRATION': 'مدت پلن / انقضا',
    '30 Days (1 Month)': '۳۰ روز (۱ ماه)',
    '7 Days (1 Week)': '۷ روز (۱ هفته)',
    '1 Day (24 Hours)': '۱ روز (۲۴ ساعت)',
    '90 Days (3 Months)': '۹۰ روز (۳ ماه)',
    '365 Days (1 Year)': '۳۶۵ روز (۱ سال)',
    'Lifetime (No Expiration)': 'همیشگی (بدون انقضا)',
    'CREATE CLIENT & GENERATE LINK': 'ساخت کلاینت و تولید لینک',
    'Inheriting all global policies': 'در حال ارث‌بری همهٔ سیاست‌های کلی',
    'No matching policies found': 'سیاستی مطابق پیدا نشد',
    'No policies available to select': 'سیاستی برای انتخاب موجود نیست',
    'Loading policies…': 'در حال بارگذاری سیاست‌ها…',
    'Could not load the policy list from the server.':
      'لیست سیاست‌ها از سرور بارگذاری نشد.',
    'there are no policies': 'هیچ سیاستی وجود ندارد',
    'empty catalog': 'کاتالوگ خالی',
    /* --- datepicker. The calendar is Gregorian by design, so the month names are the
       Persian names of the Gregorian months rather than Jalali ones. --- */
    'Su': 'ی', 'Mo': 'د', 'Tu': 'س', 'We': 'چ', 'Th': 'پ', 'Fr': 'ج', 'Sa': 'ش',
    'Jan': 'ژانویه', 'Feb': 'فوریه', 'Mar': 'مارس', 'Apr': 'آپریل',
    'May': 'مه', 'Jun': 'ژوئن', 'Jul': 'ژوئیه', 'Aug': 'اوت',
    'Sep': 'سپتامبر', 'Oct': 'اکتبر', 'Nov': 'نوامبر', 'Dec': 'دسامبر',

    /* --- policy tab: headings and profile buttons --- */
    'Quick Policy Profiles': 'پروفایل‌های سریع سیاست',
    '1-Click activate targeted optimization bundles':
      'فعال‌سازی یک‌کلیکی بستهٔ بهینه‌سازی هدفمند',
    'Pro Gamer': 'گیمر حرفه‌ای',
    'All 13 game routes': 'همهٔ ۱۳ مسیر گیم',
    'Streamer': 'استریمر',
    'Discord, Twitch, Kick': 'Discord، Twitch، Kick',
    'Dev 403': 'توسعه‌دهنده ۴۰۳',
    'Docker, AI, npm': 'Docker، AI، npm',
    'Safe DNS': 'DNS ایمن',
    'AdBlock & Family': 'ضدتبلیغ و خانواده',
    'Anti-sanction & low-latency routing for competitive PC, Console & Mobile games':
      'مسیریابی ضدتحریم و کم‌تأخیر برای بازی‌های رقابتی PC، کنسول و موبایل',
    'Streaming & Media Policies': 'سیاست‌های استریم و رسانه',
    'Bypass restrictions on live streaming, voice channels, and music':
      'دور زدن محدودیت استریم زنده، کانال صوتی و موسیقی',
    'Developer & Security Policies': 'سیاست‌های توسعه و امنیت',
    'Developer 403 bypass, ad-blocking sinkhole, and parental controls':
      'دور زدن خطای ۴۰۳ توسعه‌دهنده، سینک‌هول ضدتبلیغ و کنترل والدین',

    /* --- policy cards. Product names stay in Latin script — Persian gamers read and
       search for them that way — but every description is translated. --- */
    'Valorant · LoL · Vanguard': 'Valorant · LoL · Vanguard',
    'Bypasses 403 errors and optimizes Vanguard matchmaking route.':
      'خطای ۴۰۳ را دور می‌زند و مسیر مچ‌میکینگ Vanguard را بهینه می‌کند.',
    'Store · Fortnite · EAC': 'Store · Fortnite · EAC',
    'Unblocks Store, Unreal Engine, and Easy Anti-Cheat handshake servers.':
      'Store، Unreal Engine و سرورهای هندشیک Easy Anti-Cheat را باز می‌کند.',
    'Community · CS2 · Dota 2': 'Community · CS2 · Dota 2',
    'Fixes Steam Community marketplace, friends chat, and Valve servers.':
      'مارکت‌پلیس Steam Community، چت دوستان و سرورهای Valve را درست می‌کند.',
    'PUBG Mobile & PC': 'PUBG موبایل و PC',
    'Krafton · Level Infinite': 'Krafton · Level Infinite',
    'Fixes loading/handshake errors, optimizes matchmaking, and unblocks in-game events.':
      'خطاهای لودینگ و هندشیک را درست می‌کند، مچ‌میکینگ را بهینه و ایونت‌های داخل بازی را باز می‌کند.',
    'Call of Duty Mobile': 'Call of Duty Mobile',
    'CODM · Warzone Mobile': 'CODM · Warzone Mobile',
    'Unblocks Activision login, Demonware matchmaking, and token validation.':
      'ورود Activision، مچ‌میکینگ Demonware و اعتبارسنجی توکن را باز می‌کند.',
    'Supercell Games': 'بازی‌های Supercell',
    'Brawl Stars · Clash Royale': 'Brawl Stars · Clash Royale',
    'Fixes Brawl Stars, Clash of Clans, and Squad Busters connection lock.':
      'قفل اتصال Brawl Stars، Clash of Clans و Squad Busters را باز می‌کند.',
    'EA & Origin': 'EA و Origin',
    'EA App · Apex Legends': 'EA App · Apex Legends',
    'Fixes EA App authentication and Apex Legends token refresh.':
      'احراز هویت EA App و تازه‌سازی توکن Apex Legends را درست می‌کند.',
    'Blizzard · Overwatch · WoW': 'Blizzard · Overwatch · WoW',
    'Ensures Battle.net launcher connectivity and Blizzard game servers access.':
      'اتصال لانچر Battle.net و دسترسی به سرورهای Blizzard را تضمین می‌کند.',
    'Ubisoft Connect': 'Ubisoft Connect',
    'Rainbow Six · AC': 'Rainbow Six · AC',
    'Bypasses Ubisoft Connect login issues and sync errors.':
      'مشکلات ورود و خطاهای همگام‌سازی Ubisoft Connect را دور می‌زند.',
    'Rockstar Games': 'Rockstar Games',
    'GTA Online · RDR2': 'GTA Online · RDR2',
    'Fixes Social Club offline mode and GTA Online cloud save sync.':
      'حالت آفلاین Social Club و همگام‌سازی سیو ابری GTA Online را درست می‌کند.',
    'Xbox & Microsoft': 'Xbox و Microsoft',
    'Xbox Live · Minecraft': 'Xbox Live · Minecraft',
    'Optimizes Xbox Live party chat and Microsoft gaming authentication.':
      'چت پارتی Xbox Live و احراز هویت گیمینگ Microsoft را بهینه می‌کند.',
    'PlayStation Network': 'PlayStation Network',
    'PSN · PS5 / PS4 Store': 'PSN · استور PS5 / PS4',
    'Unblocks PlayStation Network login and store connection.':
      'ورود به PlayStation Network و اتصال به استور را باز می‌کند.',
    'Client · Assets CDN': 'کلاینت · CDN دارایی‌ها',
    'Bypasses Roblox client connection blocks and asset download errors.':
      'مسدودی اتصال کلاینت Roblox و خطاهای دانلود دارایی را دور می‌زند.',
    'Tactical Shooters Extra': 'شوترهای تاکتیکی (تکمیلی)',
    'Tarkov · The Finals · R6 · HellDivers 2': 'Tarkov · The Finals · R6 · HellDivers 2',
    'Anime & Modern MMOs': 'انیمه و MMO‌های مدرن',
    'Genshin · Wuthering Waves · ZZZ · PoE 2': 'Genshin · Wuthering Waves · ZZZ · PoE 2',
    'Sports, Fighting & Racing': 'ورزشی، مبارزه‌ای و مسابقه‌ای',
    'FC 25 · eFootball · SF6 · MK1 · Tekken 8': 'FC 25 · eFootball · SF6 · MK1 · Tekken 8',
    'Co-Op, Survival & Strategy': 'همکاری، بقا و استراتژی',
    'Palworld · Among Us · Terraria · War Thunder':
      'Palworld · Among Us · Terraria · War Thunder',
    'Platforms & Hardware Tools': 'پلتفرم‌ها و ابزارهای سخت‌افزاری',
    'GeForce Now · AMD · GameLoop · RED': 'GeForce Now · AMD · GameLoop · RED',
    'Nvidia GeForce Now cloud gaming, AMD Adrenaline, GameLoop emulator, GameRanger, CD Projekt REDlauncher.':
      'گیمینگ ابری Nvidia GeForce Now، AMD Adrenaline، امولاتور GameLoop، GameRanger و لانچر CD Projekt RED.',
    'Updates · RTC Voice': 'آپدیت‌ها · صوت RTC',
    'Fixes updater downloading loop and RTC connecting voice lock.':
      'حلقهٔ دانلود آپدیتر و قفل اتصال صوتی RTC را درست می‌کند.',
    'Spotify & SoundCloud': 'Spotify و SoundCloud',
    'Music Streaming Anti-Sanction': 'ضدتحریم استریم موسیقی',
    'Bypasses 403 sanctions on Spotify music playback, login, and SoundCloud CDN streams.':
      'تحریم ۴۰۳ روی پخش موسیقی Spotify، ورود و استریم‌های CDN ساندکلاد را دور می‌زند.',
    'Live Streams & Chat': 'استریم زنده و چت',
    'Ensures high-speed Twitch streaming and websocket chat connectivity.':
      'استریم پرسرعت Twitch و اتصال چت وب‌سوکت را تضمین می‌کند.',
    'Kick.com': 'Kick.com',
    'Live Streaming': 'استریم زنده',
    'Bypasses Kick live stream playback blocks and chat websocket blocks.':
      'مسدودی پخش استریم زندهٔ Kick و مسدودی وب‌سوکت چت را دور می‌زند.',
    'Developer 403 Suite': 'مجموعهٔ ۴۰۳ توسعه‌دهنده',
    'Docker · OpenAI · Claude · npm': 'Docker · OpenAI · Claude · npm',
    'Bypasses 403 blocks on Docker, Android SDK, OpenAI, Claude, npm, and Gradle.':
      'مسدودی ۴۰۳ روی Docker، Android SDK، OpenAI، Claude، npm و Gradle را دور می‌زند.',
    'AdBlock & Trackers': 'ضدتبلیغ و ردیاب‌ها',
    'Sinkhole · 0.0.0.0': 'سینک‌هول · 0.0.0.0',
    'Pi-hole/AdGuard style blocking of telemetry, in-app trackers, and banner ads.':
      'مسدودسازی تلمتری، ردیاب‌های داخل اپ و تبلیغات بنری، به سبک Pi-hole/AdGuard.',
    'Family Safe Filter': 'فیلتر ایمن خانواده',
    'FamilySafe Protection': 'محافظت خانوادگی',
    'Adult Content Filter': 'فیلتر محتوای بزرگسال',
    'Sinkholes adult and pornographic domains for safe household browsing.':
      'دامنه‌های بزرگسال و پورنوگرافی را سینک‌هول می‌کند تا مرور خانگی ایمن باشد.',
    'Blocks (sinkholes) these domains': 'این دامنه‌ها را مسدود (سینک‌هول) می‌کند',
    'Riot Games & Valorant': 'Riot Games و Valorant',

    /* --- bandwidth & traffic policy (the download veto) --- */
    'Bandwidth & Traffic Policy': 'سیاست پهنای باند و ترافیک',
    "Whether bulk downloads travel through the proxy or the subscriber's own line":
      'اینکه دانلودهای حجیم از مسیر پروکسی بروند یا از خط اینترنت خود مشترک',
    'Game & App Downloads via DNS': 'دانلود بازی و اپلیکیشن از مسیر DNS',
    /* Also the rule label the daemon returns in /api/policies and the query stream, so
       the client policy picker and the log rows read Persian too. */
    'Game & App Downloads': 'دانلود بازی و اپلیکیشن',
    "OFF, the default: store pages, sign-in, matchmaking and patch metadata still go through the proxy, but the depot and CDN hosts carrying the multi-gigabyte payload resolve to their real addresses, so installs and updates run on the subscriber's own connection. ON: that payload is relayed too.":
      'خاموش، حالت پیش‌فرض: صفحه‌های فروشگاه، ورود به حساب، مچ‌میکینگ و متادیتای پچ همچنان از پروکسی می‌گذرند، اما هاست‌های دیپو و CDN که حجم چندگیگابایتی را حمل می‌کنند به آدرس واقعی خودشان resolve می‌شوند؛ پس نصب و آپدیت روی خط اینترنت خود مشترک انجام می‌شود. روشن: آن حجم هم رله می‌شود.',
    'Read this before switching it on': 'قبل از روشن کردن، این‌ها را بخوانید',
    'A single 100 GB install crosses this server twice, in and out again. Most providers bill egress by the gigabyte.':
      'یک نصب ۱۰۰ گیگابایتی دو بار از این سرور می‌گذرد؛ یک بار ورودی و یک بار خروجی. بیشتر سرویس‌دهنده‌ها ترافیک خروجی را گیگابایتی حساب می‌کنند.',
    'Traffic quotas count those bytes and there is no per-domain accounting, so one subscriber can burn a monthly plan in an evening.':
      'سهمیهٔ ترافیک این بایت‌ها را هم می‌شمارد و حسابداری به‌تفکیک دامنه وجود ندارد؛ پس یک مشترک می‌تواند پلن یک‌ماهه را در یک شب تمام کند.',
    'A relayed download is usually slower, not faster. The proxy adds a hop, and the CDN edge nearest the subscriber is closer than this server is.':
      'دانلود رله‌شده معمولاً کندتر است، نه سریع‌تر. پروکسی یک هاپ اضافه می‌کند و نزدیک‌ترین لبهٔ CDN به مشترک، از این سرور به او نزدیک‌تر است.',
    'Switch it on when a line cannot reach the CDN at all — a hard block, not a slow one. With it off those installs fail instead of crawling, and launchers retry forever without saying why.':
      'وقتی روشنش کنید که خط اینترنت مشترک به‌کل به CDN نمی‌رسد — یعنی مسدودی کامل، نه کندی. با خاموش بودنش آن نصب‌ها شکست می‌خورند، نه اینکه فقط کند شوند، و لانچر بی‌پایان تلاش می‌کند بدون اینکه دلیلش را بگوید.',
    'Per-client scope: a plan has to select this category as well. The global switch is the ceiling, so off here overrides every plan.':
      'دامنهٔ هر-کلاینت: پلن مشترک هم باید این دسته را انتخاب کرده باشد. کلید سراسری سقف است؛ پس خاموش بودن در اینجا بر همهٔ پلن‌ها اولویت دارد.',

    /* --- live query stream --- */
    'All Actions': 'همهٔ اقدام‌ها',
    'ALL': 'همه',
    'PROXY': 'پروکسی',
    'DIRECT': 'مستقیم',
    'BLOCK': 'مسدود',
    'BLOCKED': 'مسدود شد',
    'CACHED': 'از کش',
    'CUSTOM': 'سفارشی',
    'STALE': 'کهنه',
    'RAM': 'رم',
    'QUOTA': 'سهمیه',
    'RATE LIMITED': 'محدودشده',
    'PROXY · IPv6 SINK': 'پروکسی · سینک IPv6',
    'No Match': 'بی‌تطابق',
    'Default Direct': 'مستقیم پیش‌فرض',
    'Public / Direct': 'عمومی / مستقیم',
    'Public': 'عمومی',
    'TIME': 'زمان',
    'CLIENT / ACCOUNT': 'کلاینت / حساب',
    'PROTO': 'پروتکل',
    'QUERY DOMAIN': 'دامنهٔ کوئری',
    'RULE MATCHED': 'قانون منطبق',
    'ACTION': 'اقدام',
    'LATENCY': 'تأخیر',
    'Listening for live DNS queries...': 'در انتظار کوئری‌های زندهٔ DNS…',
    'Search domain or IP...': 'جست‌وجوی دامنه یا IP…',
    'All': 'همه',
    'Direct': 'مستقیم',
    'Proxied': 'از طریق پروکسی (پروکسی‌شده)',
    'Blocked': 'مسدودشده',
    'Pause': 'توقف موقت',
    'Resume': 'ازسرگیری',
    'Clear': 'پاک‌سازی',
    'Time': 'زمان',
    'Domain': 'دامنه',
    'Type': 'نوع رکورد (Type)',
    'Client': 'کلاینت',
    'Action': 'نحوه هدایت (اقدام)',
    'Latency': 'زمان پاسخ (تأخیر)',
    'the current filter': 'فیلتر فعلی',
    'The one query received so far does not match': 'تنها کوئری دریافت‌شده مطابق نیست با',
    's matching subset in the buffer': 'زیرمجموعهٔ منطبق در بافر',
    'the last STREAM_BUFFER_MAX queries received': 'آخرین کوئری‌های دریافت‌شده در بافر',

    /* --- API tab --- */
    'Developer REST API v1': 'REST API نسخهٔ ۱ برای توسعه‌دهنده',
    'Automate client creation, whitelist sync, and dynamic IP updates':
      'خودکارسازی ساخت کلاینت، همگام‌سازی لیست سفید و به‌روزرسانی IP پویا',
    'Interactive Swagger Docs': 'مستندات تعاملی Swagger',
    'API Network Binding & Security': 'اتصال شبکه و امنیت API',
    'Control interface exposure and remote API access':
      'کنترل نمایان‌بودن اینترفیس و دسترسی API از راه دور',
    '127.0.0.1 (Localhost Only)': '127.0.0.1 (فقط لوکال)',
    '0.0.0.0 (Public HTTPS)': '0.0.0.0 (HTTPS عمومی)',
    'Expose API to Public (': 'انتشار عمومی API (',
    'expose the API publicly': 'API را عمومی کنی',
    'Allows external bots, web services, and billing systems to call REST API v1 directly.':
      'به بات‌های بیرونی، سرویس‌های وب و سیستم‌های صورت‌حساب اجازه می‌دهد مستقیم REST API v1 را صدا بزنند.',
    'Security requirement:': 'الزام امنیتی:',
    'Requires an active custom domain and valid SSL/HTTPS on the server to prevent credential leakage.':
      'برای جلوگیری از لو رفتن اطلاعات ورود، به یک دامنهٔ سفارشی فعال و SSL/HTTPS معتبر روی سرور نیاز دارد.',
    'Master API Authentication Key': 'کلید اصلی احراز هویت API',
    'Full administrative access key for headers (': 'کلید دسترسی کامل مدیریتی برای هدر (',
    'Regenerate Key': 'تولید مجدد کلید',
    'Copy API Key': 'کپی کلید API',
    'Show/Hide Key': 'نمایش/پنهان‌سازی کلید',
    'Quick Integration Code Snippets': 'نمونه‌کدهای سریع یکپارچه‌سازی',
    'cURL': 'cURL',
    'Python (Requests)': 'Python (Requests)',
    'Node.js / Telegram Bot': 'Node.js / بات تلگرام',
    'Administrator Credentials': 'اطلاعات ورود مدیر',
    'Dashboard login for': 'ورود به پنل برای',
    '. Changing the password signs out every other session.':
      '. تغییر رمز عبور همهٔ نشست‌های دیگر را خارج می‌کند.',
    'Change Username / Password': 'تغییر نام کاربری / رمز عبور',
    /* --- v2.1: two-factor, LDAP, admin path, subscription --- */
    'Hidden Admin Path': 'مسیر مخفی مدیریت',
    'Regenerate Path': 'تولید مجدد مسیر',
    'Subscription Portal': 'پورتال اشتراک',
    'Portal enabled': 'پورتال فعال باشد',
    "Use the panel's certificate": 'از گواهی پنل استفاده شود',
    'Subscription domain (empty = panel domain)': 'دامنه اشتراک (خالی = دامنه پنل)',
    'Advertised port': 'پورت اعلام‌شده',
    'Portal title (default HyperDNS)': 'عنوان پورتال (پیش‌فرض HyperDNS)',
    'Certificate path (separate domain only)': 'مسیر گواهی (فقط برای دامنه مجزا)',
    'Key path (separate domain only)': 'مسیر کلید (فقط برای دامنه مجزا)',
    'Save Subscription Settings': 'ذخیره تنظیمات اشتراک',
    'Two-Factor Authentication': 'ورود دومرحله‌ای',
    'Start Enrollment': 'شروع ثبت‌نام',
    'Add this secret to your authenticator app, then re-enter your password and the code it shows:': 'این رمز را در برنامهٔ احرازکنندهٔ خود ثبت کنید، سپس رمز عبور و کد نمایش‌داده‌شده را دوباره وارد کنید:',
    'Current password': 'رمز عبور فعلی',
    'Confirm & Enable': 'تأیید و فعال‌سازی',
    'Disable 2FA': 'غیرفعال‌سازی ورود دومرحله‌ای',
    '6-digit code': 'کد ۶ رقمی',
    'LDAP Directory Login': 'ورود از طریق دایرکتوری LDAP',
    'LDAP enabled': 'LDAP فعال باشد',
    'Save LDAP Settings': 'ذخیره تنظیمات LDAP',
    /* --- credentials modal --- */
    'ROTATE YOUR DASHBOARD LOGIN': 'چرخش اطلاعات ورود پنل',
    'Enter your current password to confirm the change':
      'برای تأیید تغییر، رمز عبور فعلی خود را وارد کنید',
    'Leave the password blank to change only the username.':
      'برای تغییر فقط نام کاربری، رمز عبور را خالی بگذارید.',
    'Leave blank to keep the current password': 'خالی بگذارید تا رمز فعلی حفظ شود',

    /* --- settings / SSL tab --- */
    'Automated Let\'s Encrypt SSL / TLS Manager':
      'مدیر خودکار SSL / TLS با Let\'s Encrypt',
    'Issue trusted certificates for clean DoH, DoT (Android Private DNS), and HTTPS':
      'صدور گواهی معتبر برای DoH، DoT (Private DNS اندروید) و HTTPS',
    'Issue SSL Certificate': 'صدور گواهی SSL',
    'Domain name (e.g. dns.mygame.ir)': 'نام دامنه (مثلاً dns.mygame.ir)',
    'Admin Email (optional)': 'ایمیل مدیر (اختیاری)',
    'Custom Proxied Domains': 'دامنه‌های پروکسی سفارشی',
    'Domains that will be spoofed to this server\'s SNI Proxy':
      'دامنه‌هایی که به پروکسی SNI این سرور هدایت می‌شوند',
    'Loading rules…': 'در حال بارگذاری قوانین…',
    'No custom entries yet': 'هنوز ورودی سفارشی‌ای نیست',
    'Custom Blocklist (Sinkhole)': 'لیست مسدودی سفارشی (سینک‌هول)',
    'Domains that will be blocked (returning 0.0.0.0)':
      'دامنه‌هایی که مسدود می‌شوند (پاسخ 0.0.0.0)',
    'DoH Secret Tokens': 'توکن‌های محرمانهٔ DoH',
    'If enabled, clients must pass': 'اگر فعال باشد، کلاینت‌ها باید',
    'to use DoH': 'را برای استفاده از DoH بفرستند',
    'Add Token': 'افزودن توکن',
    'Loading tokens…': 'در حال بارگذاری توکن‌ها…',
    'Custom Static Records': 'رکوردهای استاتیک سفارشی',
    'Map any hostname directly to a custom IP address':
      'هر هاست‌نیم را مستقیم به یک IP سفارشی نگاشت کنید',
    'Loading records…': 'در حال بارگذاری رکوردها…',
    'No static records yet': 'هنوز رکورد استاتیکی نیست',
    'e.g. *.newgame.com or api.target.com': 'مثلاً *.newgame.com یا api.target.com',
    'e.g. *.telemetry.com or ads.tracker.net': 'مثلاً *.telemetry.com یا ads.tracker.net',
    'Enter secure token (e.g. mysecretkey)': 'توکن امن را وارد کنید (مثلاً mysecretkey)',
    'hostname.com': 'hostname.com',

    /* --- form placeholders --- */
    'e.g. gamer-reza': 'مثلاً gamer-reza',
    '0 (0 = Unlimited)': '۰ (۰ = نامحدود)',
    '0 = Unlimited': '۰ = نامحدود',
    'YYYY-MM-DD HH:mm:ss': 'YYYY-MM-DD HH:mm:ss',
    'e.g. customer-a / VIP Gamer Plan': 'مثلاً customer-a / پلن گیمر VIP',
    'Click or search policies...': 'کلیک یا جست‌وجوی سیاست‌ها…',
    'e.g. Reza (PS5 & Phone)': 'مثلاً رضا (PS5 و موبایل)',
    'e.g. 2.189.86.32 (or leave blank for auto-link)':
      'مثلاً 2.189.86.32 (یا خالی بگذارید تا خودکار وصل شود)',
    'IPv4 or IPv6 address': 'آدرس IPv4 یا IPv6',
    /* --- connect guide --- */
    'How to Connect Client Devices': 'چطور دستگاه‌های کلاینت را وصل کنیم',
    'Connect your Gaming PC, PlayStation, Xbox, Android, iOS, or Router in seconds without installing any client software.':
      'کامپیوتر گیمینگ، PlayStation، Xbox، اندروید، iOS یا روتر خود را در چند ثانیه و بدون نصب هیچ نرم‌افزاری وصل کنید.',
    'Windows 10 / 11 (Gaming PC)': 'ویندوز ۱۰ / ۱۱ (کامپیوتر گیمینگ)',
    'Open': 'باز کنید',
    'Settings': 'تنظیمات',
    'Network & Internet': 'شبکه و اینترنت',
    'Wi-Fi / Ethernet': 'Wi-Fi / اترنت',
    'Click': 'بزنید روی',
    'Edit DNS assignment': 'ویرایش تخصیص DNS',
    '> Select': '> انتخاب کنید',
    'Manual': 'دستی',
    'Turn on': 'روشن کنید',
    'IPv4': 'IPv4',
    'and enter your Server IP:': 'و IP سرور خود را وارد کنید:',
    'Loading IP...': 'در حال بارگذاری IP…',
    'PlayStation 5 / Xbox': 'PlayStation 5 / Xbox',
    'Go to': 'بروید به',
    'Network': 'شبکه',
    'Set Up Internet Connection': 'راه‌اندازی اتصال اینترنت',
    'Select Wi-Fi/LAN >': 'انتخاب Wi-Fi/LAN >',
    'Advanced Settings': 'تنظیمات پیشرفته',
    'DNS': 'DNS',
    ': Manual.': ': دستی.',
    'Primary DNS': 'DNS اصلی',
    'to your Server IP:': 'روی IP سرور خود:',
    'Android Private DNS (DoT)': 'Private DNS اندروید (DoT)',
    'Private DNS': 'Private DNS',
    'Select': 'انتخاب کنید',
    'Private DNS provider hostname': 'هاست‌نیم ارائه‌دهندهٔ Private DNS',
    'and enter:': 'و وارد کنید:',
    'dns.yourdomain.com': 'dns.yourdomain.com',
    'Browser Secure DNS (DoH)': 'DNS امن مرورگر (DoH)',
    'In Browser:': 'در مرورگر:',
    'Privacy & Security': 'حریم خصوصی و امنیت',
    'Use secure DNS': 'استفاده از DNS امن',
    'Choose': 'انتخاب کنید',
    'Custom': 'سفارشی',
    'and paste your DoH URL:': 'و آدرس DoH خود را بچسبانید:',
    'https://your-server-ip:8443/dns-query': 'https://your-server-ip:8443/dns-query',
    /* --- toasts and confirmations raised from app.js --- */
    'Too many attempts. Try again later.': 'تلاش بیش از حد. بعداً دوباره امتحان کنید.',
    'wait fifteen minutes': 'پانزده دقیقه صبر کنید',
    'The server refused the request': 'سرور درخواست را رد کرد',
    'The server refused the request.': 'سرور درخواست را رد کرد.',
    'Could not reach the server — the list may be out of date.':
      'دسترسی به سرور برقرار نشد — ممکن است لیست به‌روز نباشد.',
    'could not reach the server': 'دسترسی به سرور برقرار نشد',
    'Invalid credentials': 'اطلاعات ورود نادرست است',
    'Server connection failed': 'اتصال به سرور ناموفق بود',
    'Error communicating with server': 'خطا در ارتباط با سرور',
    'Failed to update credentials': 'به‌روزرسانی اطلاعات ورود ناموفق بود',
    'Credentials updated — other sessions have been signed out':
      'اطلاعات ورود به‌روز شد — نشست‌های دیگر خارج شدند',
    'Username updated': 'نام کاربری به‌روز شد',
    'Error updating credentials': 'خطا در به‌روزرسانی اطلاعات ورود',
    'Could not read the account state.': 'وضعیت حساب خوانده نشد.',
    'Could not load the configuration.': 'تنظیمات بارگذاری نشد.',
    'Could not reach the server to load the configuration.':
      'برای بارگذاری تنظیمات نمی‌توان به سرور دسترسی پیدا کرد.',
    'Policies updated & active!': 'سیاست‌ها به‌روز و فعال شدند!',
    'Failed to save policies': 'ذخیرهٔ سیاست‌ها ناموفق بود',
    'Regenerate Master API Key?': 'کلید اصلی API تولید مجدد شود؟',
    'EVERY INTEGRATION BREAKS IMMEDIATELY': 'همهٔ یکپارچه‌سازی‌ها بلافاصله می‌شکنند',
    'The current key stops working the moment the new one is issued. Every external bot, billing hook and script still holding the old key will start getting 401s until you update it by hand.':
      'همان لحظه که کلید جدید صادر شود، کلید فعلی از کار می‌افتد. هر بات بیرونی، وب‌هوک صورت‌حساب و اسکریپتی که کلید قدیمی را دارد تا وقتی دستی به‌روزش نکنید خطای ۴۰۱ می‌گیرد.',
    'REGENERATE KEY': 'تولید مجدد کلید',
    'Master API Key regenerated successfully!': 'کلید اصلی API با موفقیت تولید شد!',
    'Failed to regenerate API key': 'تولید مجدد کلید API ناموفق بود',
    'Error regenerating API key': 'خطا در تولید مجدد کلید API',
    'Cannot expose API to 0.0.0.0: Public API requires an active custom domain and HTTPS configured in Settings to protect credentials.':
      'نمی‌توان API را روی 0.0.0.0 عمومی کرد: API عمومی برای محافظت از اطلاعات ورود، به دامنهٔ سفارشی فعال و HTTPS تنظیم‌شده در بخش تنظیمات نیاز دارد.',
    'Failed to update API bind configuration': 'به‌روزرسانی تنظیمات اتصال API ناموفق بود',
    'Public REST API enabled — external callers with a valid key are now accepted (0.0.0.0)':
      'REST API عمومی فعال شد — از این پس تماس‌های بیرونی با کلید معتبر پذیرفته می‌شوند (0.0.0.0)',
    'REST API restricted to localhost (127.0.0.1)':
      'REST API به لوکال محدود شد (127.0.0.1)',
    'Restart the Core Engine?': 'موتور اصلی ری‌استارت شود؟',
    'IN-FLIGHT QUERIES AND RELAYS ARE DROPPED': 'کوئری‌ها و رله‌های در جریان قطع می‌شوند',
    'All policies are reloaded from the database. Listeners go down and come back up, so queries and relays in flight at that moment are lost and clients retry.':
      'همهٔ سیاست‌ها از دیتابیس بازخوانی می‌شوند. شنودگرها خاموش و روشن می‌شوند، پس کوئری‌ها و رله‌های همان لحظه از دست می‌روند و کلاینت‌ها دوباره تلاش می‌کنند.',
    'RESTART ENGINE': 'ری‌استارت موتور',
    'Core Engine restarted & rules reloaded!':
      'موتور اصلی ری‌استارت شد و قوانین بازخوانی شدند!',
    'Failed to restart engine': 'ری‌استارت موتور ناموفق بود',
    'Upstream resolver added & tested!': 'ریزالور بالادست اضافه و تست شد!',
    'Failed to add upstream': 'افزودن بالادست ناموفق بود',
    'Upstream removed': 'بالادست حذف شد',
    'Please enter a domain name': 'لطفاً یک نام دامنه وارد کنید',
    'Requesting Let\'s Encrypt SSL certificate...':
      'در حال درخواست گواهی SSL از Let\'s Encrypt…',
    'SSL issuance triggered in background!': 'صدور SSL در پس‌زمینه شروع شد!',
    'The domain could not be saved.': 'دامنه ذخیره نشد.',
    'Domain saved.': 'دامنه ذخیره شد.',
    'Could not reach the server, so it is not known whether the domain was saved.':
      'دسترسی به سرور برقرار نشد، پس مشخص نیست دامنه ذخیره شده یا نه.',
    'Pro Gamer Profile (All 171 Games) Activated!':
      'پروفایل گیمر حرفه‌ای (همهٔ ۱۷۱ بازی) فعال شد!',
    'Streamer & Media Profile Activated!': 'پروفایل استریمر و رسانه فعال شد!',
    'Developer 403 Profile Activated!': 'پروفایل ۴۰۳ توسعه‌دهنده فعال شد!',
    'AdBlock & Safe Profile Activated!': 'پروفایل ضدتبلیغ و ایمن فعال شد!',
    'DNS cache flushed successfully!': 'کش DNS با موفقیت خالی شد!',
    'Failed to flush cache': 'خالی کردن کش ناموفق بود',
    'A benchmark is already running': 'یک بنچمارک در حال اجراست',
    'Failed to start benchmark': 'شروع بنچمارک ناموفق بود',
    'Benchmark started — upstream latencies refresh as probes land':
      'بنچمارک شروع شد — تأخیر بالادست‌ها با رسیدن هر پروب به‌روز می‌شود',
    'DoH Token added!': 'توکن DoH اضافه شد!',
    'DoH Token removed': 'توکن DoH حذف شد',
    'Client account created!': 'حساب کلاینت ساخته شد!',
    'Failed to create client': 'ساخت کلاینت ناموفق بود',
    'Network error creating client': 'خطای شبکه در ساخت کلاینت',
    'Whitelist mode enforced (Only registered clients)':
      'حالت لیست سفید فعال شد (فقط کلاینت‌های ثبت‌شده)',
    'Open public mode activated': 'حالت عمومی باز فعال شد',
    'Failed to update access mode': 'به‌روزرسانی حالت دسترسی ناموفق بود',
    'Persian client card copied for Telegram!':
      'کارت فارسی کلاینت برای تلگرام کپی شد!',
    'Client plan extended by 30 days!': 'پلن کلاینت ۳۰ روز تمدید شد!',
    'Delete this subscriber?': 'این مشترک حذف شود؟',
    'PERMANENT — THE ACCOUNT AND ITS TRAFFIC HISTORY ARE GONE':
      'دائمی — حساب و تاریخچهٔ ترافیکش از بین می‌رود',
    'DELETE SUBSCRIBER': 'حذف مشترک',
    'Client deleted': 'کلاینت حذف شد',
    'Set the whitelisted address': 'ثبت آدرس در لیست سفید',
    'A subscriber has one address at a time. The resolver answers the address stored here and refuses every other source.':
      'هر مشترک در هر لحظه یک آدرس دارد. ریزالور به آدرس ثبت‌شده در اینجا پاسخ می‌دهد و هر مبدأ دیگری را رد می‌کند.',
    'SAVE ADDRESS': 'ذخیرهٔ آدرس',
    'Enter an address, or press Cancel to leave it unchanged.':
      'یک آدرس وارد کنید، یا برای بدون‌تغییر ماندن، انصراف را بزنید.',
    'That is not an IP address. Expected something like 2.189.86.32 or 2001:db8::1.':
      'این یک آدرس IP نیست. چیزی مثل 2.189.86.32 یا 2001:db8::1 انتظار می‌رفت.',
    'Remove this address?': 'این آدرس حذف شود؟',
    'THE SUBSCRIBER STOPS RESOLVING IMMEDIATELY':
      'مشترک بلافاصله از سرویس DNS خارج می‌شود',
    'REMOVE ADDRESS': 'حذف آدرس',
    'IP removed from client': 'IP از کلاینت حذف شد',
    'UUID copied to clipboard!': 'UUID در کلیپ‌بورد کپی شد!',
    'New UUID generated!': 'UUID جدید تولید شد!',
    'Failed to regenerate UUID': 'تولید مجدد UUID ناموفق بود',
    'Client traffic counter reset to 0!': 'شمارندهٔ ترافیک کلاینت صفر شد!',
    'Failed to reset traffic counter': 'صفر کردن شمارندهٔ ترافیک ناموفق بود',
    'Network error resetting traffic': 'خطای شبکه در صفر کردن ترافیک',
    'Client configuration updated successfully!': 'تنظیمات کلاینت با موفقیت به‌روز شد!',
    'Failed to update client details': 'به‌روزرسانی مشخصات کلاینت ناموفق بود',
    'Network error updating client': 'خطای شبکه در به‌روزرسانی کلاینت',
    'IP already assigned to another client': 'این IP قبلاً به کلاینت دیگری داده شده',
    'UUID already in use': 'این UUID در حال استفاده است',
    'Invalid traffic reset cycle': 'چرخهٔ بازنشانی ترافیک نامعتبر است',
    'leave the cycle alone': 'چرخه را دست‌نخورده بگذار',
    'This field cannot be empty.': 'این فیلد نمی‌تواند خالی باشد.',
    'It worked, but not the part you were hoping for.':
      'انجام شد، ولی نه آن بخشی که انتظارش را داشتید.',
    'Testing VPS connectivity to Riot, Epic, Steam, Discord, EA, Battle.net, PUBG, Spotify...':
      'تست اتصال VPS به Riot، Epic، Steam، Discord، EA، Battle.net، PUBG و Spotify…',

    /* --- language + theme switcher labels (this file's own UI) --- */
    'Language': 'زبان',
    'Theme': 'پوسته',
    'Switch to light theme': 'تغییر به پوستهٔ روشن',
    'Switch to dark theme': 'تغییر به پوستهٔ تیره',
    'Switch to Persian': 'تغییر به فارسی',
    'Switch to English': 'تغییر به انگلیسی'
  };

  /* Strings the app composes at runtime. The walker sees the finished sentence, so an
     exact key cannot match; these run only when the exact lookup misses. Keep the
     list short — each one is a regex tested against every unmatched text node. */
  var FA_PATTERNS = [
    [/^Limit:\s*(\d+)\/s$/, 'محدودیت: $1/ث'],
    [/^Limit:\s*(\d+)\/s\s*·\s*(\d+)\s*dropped$/, 'محدودیت: $1/ث · $2 افتاده'],
    [/^(\d+)\s*dropped$/, '$1 افتاده'],
    [/^(\d+)\s*failed$/, '$1 ناموفق'],
    [/^Total:\s*([\d.,]+)$/, 'مجموع: $1'],
    [/^Items:\s*([\d.,]+)$/, 'آیتم: $1'],
    [/^Cores:\s*(\d+)$/, 'هسته: $1'],
    [/^Sys:\s*(.+)$/, 'سیستم: $1'],
    [/^All queries:\s*(.+)$/, 'همهٔ کوئری‌ها: $1'],
    [/^last seen\s+(.+)$/, 'آخرین بازدید $1'],
    [/^(\d+)\s*(days?)\s*left$/, '$1 روز مانده'],
    [/^Cache refresh:\s*(\d+)\s*served stale$/, 'نوسازی کش: $1 پاسخ کهنه'],
    [/^unreadable destination$/, 'مقصد ناخوانا'],
    [/^([\d.]+)\s*ms avg$/, 'میانگین $1 میلی‌ثانیه'],
    [/^timed at\s*([\d.]+)\s*ms$/, 'زمان‌سنجی‌شده در $1 میلی‌ثانیه']
  ];
  /* ------------------------------------------------------------------ engine */

  var LANG_KEY = 'hyperdns_lang';
  var THEME_KEY = 'hyperdns_theme';
  var ATTRS = ['placeholder', 'title', 'aria-label'];

  /* Subtrees whose text is not prose. CODE and PRE hold shell and Python snippets an
     operator copies verbatim; translating a word inside one would hand them a command
     that does not run. TEXTAREA content is user data. SVG holds path geometry. */
  var SKIP = { SCRIPT: 1, STYLE: 1, CODE: 1, PRE: 1, TEXTAREA: 1, svg: 1, CANVAS: 1 };

  var lang = 'en';
  var applying = false;
  var observer = null;

  function lookup(raw) {
    var s = raw.trim();
    if (!s) return null;
    var hit = FA[s];
    if (hit !== undefined) return hit;
    for (var i = 0; i < FA_PATTERNS.length; i++) {
      if (FA_PATTERNS[i][0].test(s)) return s.replace(FA_PATTERNS[i][0], FA_PATTERNS[i][1]);
    }
    return null;
  }

  function skipped(node) {
    var p = node.nodeType === 1 ? node : node.parentNode;
    for (; p && p.nodeType === 1; p = p.parentNode) {
      if (SKIP[p.nodeName] || SKIP[p.nodeName.toLowerCase()]) return true;
      if (p.hasAttribute('data-no-i18n')) return true;
    }
    return false;
  }

  /* A translated node keeps its English on itself. The alternative — a Persian→English
     reverse map — cannot work here: several English strings share one Persian rendering
     ('Cancel' and 'CANCEL' both become 'انصراف'), so reversing would be a guess. */
  function textNode(node) {
    var cur = node.nodeValue;
    if (!cur || !cur.trim()) return;
    var orig = node.__i18nOrig;
    var mine = orig !== undefined && cur === node.__i18nOut;

    if (lang === 'en') {
      if (mine) node.nodeValue = orig;
      return;
    }
    /* Already carrying our own output — nothing to do. Anything else means the app
       rewrote this node since we last saw it, so `cur` is the new English source and
       the old cache is stale. */
    if (mine) return;

    var fa = lookup(cur);
    if (fa === null) {
      node.__i18nOrig = undefined;
      node.__i18nOut = undefined;
      return;
    }
    var trimmed = cur.trim();
    node.__i18nOrig = cur;
    node.__i18nOut = cur.replace(trimmed, function () { return fa; });
    node.nodeValue = node.__i18nOut;
  }

  function attrs(el) {
    var cache = el.__i18nAttrs;
    for (var i = 0; i < ATTRS.length; i++) {
      var name = ATTRS[i];
      if (!el.hasAttribute(name)) continue;
      var cur = el.getAttribute(name);
      var slot = cache && cache[name];
      var mine = slot && cur === slot.out;

      if (lang === 'en') {
        if (mine) el.setAttribute(name, slot.src);
        continue;
      }
      if (mine) continue;
      var fa = lookup(cur);
      if (fa === null) continue;
      if (!cache) cache = el.__i18nAttrs = {};
      cache[name] = { src: cur, out: fa };
      el.setAttribute(name, fa);
    }
  }

  function walk(root) {
    if (root.nodeType === 3) { if (!skipped(root)) textNode(root); return; }
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    if (root.nodeType === 1 && skipped(root)) return;
    if (root.nodeType === 1) attrs(root);
    /* One TreeWalker per subtree, filtered in the walker rather than in the callback so
       a skipped element's whole subtree is rejected once instead of re-walked per node. */
    var w = document.createTreeWalker(root, 5 /* ELEMENT | TEXT */, {
      acceptNode: function (n) {
        if (n.nodeType === 1) {
          return (SKIP[n.nodeName] || SKIP[n.nodeName.toLowerCase()] ||
            n.hasAttribute('data-no-i18n')) ? 2 /* REJECT */ : 1 /* ACCEPT */;
        }
        return n.nodeValue && n.nodeValue.trim() ? 1 : 3 /* SKIP */;
      }
    });
    var n;
    while ((n = w.nextNode())) {
      if (n.nodeType === 1) attrs(n); else textNode(n);
    }
  }

  function applyDir() {
    var html = document.documentElement;
    html.setAttribute('lang', lang === 'fa' ? 'fa' : 'en');
    html.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
  }

  function applyLang(next, persist) {
    lang = next === 'fa' ? 'fa' : 'en';
    if (persist !== false) {
      try { localStorage.setItem(LANG_KEY, lang); } catch (e) { /* private mode */ }
    }
    applying = true;
    try {
      applyDir();
      walk(document.documentElement);
    } finally {
      applying = false;
    }
    syncSwitchLabels();
    document.dispatchEvent(new CustomEvent('hyperdns:lang', { detail: { lang: lang } }));
  }

  /* The panel re-renders the query stream, the client grid and the upstream list on a
     timer, so translation cannot be a one-shot pass. The observer is cheap because the
     filter rejects the numeric stat nodes that change most often — they never match a
     dictionary key, so `lookup` fails on a trim and a hash miss. */
  function startObserver() {
    if (observer || typeof MutationObserver !== 'function') return;
    observer = new MutationObserver(function (records) {
      if (applying || lang === 'en') return;
      applying = true;
      try {
        for (var i = 0; i < records.length; i++) {
          var r = records[i];
          if (r.type === 'characterData') {
            if (!skipped(r.target)) textNode(r.target);
            continue;
          }
          if (r.type === 'attributes') {
            if (r.target.nodeType === 1 && !skipped(r.target)) attrs(r.target);
            continue;
          }
          for (var j = 0; j < r.addedNodes.length; j++) walk(r.addedNodes[j]);
        }
      } finally {
        applying = false;
      }
    });
    observer.observe(document.documentElement, {
      childList: true, subtree: true, characterData: true,
      attributes: true, attributeFilter: ATTRS
    });
  }
  /* ------------------------------------------------------------------- theme */

  var theme = 'dark';

  function applyTheme(next, persist) {
    theme = next === 'light' ? 'light' : 'dark';
    var html = document.documentElement;
    html.setAttribute('data-theme', theme);
    /* Tailwind's own `dark` class is still on the element even though no dark: variant
       is used in this markup — leaving it consistent costs nothing and means a future
       dark:… utility behaves. */
    html.classList.toggle('dark', theme === 'dark');
    if (persist !== false) {
      try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ }
    }
    syncSwitchLabels();
    document.dispatchEvent(new CustomEvent('hyperdns:theme', { detail: { theme: theme } }));
  }

  /* --------------------------------------------------------------- switch UI */

  /* Both switches are addressed by attribute rather than by id, and the reason is that
     there are two of each: the sidebar carries one pair for a desktop viewport and the
     mobile header carries another, and only one of the two is ever visible. An id would
     have to be unique, so the second copy would need a second name, and every function
     below would then have to know both. */
  function syncSwitchLabels() {
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    var toLight = theme === 'dark';
    var label = toLight
      ? (lang === 'fa' ? 'تغییر به پوستهٔ روشن' : 'Switch to light theme')
      : (lang === 'fa' ? 'تغییر به پوستهٔ تیره' : 'Switch to dark theme');
    for (var i = 0; i < toggles.length; i++) {
      var t = toggles[i];
      t.setAttribute('title', label);
      t.setAttribute('aria-label', label);
      t.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
      var icon = t.querySelector('[data-feather], svg');
      if (icon && icon.tagName.toLowerCase() === 'i') {
        icon.setAttribute('data-feather', toLight ? 'sun' : 'moon');
      }
      /* The cached original would otherwise fight the label we just wrote. */
      if (t.__i18nAttrs) t.__i18nAttrs = undefined;
    }
    var l = document.querySelectorAll('[data-lang-btn]');
    for (var j = 0; j < l.length; j++) {
      var on = l[j].getAttribute('data-lang-btn') === lang;
      l[j].setAttribute('aria-pressed', on ? 'true' : 'false');
      l[j].classList.toggle('is-active', on);
    }
  }

  function wireSwitches() {
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < toggles.length; i++) {
      if (toggles[i].__i18nWired) continue;
      toggles[i].__i18nWired = true;
      toggles[i].addEventListener('click', function () {
        applyTheme(theme === 'dark' ? 'light' : 'dark');
        /* The icon name was just swapped by syncSwitchLabels; nothing redraws it but this. */
        if (typeof window.safeFeatherReplace === 'function') window.safeFeatherReplace();
      });
    }
    var l = document.querySelectorAll('[data-lang-btn]');
    for (var j = 0; j < l.length; j++) {
      if (l[j].__i18nWired) continue;
      l[j].__i18nWired = true;
      l[j].addEventListener('click', function () {
        applyLang(this.getAttribute('data-lang-btn'));
      });
    }
    syncSwitchLabels();
  }
  /* -------------------------------------------------------------------- init */

  function stored(key, fallback) {
    try {
      var v = localStorage.getItem(key);
      return v || fallback;
    } catch (e) {
      return fallback;
    }
  }

  function init() {
    /* The inline script in index.html already set data-theme, lang and dir before first
       paint so there is no flash; this only recovers the same values into module state
       and does the DOM pass the inline script cannot do (it runs before <body>). */
    theme = document.documentElement.getAttribute('data-theme') === 'light'
      ? 'light' : stored(THEME_KEY, 'dark') === 'light' ? 'light' : 'dark';
    applyTheme(theme, false);
    applyLang(stored(LANG_KEY, 'en'), false);
    wireSwitches();
    startObserver();
    if (typeof window.safeFeatherReplace === 'function') window.safeFeatherReplace();
  }

  window.HyperI18N = {
    /* t() is here for strings that never reach the DOM as text — a window.confirm, or a
       clipboard payload. Everything rendered into the page is covered by the walker, so
       app.js does not have to call this. */
    t: function (s) {
      if (lang === 'en') return s;
      var fa = lookup(s);
      return fa === null ? s : fa;
    },
    lang: function () { return lang; },
    setLang: applyLang,
    theme: function () { return theme; },
    setTheme: applyTheme,
    refresh: function (root) {
      if (lang === 'en') return;
      applying = true;
      try { walk(root || document.documentElement); } finally { applying = false; }
    },
    wire: wireSwitches
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

