# ⚡ پروژه HyperDNS — گیت‌وی و کنترلر هوشمند SmartDNS و کاهش پینگ گیمینگ

<p align="center">
  <img src="https://img.shields.io/badge/Release-beta%201.2.0-00f0ff?style=for-the-badge&logo=rocket" alt="Version">
  <img src="https://img.shields.io/badge/Status-Beta%20Preview-amber?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/Language-Go%201.26-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Architecture-Single%20Binary-a855f7?style=for-the-badge" alt="Single Binary">
  <img src="https://img.shields.io/badge/Protocols-UDP%20%7C%20DoH%20%7C%20DoT-10b981?style=for-the-badge" alt="Protocols">
  <img src="https://img.shields.io/badge/Gaming-Zero%20Loss%20%26%20Low%20Ping-ff4655?style=for-the-badge" alt="Gaming">
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge&logo=gnu" alt="License">
</p>

> [!WARNING]
> ### ⚠️ هشدار نسخه آزمایشی (BETA RELEASE NOTICE)
> **این پروژه در فاز آزمایشی و اولیه (BETA) قرار دارد و ممکن است دارای باگ‌ها، نقص‌ها یا رفتارهای پیش‌بینی‌نشده باشد.**  
> لطفاً در صورت مواجهه با هرگونه اشکال، باگ در مسیریابی بازی‌ها یا قطعی، از طریق بخش **[Issues](https://github.com/IzumiRain/HyperDNS/issues)** گزارش دهید تا سریعاً بررسی و برطرف شود.

<div align="center" dir="rtl">
  <a href="#-نصب-سریع-و-آسان">نصب سریع</a> •
  <a href="#-معرفی-پروژه">معرفی پروژه</a> •
  <a href="SUPPORTED_GAMES.md">لیست ۱۷۱+ بازی ساپورت‌شده</a> •
  <a href="API.md">داکیومنت REST API</a> •
  <a href="CHANGELOG.md">تغییرات (Changelog)</a> •
  <a href="#-ویژگیهای-کلیدی">ویژگی‌ها</a> •
  <a href="#-کنترلر-ترمینال-hdns">کنترلر TUI</a> •
  <a href="#-راهنمای-اتصال-دستگاهها">راهنمای اتصال</a> •
  <a href="README.md">English</a> •
  <a href="#-حمایت-مالی-و-دونیت">دونیت</a>
</div>

---

<div dir="rtl">

## 📖 معرفی پروژه

**HyperDNS** یک سرور SmartDNS فوق‌سریع و پراکسی شفاف SNI است که به صورت یک تک‌فایل باینری مستقل با زبان Go نوشته شده و دارای پنل مدیریتی تحت وب با تم سایبرپانک، رابط برنامه‌نویسی REST API v1 و رابط خط‌فرمان تعاملی (`hdns`) می‌باشد.

این پروژه هر سرور مجازی (VPS/VDS) در خارج از کشور (ترکیه، آلمان، هلند و ...) را به یک **سامانه ضدتحریم (دور زدن ارور ۴۰۳) و کاهش پینگ گیمینگ** تبدیل می‌کند که بدون نیاز به نصب هرگونه فیلترشکن یا کلاینت، روی کامپیوتر، پلی‌استیشن ۵، ایکس‌باکس، اندروید، آیفون و روترها کار می‌کند.

</div>

```
                                  [ دستگاه‌های کاربر ]
                     (Gaming PC, PS5/Xbox, Mobile, Browser)
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │  UDP/TCP 53, DoH (8443/8080), DoT (853)       │
                 ▼                                               ▼
       ┌───────────────────────────────────┐       ┌───────────────────────────────────┐
       │     HyperDNS Core Engine (Go)     │       │     HyperDNS SNI Proxy (80/443)   │
       │  - In-Memory Sharded LRU Cache    │       │  - TLS ClientHello SNI Parser     │
       │  - Smart Policy Matcher           │       │  - Zero-Knowledge TCP Forwarder   │
       │  - Fastest Upstream Racing Pool   │       │  - Anti-DPI TLS Fragmentation     │
       │  - Access Control (Tokens/1-IP)   │       │  - Direct Forward to Target Host  │
       └─────────────────┬─────────────────┘       └─────────────────┬─────────────────┘
                         │                                           │
                         ▼                                           ▼
              [ سرورهای دی‌ان‌اس تمیز ]                     [ سرورهای مقصد بازی ]
            (1.1.1.1, 8.8.8.8, Quad9)                  (Riot, Epic, Discord, Steam)
```

---

<div dir="rtl">

## 🚀 نصب سریع و آسان

### روش اول: اسکریپت نصب تک‌خطی لینوکس (پیشنهادی)
روی اوبونتو، دبیان یا CentOS دستور زیر را به عنوان `root` اجرا کنید:
</div>

```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/main/scripts/install.sh | sudo bash
```

> [!TIP]
> **تشخیص و ارتقای خودکار (Auto-Detect):** اجرای این دستور روی سروری که نسخه‌های قبلی HyperDNS روی آن نصب است، به صورت خودکار نسخه قبلی را تشخیص داده و یک ارتقای بدون از دست رفتن داده (Zero-Data-Loss) به همراه بکاپ‌گیری اتوماتیک انجام می‌دهد.

<div dir="rtl">

### روش دوم: با Docker Compose
</div>

```bash
git clone https://github.com/IzumiRain/HyperDNS.git
cd HyperDNS
docker compose up -d
```

<div dir="rtl">

### روش سوم: نصب ۱۰۰٪ آفلاین (بدون نیاز به اینترنت روی سرور)
اگر سرور دسترسی مستقیم به اینترنت برای دانلود پکیج‌ها ندارد یا می‌خواهید پکیج آماده را مستقیماً آپلود و نصب کنید:

۱. فایل فشرده پکیج آفلاین (`hyperdns-offline-bundle.tar.gz`) را روی سرور آپلود کنید:
</div>

```bash
# آپلود از سیستم لوکال با SCP
scp hyperdns-offline-bundle.tar.gz root@YOUR_SERVER_IP:/root/
```

<div dir="rtl">
۲. روی سرور اکسترکت و نصب کنید:
</div>

```bash
tar -xzvf hyperdns-offline-bundle.tar.gz
chmod +x install.sh hyperdns
sudo ./install.sh
```

---

<div dir="rtl">

## 🌟 ویژگی‌های کلیدی

### 🎮 ۱. پالیسی‌های دسته‌بندی‌شده و هوشمند (پشتیبانی از بیش از ۱۷۱ بازی و سرویس)
- **شوترهای تاکتیکال و بتل‌رویال:** Valorant، CS2، Call of Duty (Warzone / Mobile / BO6)، The Finals، Escape from Tarkov، Delta Force: Hawk Ops، HellDivers 2، PUBG، Apex Legends، Rainbow Six Siege، Rust، Squad، DayZ، ArmA، Dead by Daylight.
- **انیمه، گاچا و MMORPGها:** Genshin Impact، Honkai: Star Rail، Zenless Zone Zero، Wuthering Waves، Arknights: Endfield، Lost Ark، Throne & Liberty، Path of Exile 1 & 2، Warframe، Elden Ring، Black Desert، Final Fantasy XIV.
- **ورزشی، مبارزه‌ای و ریسینگ:** EA Sports FC 25 / FIFA، eFootball / PES، Street Fighter 6، Mortal Kombat 1، Tekken 8، 2XKO، Assetto Corsa، Euro Truck Simulator 2، Forza Horizon 5، F1 24.
- **پلتفرم‌ها، آنتی‌چیت‌ها و کلود گیمینگ:** Faceit AC، Riot Vanguard، EasyAntiCheat (EAC)، BattlEye، Ricochet، GeForce NOW، Boosteroid، Xbox Cloud Gaming، Razer Synapse، Logitech G Hub، Corsair iCUE.
- **اکوسیستم و ناشران:** Riot Games، Steam/Valve، Epic Games، Blizzard، EA، Ubisoft، Rockstar، Xbox Live، PlayStation Network، Roblox، Supercell.
- **استریم و مدیا:** Discord (کامل + حل مشکل Updating + ویس چت RTC)، Spotify و SoundCloud، Twitch، Kick.com.
- **سوییت توسعه‌دهندگان (Dev 403):** دور زدن تحریم‌های Docker Hub، OpenAI / ChatGPT، Claude / Anthropic، npm، Gradle، Android SDK، PyPI، HuggingFace، Supabase، Vercel.
- **امنیت و مسدودسازی:** AdBlock و تله‌متری به شیوه Sinkhole (`0.0.0.0`)، فیلتر Family Safe.

👉 **[مشاهده دایرکتوری کامل بازی‌ها و پلتفرم‌های ساپورت‌شده (۱۷۱+ عنوان)](SUPPORTED_GAMES.md)**

### 🔌 ۲. رابط برنامه‌نویسی REST API v1 و مستندات تعاملی Swagger
- کنترل کامل و بی‌سر (Headless) از طریق REST API با دو روش احراز هویت: Master API Key و توکن JWT.
- صفحه تعاملی Swagger / OpenAPI در اندپوینت `/api/v1/docs`.
- امکان ساخت اکانت، تمدید اشتراک، دریافت زنده تله‌متری QPS و تغییر آنلاین رول‌ها بدون ریستارت سرویس.

👉 **[مشاهده مستندات فنی REST API و نمونه کدها](API.md)**

### 👥 ۳. اکانتینگ کاربران با محدودیت سفت‌وسخت ۱ آی‌پی و قطع آنی اشتراک‌های منقضی
- **لینک اختصاصی ۱-کلیک ثبت آی‌پی:** تولید لینک `/r/:token` برای ثبت خودکار و تغییر آی‌پی داینامیک کاربر بدون نیاز به ورود به پنل ادمین.
- **محدودیت سفت‌وسخت ۱ آی‌پی (Strict 1-IP):** جلوگیری از شیر کردن اکانت؛ در صورت لاگین دستگاه جدید، آی‌پی قبلی خودکار جایگزین و قطع می‌شود.
- **چک‌کننده پس‌زمینه ۱ دقیقه‌ای:** بررسی خودکار و قطع لحظه‌ای دسترسی DNS اکانت‌های منقضی‌شده.

### 🔄 ۴. سیستم هوشمند Auto-Detect و ارتقای بدون از دست رفتن داده‌ها
- اسکریپت نصب تک‌خطی به صورت خودکار نسخه قبلی (`v1.1.0-beta`) را تشخیص می‌دهد.
- از کانفیگ و گواهینامه‌ها بکاپ زمان‌دار می‌گیرد (`/opt/hyperdns/backups/backup_*`).
- کانفیگ را ارتقا داده و ۱۰۰٪ اطلاعات کاربران، پسورد ادمین، رول‌های سفارشی و گواهی‌های SSL را بدون تغییر حفظ می‌کند.

### ⚡ ۵. کَش پرسرعت در حافظه رم و سیستم Fastest Racing
- پاسخگویی به درخواست‌های تکراری در کمتر از **۰.۵ میلی‌ثانیه**.
- ارسال همزمان درخواست به کلودفلر (`1.1.1.1`)، گوگل (`8.8.8.8`) و Quad9 (`9.9.9.9`) و انتخاب سریع‌ترین سرور.

### 🛡️ ۶. مقاومت در برابر فیلترینگ DPI
- فوروارد شفاف ترافیک TLS بدون شکستن رمزنگاری (Zero-Knowledge).
- قابلیت **TLS ClientHello Fragmentation** برای شکستن هدر SNI و عبور از فیلترینگ DPI.

### 🖥️ ۷. دو رابط کاربری کامل (پنل وب + ترمینال `hdns`)
- **پنل تحت وب:** گرافیک سایبرپانک، مانیتورینگ زنده QPS، پردازنده، رم، سرعت ترافیک دانلود/آپلود، تست تشخیصی سرور و استریم زنده لاگ کوئری‌ها.
- **رابط خط‌فرمان (`hdns`):** کنترل کامل تنظیمات، دامنه‌ها، ریستارت سرویس و تغییر وضعیت پالیسی‌ها از داخل SSH.

</div>

---

<div dir="rtl">

## 🖥️ کنترلر ترمینال (`hdns`)

در هر کجای ترمینال سرور دستور زیر را بزنید تا TUI باز شود:
</div>

```bash
hdns
```

<div dir="rtl">

### کلیدهای میانبر و منو:
- **`[1]`** داشبورد مانیتورینگ زنده
- **`[2]`** مدیریت ۱۵+ پالیسی گیمینگ و امنیتی
- **`[3]`** تنظیم دامنه اختصاصی و گواهی TLS (برای DoH و DoT)
- **`[4]`** مدیریت نام‌کاربری و رمز عبور ادمین
- **`[5]`** مدیریت سرورهای بالادستی DNS
- **`[6]`** فلش کردن فوری کش رم
- **`[7]`** ریستارت سرویس HyperDNS
- **`[8]`** ریست و تولید مجدد گواهی TLS
- **`[9]`** حذف کامل نرم‌افزار (Uninstall)

</div>

<div dir="ltr">

### دستورات مستقیم خط فرمان (CLI Commands):
| Command | Description |
|:---|:---|
| `hdns` | باز کردن کنسول مدیریتی تعاملی TUI |
| `hdns status` | نمایش وضعیت زنده سرویس، پورت‌ها و آمار |
| `hdns restart` | ریستارت سرویس پس‌زمینه |
| `hdns stop` / `hdns start` | توقف / استارت سرویس پس‌زمینه |
| `hdns logs` | مشاهده زنده لاگ‌های سیستم و کوئری‌ها |
| `hdns flush` | خالی کردن فوری کش رم DNS |
| `hdns diag` | اجرای بنچ‌مارک پینگ و دایاگنوستیک بازی‌ها |
| `hdns clients` | نمایش لیست کلاینت‌ها و آی‌پی‌های وایت‌لیست |
| `hdns uninstall` | حذف کامل و تمیز HyperDNS از روی سرور |

</div>

<div dir="rtl">

---

<div dir="rtl">

## 🎮 راهنمای اتصال دستگاه‌ها

### 🖥️ ویندوز (Windows 10 / 11)
1. وارد **Settings** > **Network & Internet** > **Ethernet / Wi-Fi** شوید.
2. روی **Edit DNS assignment** کلیک کرده و **Manual** را انتخاب کنید.
3. گزینه **IPv4** را فعال کرده و آی‌پی سرور خود را در بخش‌های Preferred و Alternate وارد کنید.

### 🎮 کنسول‌های بازی (PlayStation 5 / Xbox)
1. به **Settings** > **Network** > **Set Up Internet Connection** بروید.
2. روی شبکه خود رفته و در **Advanced Settings**، بخش **DNS Settings** را روی **Manual** بگذارید.
3. مقدار **Primary DNS** را آی‌پی سرور خود تنظیم کنید.

### 📱 اندروید (Private DNS / DoT)
1. به **Settings** > **Network & Internet** > **Private DNS** بروید.
2. گزینه **Private DNS provider hostname** را انتخاب کرده و دامنه سرور را وارد کنید: `dns.yourdomain.com`.

### 🌐 مرورگرها (Chrome, Brave, Firefox)
1. در تنظیمات مرورگر به بخش **Privacy & Security** > **Use secure DNS** بروید.
2. گزینه **Custom** را انتخاب کرده و آدرس زیر را وارد کنید:
   `http://YOUR_SERVER_IP:8080/dns-query`

</div>

---

<div dir="rtl">

## 💖 حمایت مالی و دونیت

اگر پروژه **HyperDNS** برای گیمینگ و دور زدن محدودیت‌های اینترنت برای شما مفید بوده است، با دونیت خود می‌توانید به توسعه و نگهداری آن کمک کنید!

🌐 **وب‌سایت شخصی توسعه‌دهنده:** [https://izumirain.github.io/](https://izumirain.github.io/)

</div>

<div dir="ltr">

| Network | Address |
|:---|:---|
| **TRC20** (Tron) | `TKBHWNoeygcaCK8N78e7dQX5Yco3WTb6ZN` |
| **BEP20** (BNB Smart Chain) | `0x0F982640a69D3B9FB944840D7DA8bECCfcF0bb9E` |
| **TON** | `UQAyLUyxew-eggwhxbzsAZZZ9ULM8MYOk-3IXFh7tNC33LNt` |

</div>

---

<div dir="rtl">

## 📄 لایسنس
این پروژه تحت لایسنس بین‌المللی **[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE)** به صورت ۱۰۰٪ متن‌باز و آزاد منتشر شده است. ساخته‌شده با ❤️ برای گیمرها و اینترنت آزاد.

</div>
