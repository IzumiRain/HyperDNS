# ⚡ پروژه HyperDNS — گیت‌وی و کنترلر هوشمند SmartDNS و کاهش پینگ گیمینگ

<p align="center">
  <img src="https://img.shields.io/badge/Release-beta%201.1.0-00f0ff?style=for-the-badge&logo=rocket" alt="Version">
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
  <a href="#-معرفی-پروژه">معرفی پروژه</a> •
  <a href="#-ویژگیهای-کلیدی">ویژگی‌ها</a> •
  <a href="#-نصب-سریع-و-آسان">نصب سریع</a> •
  <a href="#-کنترلر-ترمینال-hdns">کنترلر TUI</a> •
  <a href="#-راهنمای-اتصال-دستگاهها">راهنمای اتصال</a> •
  <a href="README.md">English</a> •
  <a href="#-حمایت-مالی-و-دونیت">دونیت</a>
</div>

---

<div dir="rtl">

## 📖 معرفی پروژه

**HyperDNS** یک سرور SmartDNS فوق‌سریع و پراکسی شفاف SNI است که به صورت یک تک‌فایل باینری مستقل با زبان Go نوشته شده و دارای پنل مدیریتی تحت وب با تم سایبرپانک و رابط خط‌فرمان تعاملی (`hdns`) می‌باشد.

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
       │  - Access Control (Tokens/IPs)    │       │  - Direct Forward to Target Host  │
       └─────────────────┬─────────────────┘       └─────────────────┬─────────────────┘
                         │                                           │
                         ▼                                           ▼
              [ سرورهای دی‌ان‌اس تمیز ]                     [ سرورهای مقصد بازی ]
            (1.1.1.1, 8.8.8.8, Quad9)                  (Riot, Epic, Discord, Steam)
```

---

<div dir="rtl">

## 🌟 ویژگی‌های کلیدی

### 🎮 ۱. پالیسی‌های دسته‌بندی‌شده و هوشمند (Policies)
- **پالیسی‌های گیمینگ:**
  - **PUBG Mobile & PC:** رفع تحریم و کاهش پینگ پابجی موبایل و پی‌سی (Krafton / Level Infinite).
  - **Call of Duty Mobile & Warzone:** رفع تحریم کالاف دیوتی موبایل، وارزون موبایل، شبکه اکتیویژن و مچ‌میکینگ Demonware.
  - **Supercell Games:** رفع کامل مشکل وصل نشدن و لودینگ بازی‌های براول استارز (Brawl Stars)، کلش آو کلنز (Clash of Clans) و کلش رویال.
  - **Riot Games:** رفع کامل تحریم Valorant، League of Legends، Riot Client و بهینه‌سازی Vanguard.
  - **Epic Games:** فروشگاه Epic، بازی Fortnite و سرورهای Easy Anti-Cheat.
  - **Steam & Valve:** مارکت‌پلیس استیم، CS2 و Dota 2.
  - **Electronic Arts:** برنامه EA App، Origin و Apex Legends.
  - **Blizzard:** پلتفرم Battle.net، اورواچ و وارکرافت.
  - **Ubisoft Connect:** رینبو سیکس و اساسینز کرید.
  - **Rockstar Games:** سرورهای GTA Online، RDR2 و Social Club.
  - **Xbox & Microsoft:** شبکه Xbox Live، ماینکرفت و PlayFab.
  - **PlayStation Network:** لاگین PSN، استور PS5/PS4.
  - **Roblox:** کلاینت بازی و CDN است‌ها.
- **پالیسی‌های استریم و مدیا:**
  - **Discord:** رفع فیلترینگ چت، برطرف کردن باگ چرخیدن روی Updating و اتصال پایدار Voice RTC.
  - **Twitch & Kick:** لایو استریم پرسرعت و وب‌سوکت چت.
  - **Spotify:** پخش آنلاین موزیک بدون تحریم ۴۰۳.
- **پالیسی‌های توسعه‌دهندگان (Dev 403):**
  - دور زدن تحریم‌های Docker Hub، OpenAI / ChatGPT، Claude / Anthropic، npm، Gradle، Android SDK، PyPI، HuggingFace، Supabase، Vercel، MongoDB و Oracle.
- **پالیسی‌های امنیتی (AdGuard / Pi-hole Style):**
  - **AdBlock & Trackers:** مسدودسازی تبلیغات درون‌برنامه‌ای و تله‌متری به روش سینک‌هول (`0.0.0.0`).
  - **Family Safe Filter:** مسدودسازی سایت‌های غیراخلاقی و مستهجن.

### ⚡ ۲. کَش پرسرعت در حافظه رم و سیستم Fastest Racing
- پاسخگویی به درخواست‌های تکراری در کمتر از **۰.۵ میلی‌ثانیه**.
- ارسال همزمان درخواست به کلودفلر (`1.1.1.1`)، گوگل (`8.8.8.8`) و Quad9 (`9.9.9.9`) و انتخاب سریع‌ترین سرور.

### 🛡️ ۳. مقاومت در برابر فیلترینگ DPI
- فوروارد شفاف ترافیک TLS بدون شکستن رمزنگاری (Zero-Knowledge).
- قابلیت **TLS ClientHello Fragmentation** برای شکستن هدر SNI و عبور از فیلترینگ DPI.

### 🖥️ ۴. دو رابط کاربری کامل (پنل وب + ترمینال `hdns`)
- **پنل تحت وب:** گرافیک سایبرپانک، مانیتورینگ زنده QPS، پردازنده، رم، سرعت ترافیک دانلود/آپلود، تست تشخیصی سرور و استریم زنده لاگ کوئری‌ها.
- **رابط خط‌فرمان (`hdns`):** کنترل کامل تنظیمات، دامنه‌ها، ریستارت سرویس و تغییر وضعیت پالیسی‌ها از داخل SSH.

</div>

---

<div dir="rtl">

## 🚀 نصب سریع و آسان

### روش اول: اسکریپت نصب تک‌خطی لینوکس (پیشنهادی)
روی اوبونتو، دبیان یا CentOS دستور زیر را به عنوان `root` اجرا کنید:
</div>

```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/main/scripts/install.sh | sudo bash
```

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
