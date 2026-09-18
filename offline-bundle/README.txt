========================================================================
   HYPERDNS v2.2.0-beta (Codename: HyperSHIELD) — OFFLINE INSTALLER
   100% Standalone · Zero Internet Required · Single Binary
========================================================================

WHAT'S IN THIS PACKAGE
----------------------
  hyperdns              The complete daemon (Linux amd64, static, zero CGO).
                        DNS 53 (UDP/TCP) + DoT 853 + DoH (own port) + Panel
                        + REST API v1/v2 + Subscriber portal + TUI — all
                        embedded. The ACME client is IN the binary: the
                        daemon issues and renews its own Let's Encrypt
                        certificates while the service runs.
  install.sh            The installer (systemd service, user, firewall,
                        backups, first-run credentials, panel domain).
  config.example.json   Optional configuration template. The installer seeds
                        /opt/hyperdns/config.json from it on a FRESH install.
                        You do NOT need to edit it beforehand.
  migrate-from-v1.sh    Coming from a HyperDNS 1.x install? Run this FIRST:
                        it sweeps every trace of the old version (service,
                        units, resolver drop-in, CLI links, /opt/hyperdns,
                        cron, leftover processes), archives the old data to
                        /root, then hands over to install.sh.
                        bash migrate-from-v1.sh        (asks MIGRATE)
                        bash migrate-from-v1.sh -y    (no prompt)
  version.json          Build version metadata (2.2.0-beta / HyperSHIELD).
  scripts/uninstall.sh  Clean uninstaller.
  scripts/restore.sh    Restore an uninstall backup (requires Python 3).
  LICENSE               AGPL-3.0.

  NOTE: data.db, master.key and certs/ are NOT shipped — a fresh install
  generates them on the server (master.key with 0600 permissions). Never
  copy an old master.key into a fresh install "to save time": it makes the
  fresh database unreadable, and a leaked key makes the old one readable.

  NOTE: there is NO ssl_issue.sh in this package — nothing to run by hand.
  The daemon issues the certificate at first start (the HTTP-01 challenge
  is served from its own running port-80 listener) and renews daily.

REQUIREMENTS
------------
  - Linux amd64: Ubuntu 20.04+, Debian 11+, CentOS/RHEL/Alma/Rocky 8+
  - root (or sudo)
  - A panel DOMAIN whose A record points at the server (HTTPS is
    mandatory; the panel refuses a self-signed fallback).
  - Ports: 53 UDP+TCP (DNS), 80 TCP (ACME HTTP-01 challenge), a random
    management port for the panel (fresh installs draw one from
    20000-60000; the installer prints it and opens the firewall),
    optionally 853 (DoT) and 8443 (DoH). Internet is required for the
    first certificate issuance only; after that the daemon runs offline.

INSTALL (3 STEPS)
-----------------
1) Upload the WHOLE folder to the server (from your PC):

     scp -r offline-bundle root@YOUR_SERVER_IP:/root/hyperdns-offline

2) Connect and run the installer:

     ssh root@YOUR_SERVER_IP
     cd /root/hyperdns-offline
     chmod +x install.sh hyperdns
     export HYPERDNS_DOMAIN=panel.example.com      # optional: non-interactive
     export HYPERDNS_EMAIL=you@example.com         # optional
     ./install.sh

3) The installer prints, ONCE:
     - the generated admin password (stdout only — never written to logs)
     - the hidden admin path (also in the log)
     - the panel management port

   Then open:

     https://panel.example.com:<panel-port>/<admin-path>/dash/login

   The installer health-checks the dashboard, a stylesheet and a script
   over TRUSTED HTTPS before it prints success. If certificate issuance
   fails it states the cause (A record, port 80, Let's Encrypt rate
   limit) and exits instead of printing success.

FIRST THINGS TO DO AFTER LOGIN
------------------------------
  1. Change the generated password (Settings → Administrator Credentials).
  2. Enable Two-Factor Authentication (Settings → Two-Factor Authentication).
     After that, logins AND password/API-key changes require a 6-digit code,
     and a validated code is single-use across gated operations.
  3. Note your admin path; regenerate it from Settings if it ever leaks
     (regenerating signs out every session and breaks old bookmarks).
  4. If you put nginx/Caddy in front: set the proxy address in
     config.json → server.trusted_proxy_cidrs (restart). Forwarding headers
     are ignored otherwise — by design.
  5. Client access whitelist ships ON (v2.2.0): unknown sources are refused
     by DNS with an RFC 8914 Extended DNS Error. Register clients, or flip
     access.allow_all=true from the dashboard for a personal all-devices
     install (revocation does not work while it is on).

USEFUL COMMANDS
---------------
     systemctl status hyperdns      # service status
     journalctl -u hyperdns -f      # live logs
     hdns                           # interactive TUI console
     hdns status                    # listener + certificate state, no DB

UNINSTALL
---------
     /opt/hyperdns/scripts/uninstall.sh
     (or: hdns, option 16, typed UNINSTALL confirmation)

RESTORE AN UNINSTALL BACKUP
---------------------------
  Install HyperDNS first, then run as root:

     bash /opt/hyperdns/scripts/restore.sh /root/hyperdns-backup-TIMESTAMP.tar.gz --check
     bash /opt/hyperdns/scripts/restore.sh /root/hyperdns-backup-TIMESTAMP.tar.gz

  Type RESTORE when prompted, or pass --yes for unattended use. Python 3 is
  required. Only the uninstall archive layout is supported, not full-tree
  preinstall/migration archives. data.db and master.key must both be present.
  --check validates archive layout and JSON, NOT database integrity or whether
  the key decrypts the database. Use only a trusted backup from your installation.

  Existing data is backed up to /root/hyperdns-before-restore-*.tar.gz (0600).
  The service is stopped before the backup/replacement and remains STOPPED.
  Check the restored domains, ports and firewall rules, then explicitly run:

     systemctl start hyperdns
     systemctl status hyperdns

  Restoring config.json brings back the old panel port, path and credentials.
  Missing optional config.json/certs are left unchanged. Host resolver/firewall
  settings, binaries and service units are never restored from the archive.
  Keep both backups until the restored application has been verified.
  --data-dir DIR is for an idle offline directory only; it does not stop services.

TROUBLESHOOTING
---------------
  - Installer died with "TERM environment variable not set" → this build
    guards `clear`; if you still see it, run:  TERM=xterm ./install.sh
  - Panel does not open → check:  ss -tlnp | grep hyperdns
  - Certificate not issued → the A record must point here and port 80 must
    be reachable; Let's Encrypt allows 5 duplicate certificates per name
    per week. The daemon retries daily; or re-issue from Dashboard →
    Settings → Issue SSL (the built-in ACME client).
  - Forgot the password → rm /opt/hyperdns/data.db is WRONG (destroys all
    subscribers). Ask on the project channel for the reset procedure.
  - Wrong admin path / locked out → the path is in the journal:
     journalctl -u hyperdns | grep "admin panel path"

========================================================================
   HyperDNS v2.2.0-beta · AGPL-3.0 · single Go binary · no dependencies
========================================================================
