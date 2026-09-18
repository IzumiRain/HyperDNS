#!/usr/bin/env bash
# ==============================================================================
# HyperDNS Clean & Complete Uninstaller
#
# Reverses scripts/install.sh, including the parts of it that reach outside
# /opt/hyperdns: the systemd-resolved drop-in, the /etc/resolv.conf the installer
# replaced, and the firewall rules it opened.
#
# The default run archives config.json, data.db, master.key and certs/ to /root
# before deleting anything, because "uninstall" on a box that is serving
# subscribers is one keystroke away from "delete every account I have sold".
# Pass --purge to skip the archive when the intent really is a clean wipe.
#
#   uninstall.sh              interactive, keeps a backup archive
#   uninstall.sh -y           no confirmation prompt, keeps a backup archive
#   uninstall.sh --purge      deletes the data too (asks first, unless -y)
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/hyperdns"
RESOLV_MARKER="${INSTALL_DIR}/.resolv-backup"
FIREWALL_MARKER="${INSTALL_DIR}/.firewall-backup"
BACKUP_ARCHIVE="/root/hyperdns-backup-$(date +%Y%m%d_%H%M%S).tar.gz"

ASSUME_YES=false
PURGE=false

for arg in "$@"; do
    case "${arg}" in
        -y|--yes)
            ASSUME_YES=true
            ;;
        --purge)
            PURGE=true
            ;;
        -h|--help)
            cat <<'USAGE'
HyperDNS uninstaller — reverses the installer, including the changes it makes outside
/opt/hyperdns (the systemd-resolved drop-in, /etc/resolv.conf, firewall rules).

  uninstall.sh              interactive; archives your data to /root first
  uninstall.sh -y, --yes    no confirmation prompt; still archives your data
  uninstall.sh --purge      deletes config.json, data.db and master.key with no backup
  uninstall.sh -h, --help   this text

data.db holds every subscriber and master.key is the only thing that can decrypt it,
so the default run always keeps a copy. --purge is the only way to lose them.
USAGE
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: ${arg}${NC}"
            echo "Usage: uninstall.sh [-y|--yes] [--purge]"
            exit 1
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This uninstall script must be run as root (or with sudo).${NC}"
    exit 1
fi

echo -e "${RED}${BOLD}=========================================================================${NC}"
echo -e "${RED}${BOLD} HyperDNS Clean & Complete Uninstaller${NC}"
echo -e "${RED}${BOLD}=========================================================================${NC}"
echo ""
echo "This uninstaller will completely remove HyperDNS from this server:"
echo "  1. Stop and disable the systemd service ('hyperdns')"
echo "  2. Remove the systemd service unit (/etc/systemd/system/hyperdns.service)"
echo "  3. Restore the system DNS resolver that was replaced to free port 53"
echo "  4. Remove only the firewall rules this server's installer opened"
echo "  5. Archive config.json, data.db, master.key and certs/ to /root"
echo "  6. Remove the global 'hdns' command (/usr/local/bin/hdns)"
echo "  7. Remove ${INSTALL_DIR} entirely"
echo ""

# What is about to be destroyed, named rather than implied. The old wording — "configs,
# certs, logs, and binaries" — did not mention the database at all, and the database is
# the only thing in this directory that matters: data.db holds every subscriber, policy
# and quota counter, and master.key is the AES-256-GCM key without which no copy of that
# database can ever be read again.
if [ -f "${INSTALL_DIR}/data.db" ]; then
    DB_SIZE=$(du -h "${INSTALL_DIR}/data.db" 2>/dev/null | cut -f1 || echo "?")
    echo -e "${YELLOW}${BOLD}Data that lives in ${INSTALL_DIR}:${NC}"
    echo -e "  ${YELLOW}• data.db    (${DB_SIZE}) — every subscriber, policy, and quota counter${NC}"
    echo -e "  ${YELLOW}• master.key — the key data.db is encrypted with. Lose it and no${NC}"
    echo -e "  ${YELLOW}               backup of the database is recoverable, ever.${NC}"
    echo -e "  ${YELLOW}• config.json, certs/ — settings, API key, and TLS material${NC}"
    echo ""
fi

if [ "${PURGE}" = true ]; then
    echo -e "${RED}${BOLD}--purge was passed: NO backup will be taken. This is unrecoverable.${NC}"
else
    echo -e "${CYAN}A backup archive will be written first:${NC}"
    echo -e "${CYAN}  ${BACKUP_ARCHIVE}${NC}"
fi
echo ""

if [ "${ASSUME_YES}" != true ]; then
    if [ "${PURGE}" = true ]; then
        # A typed word rather than y/n, because this branch has no undo.
        read -rp "$(echo -e "${YELLOW}Type DELETE to erase HyperDNS and all subscriber data with no backup: ${NC}")" CONFIRM
        if [ "${CONFIRM}" != "DELETE" ]; then
            echo -e "${YELLOW}Uninstall cancelled. No files were modified.${NC}"
            exit 0
        fi
    else
        read -rp "$(echo -e "${YELLOW}Are you sure you want to completely uninstall HyperDNS? (yes/no): ${NC}")" CONFIRM
        if [ "${CONFIRM}" != "yes" ] && [ "${CONFIRM}" != "y" ] && [ "${CONFIRM}" != "YES" ]; then
            echo -e "${YELLOW}Uninstall cancelled. No files were modified.${NC}"
            exit 0
        fi
    fi
fi

echo ""
echo -e "${CYAN}[1/7] Stopping and disabling the hyperdns service...${NC}"
systemctl stop hyperdns 2>/dev/null || true
systemctl disable hyperdns 2>/dev/null || true

echo -e "${CYAN}[2/7] Removing the systemd service unit...${NC}"
rm -f /etc/systemd/system/hyperdns.service
systemctl daemon-reload 2>/dev/null || true

echo -e "${CYAN}[3/7] Restoring the system DNS resolver...${NC}"
rm -f /etc/systemd/resolved.conf.d/hyperdns.conf

# The drop-in is only half of what step [2/6] of the installer changed. It also replaced
# /etc/resolv.conf, because with DNSStubListener=no the 127.0.0.53 that every generated
# resolv.conf points at has nothing listening on it. Removing the drop-in and restarting
# resolved brings the stub listener back; the resolv.conf that was there before has to be
# put back from the marker the installer left, or the host keeps resolving through
# 1.1.1.1 forever and DHCP- or netplan-supplied nameservers never take effect again.
if [ -f "${RESOLV_MARKER}" ]; then
    RESOLV_KIND=$(head -n 1 "${RESOLV_MARKER}")
    case "${RESOLV_KIND}" in
        symlink)
            RESOLV_TARGET=$(sed -n '2p' "${RESOLV_MARKER}")
            if [ -n "${RESOLV_TARGET}" ]; then
                rm -f /etc/resolv.conf
                ln -s "${RESOLV_TARGET}" /etc/resolv.conf
                echo -e "  ${GREEN}✓ /etc/resolv.conf restored as a symlink to ${RESOLV_TARGET}${NC}"
            fi
            ;;
        file)
            rm -f /etc/resolv.conf
            tail -n +2 "${RESOLV_MARKER}" > /etc/resolv.conf
            echo -e "  ${GREEN}✓ /etc/resolv.conf restored from backup.${NC}"
            ;;
        absent)
            rm -f /etc/resolv.conf
            echo -e "  ${GREEN}✓ /etc/resolv.conf removed (there was none before install).${NC}"
            ;;
        *)
            echo -e "  ${YELLOW}! Resolver marker unreadable; leaving /etc/resolv.conf as it is.${NC}"
            ;;
    esac
else
    echo -e "  ${YELLOW}! No resolver backup found — /etc/resolv.conf left as it is.${NC}"
    echo -e "  ${YELLOW}  If DNS stops working, run: systemctl restart systemd-resolved${NC}"
fi

if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved 2>/dev/null || true
    echo -e "  ${GREEN}✓ systemd-resolved restarted; the port 53 stub listener is back.${NC}"
fi

echo -e "${CYAN}[4/7] Removing the firewall rules this installer opened...${NC}"

# Only the rules recorded at install time, and only the ones that were not already there.
# An uninstaller that closed every port unconditionally would close 80, 443 or 8080 on a
# server that was using them before HyperDNS was ever installed.
if [ -f "${FIREWALL_MARKER}" ]; then
    REMOVED=0
    ABSENT=0
    while read -r backend port; do
        if [ -n "${backend}" ] && [ -n "${port}" ]; then
            case "${backend}" in
                ufw)
                    # The exit status cannot be counted here: `ufw delete allow 9999` prints
                    # "Could not delete non-existent rule" and still exits 0. The number below
                    # is read out to the operator as a fact about their firewall, so a rule
                    # they had already removed by hand must not be reported as one this
                    # script closed. The output is what distinguishes the two.
                    if command -v ufw >/dev/null 2>&1; then
                        OUT="$(ufw delete allow "${port}" 2>&1)"
                        case "${OUT}" in
                            *non-existent*) ABSENT=$((ABSENT + 1)) ;;
                            *) REMOVED=$((REMOVED + 1)) ;;
                        esac
                    fi
                    ;;
                firewalld)
                    # Same shape of answer from firewall-cmd, which prints
                    # "Warning: NOT_ENABLED" and exits 0 for a port that is not in the
                    # permanent configuration.
                    if command -v firewall-cmd >/dev/null 2>&1; then
                        OUT="$(firewall-cmd --permanent --remove-port="${port}" 2>&1)"
                        case "${OUT}" in
                            *NOT_ENABLED*) ABSENT=$((ABSENT + 1)) ;;
                            *) REMOVED=$((REMOVED + 1)) ;;
                        esac
                    fi
                    ;;
            esac
        fi
    done < "${FIREWALL_MARKER}"
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    echo -e "  ${GREEN}✓ ${REMOVED} firewall rule(s) removed; anything you added yourself was left alone.${NC}"
    if [ "${ABSENT}" -gt 0 ]; then
        echo -e "  ${YELLOW}  ${ABSENT} recorded rule(s) had already been removed by hand.${NC}"
    fi
else
    echo -e "  ${YELLOW}! No firewall marker found. Rules were left untouched — review them with:${NC}"
    echo -e "  ${YELLOW}    ufw status   (or)   firewall-cmd --list-ports${NC}"
fi

echo -e "${CYAN}[5/7] Archiving configuration, database, and keys...${NC}"
if [ "${PURGE}" = true ]; then
    echo -e "  ${RED}Skipped: --purge was passed, so nothing is being kept.${NC}"
elif [ -d "${INSTALL_DIR}" ]; then
    # tar is given explicit member names rather than the whole directory, so the archive
    # carries what cannot be reinstalled and not the 12 MB binary or a backups/ tree that
    # may already hold several copies of itself.
    ARCHIVE_MEMBERS=""
    for member in config.json data.db master.key certs; do
        if [ -e "${INSTALL_DIR}/${member}" ]; then
            ARCHIVE_MEMBERS="${ARCHIVE_MEMBERS} ${member}"
        fi
    done
    if [ -n "${ARCHIVE_MEMBERS}" ]; then
        # ARCHIVE_MEMBERS is a deliberate word list of fixed, space-free names.
        # shellcheck disable=SC2086
        if tar -czf "${BACKUP_ARCHIVE}" -C "${INSTALL_DIR}" ${ARCHIVE_MEMBERS} 2>/dev/null; then
            chmod 600 "${BACKUP_ARCHIVE}" 2>/dev/null || true
            ARCHIVE_SIZE=$(du -h "${BACKUP_ARCHIVE}" 2>/dev/null | cut -f1 || echo "?")
            echo -e "  ${GREEN}✓ Backup written: ${BACKUP_ARCHIVE} (${ARCHIVE_SIZE}, mode 600)${NC}"
            echo -e "  ${CYAN}  After reinstalling, restore with: bash ${INSTALL_DIR}/scripts/restore.sh '${BACKUP_ARCHIVE}'${NC}"
        else
            echo -e "  ${RED}✗ Backup failed. Nothing has been deleted yet — resolve this first,${NC}"
            echo -e "  ${RED}  or re-run with --purge if you genuinely do not want the data.${NC}"
            exit 1
        fi
    else
        echo -e "  ${YELLOW}! Nothing to archive (no config.json, data.db, master.key, or certs/).${NC}"
    fi
else
    echo -e "  ${YELLOW}! ${INSTALL_DIR} does not exist; nothing to archive.${NC}"
fi

echo -e "${CYAN}[6/7] Removing the global CLI command 'hdns'...${NC}"
# Only if it is this installation's symlink. install.sh creates it with `ln -sf`, so a
# regular file of the same name belongs to something else and is left where it is.
if [ -L /usr/local/bin/hdns ]; then
    rm -f /usr/local/bin/hdns
elif [ -e /usr/local/bin/hdns ]; then
    echo -e "  ${YELLOW}! /usr/local/bin/hdns is not a symlink; leaving it in place.${NC}"
fi

echo -e "${CYAN}[7/7] Removing ${INSTALL_DIR}...${NC}"
rm -rf "${INSTALL_DIR}"

echo ""
echo -e "${GREEN}${BOLD}✓ HyperDNS has been cleanly and completely uninstalled.${NC}"
if [ "${PURGE}" != true ] && [ -f "${BACKUP_ARCHIVE}" ]; then
    echo -e "${CYAN}Your data is not gone — it is in ${BACKUP_ARCHIVE}${NC}"
    echo -e "${CYAN}Keep master.key with it: the database inside cannot be decrypted without it.${NC}"
fi
echo -e "${CYAN}System DNS resolvers have been restored. Thank you for using HyperDNS! 👋${NC}"
echo ""
