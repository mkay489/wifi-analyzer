#!/usr/bin/env python3
"""
wifi_analyzer.py  WiFi Network Scanner and Beacon Frame Analyzer
Author: github.com/yourusername
Educational purposes only. Only analyze networks you own or have permission to test.
"""

import sys
import time
import json
import argparse
import signal
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import sniff
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
except ImportError:
    print("[!] Missing dependency. Run: pip install scapy")
    sys.exit(1)

BANNER = r"""
 __        ___ _____ _
 \ \      / (_)  ___(_)
  \ \ /\ / /| | |_  | |
   \ V  V / | |  _| | |
    \_/\_/  |_|_|   |_|
  ___                _
 / _ \  ___ __ _ _ | |_ ___ _ __
| | | |/ __/ _` | || __/ _ \ '__|
| |_| | (_| (_| | || ||  __/ |
 \___/ \___\__,_|_| \__\___|_|

  WiFi Beacon Analyzer v1.0  @yourusername
  For authorized use only.
"""

networks = {}
probe_clients = defaultdict(set)
start_time = time.time()
packet_count = 0
args_global = None


def get_encryption(packet) -> str:
    crypto = set()

    if packet.haslayer(Dot11Elt):
        elt = packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 48:
                crypto.add("WPA2")
            elif elt.ID == 221 and elt.info[:4] == b'\x00P\xf2\x01':
                crypto.add("WPA")
            elt = elt.payload

    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
    if "privacy" in cap:
        if not crypto:
            crypto.add("WEP")
    else:
        if not crypto:
            crypto.add("OPN")

    return "/".join(sorted(crypto)) if crypto else "Unknown"


def get_channel(packet) -> int:
    try:
        if packet.haslayer(Dot11Elt):
            elt = packet[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3:
                    return ord(elt.info) if isinstance(elt.info, str) else elt.info[0]
                elt = elt.payload
    except Exception:
        pass
    return 0


def get_signal(packet) -> int:
    try:
        if packet.haslayer(RadioTap):
            val = packet[RadioTap].dBm_AntSignal
            return -(256 - val) if val else -100
    except Exception:
        pass
    return -100


def signal_to_bars(rssi: int) -> str:
    if rssi >= -50:
        return "[####] Excellent"
    elif rssi >= -60:
        return "[###.] Good"
    elif rssi >= -70:
        return "[##..] Fair"
    elif rssi >= -80:
        return "[#...] Weak"
    else:
        return "[....] Poor"


def packet_handler(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
        try:
            ssid = packet[Dot11Elt].info.decode("utf-8", errors="replace").strip()
        except Exception:
            ssid = "<hidden>"

        ssid = ssid if ssid else "<hidden>"
        channel = get_channel(packet)
        encryption = get_encryption(packet)
        rssi = get_signal(packet)
        band = "5 GHz" if channel > 14 else "2.4 GHz"

        if bssid not in networks:
            networks[bssid] = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "band": band,
                "encryption": encryption,
                "rssi": rssi,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "beacons": 1,
            }
            warn = " [OPEN]" if encryption in ("OPN", "WEP") else ""
            print(f"  [NEW]  {ssid:30s} | {bssid} | CH:{channel:3d} | {encryption:10s} | {rssi} dBm{warn}")
        else:
            networks[bssid]["last_seen"] = datetime.now().isoformat()
            networks[bssid]["beacons"] += 1
            networks[bssid]["rssi"] = rssi

    elif packet.haslayer(Dot11) and packet[Dot11].type == 0 and packet[Dot11].subtype == 4:
        client_mac = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode("utf-8", errors="replace").strip()
        except Exception:
            ssid = ""
        if client_mac and ssid:
            probe_clients[client_mac].add(ssid)


def print_summary():
    print("\n")
    print("=" * 90)
    print(f"  SCAN SUMMARY  {len(networks)} networks found | {packet_count} packets captured")
    print("=" * 90)
    print(f"  {'SSID':<30} {'BSSID':<20} {'CH':>4} {'BAND':<8} {'ENC':<12} {'SIGNAL'}")
    print("=" * 90)

    for net in sorted(networks.values(), key=lambda x: x["rssi"], reverse=True):
        bars = signal_to_bars(net["rssi"])
        warn = " OPEN" if net["encryption"] in ("OPN", "WEP") else "    "
        print(f"  {net['ssid']:<30} {net['bssid']:<20} {net['channel']:>4} "
              f"{net['band']:<8} {net['encryption']:<10} {net['rssi']:>4} dBm  {bars}{warn}")

    if probe_clients:
        print(f"\n  PROBE REQUESTS  {len(probe_clients)} unique clients")
        print("=" * 90)
        for mac, ssids in list(probe_clients.items())[:10]:
            print(f"  {mac}  looking for: {', '.join(list(ssids)[:5])}")

    elapsed = time.time() - start_time
    print(f"\n  Scan duration: {elapsed:.1f}s")
    print("=" * 90)


def save_results(output_path: str):
    data = {
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": round(time.time() - start_time, 2),
        "packets_captured": packet_count,
        "networks": list(networks.values()),
        "probe_clients": {mac: list(ssids) for mac, ssids in probe_clients.items()}
    }
    Path(output_path).write_text(json.dumps(data, indent=2))
    print(f"\n[+] Results saved to {output_path}")


def signal_handler(sig, frame):
    print_summary()
    if args_global and args_global.output:
        save_results(args_global.output)
    sys.exit(0)


def main():
    global args_global

    parser = argparse.ArgumentParser(
        description="WiFi Beacon Frame Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Monitor mode interface (e.g. wlan0mon)")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="Scan duration in seconds (0 = infinite, use Ctrl+C to stop)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--show-hidden", action="store_true",
                        help="Include networks with hidden SSIDs in output")
    args = parser.parse_args()
    args_global = args

    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    print(f"[*] Interface : {args.interface}")
    print(f"[*] Timeout   : {'infinite (Ctrl+C to stop)' if args.timeout == 0 else str(args.timeout) + 's'}")
    print(f"[*] Output    : {args.output if args.output else 'none'}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  {'SSID':<30} {'BSSID':<20} ENC")
    print("=" * 60)

    timeout = args.timeout if args.timeout > 0 else None

    sniff(
        iface=args.interface,
        prn=packet_handler,
        store=False,
        timeout=timeout
    )

    print_summary()
    if args.output:
        save_results(args.output)


if __name__ == "__main__":
    main()
