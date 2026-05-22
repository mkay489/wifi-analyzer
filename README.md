# wifi-analyzer  WiFi Network Scanner and Beacon Frame Analyzer

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

Passive WiFi scanner that captures and analyzes 802.11 beacon frames.
Detects nearby networks, encryption types, signal strength, and probing clients.

```
 __        ___ _____ _
 \ \      / (_)  ___(_)
  \ \ /\ / /| | |_  | |
   \ V  V / | |  _| | |
    \_/\_/  |_|_|   |_|
```

## Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Only analyze networks you own or have explicit written permission to test.
Passive capture of beacon frames is generally legal, but laws vary by jurisdiction.

## Features

Passive capture of 802.11 beacon frames, no active probing.
Detects SSID, BSSID, channel, band (2.4 GHz or 5 GHz), encryption type and signal strength.
Flags open and WEP networks.
Captures probe requests to identify clients searching for networks.
JSON output for easy post-processing.
Clean terminal output with signal strength display.

## Requirements

A wireless adapter that supports monitor mode.
Linux (tested on Kali, Ubuntu, ParrotOS).
Root or sudo privileges for raw socket access.

## Installation

```bash
git clone https://github.com/yourusername/wifi-analyzer.git
cd wifi-analyzer
pip install -r requirements.txt
```

## Setup Monitor Mode

```bash
# Check your interface name
ip link show

# Put interface into monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Or use airmon-ng (from aircrack-ng suite)
sudo airmon-ng start wlan0
# This creates wlan0mon
```

## Usage

```bash
# Basic scan, infinite, Ctrl+C to stop
sudo python wifi_analyzer.py -i wlan0mon

# Scan for 60 seconds
sudo python wifi_analyzer.py -i wlan0mon -t 60

# Save results to JSON
sudo python wifi_analyzer.py -i wlan0mon -o results.json

# All options
sudo python wifi_analyzer.py -i wlan0mon -t 120 -o scan.json
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| -i / --interface | Monitor mode interface | required |
| -t / --timeout | Scan duration in seconds (0 = infinite) | 0 |
| -o / --output | Save results to JSON file | none |
| --show-hidden | Include hidden SSIDs in output | false |

## Example Output

```
[*] Interface : wlan0mon
[*] Timeout   : infinite (Ctrl+C to stop)
[*] Started   : 2025-01-15 14:32:01
============================================================
  SSID                           BSSID              ENC
============================================================
  [NEW]  HomeNetwork               aa:bb:cc:dd:ee:ff | CH:  6 | WPA2       | -65 dBm
  [NEW]  OldRouter                 11:22:33:44:55:66 | CH: 11 | WEP        | -72 dBm [OPEN]
  [NEW]  CoffeeShop_Free           ff:ee:dd:cc:bb:aa | CH:  1 | OPN        | -55 dBm [OPEN]
  [NEW]  Office5G                  ab:cd:ef:12:34:56 | CH: 36 | WPA2       | -48 dBm


==========================================================================================
  SCAN SUMMARY  4 networks found | 1248 packets captured
==========================================================================================
  SSID                           BSSID                CH BAND     ENC          SIGNAL
==========================================================================================
  Office5G                       ab:cd:ef:12:34:56    36 5 GHz    WPA2         -48 dBm  [####] Excellent
  CoffeeShop_Free                ff:ee:dd:cc:bb:aa     1 2.4 GHz  OPN          -55 dBm  [###.] Good     OPEN
  HomeNetwork                    aa:bb:cc:dd:ee:ff     6 2.4 GHz  WPA2         -65 dBm  [##..] Fair
  OldRouter                      11:22:33:44:55:66    11 2.4 GHz  WEP          -72 dBm  [#...] Weak     OPEN

  PROBE REQUESTS  2 unique clients
==========================================================================================
  aa:bb:cc:11:22:33  looking for: HomeNetwork, PreviousOffice
  dd:ee:ff:44:55:66  looking for: Starbucks_Free

  Scan duration: 45.2s
==========================================================================================
```

## JSON Output Format

```json
{
  "timestamp": "2025-01-15T14:32:46",
  "duration_seconds": 45.2,
  "packets_captured": 1248,
  "networks": [
    {
      "ssid": "HomeNetwork",
      "bssid": "aa:bb:cc:dd:ee:ff",
      "channel": 6,
      "band": "2.4 GHz",
      "encryption": "WPA2",
      "rssi": -65,
      "first_seen": "2025-01-15T14:32:01",
      "last_seen": "2025-01-15T14:32:44",
      "beacons": 87
    }
  ],
  "probe_clients": {
    "aa:bb:cc:11:22:33": ["HomeNetwork", "PreviousOffice"]
  }
}
```

## Project Structure

```
wifi-analyzer/
    wifi_analyzer.py    Main script
    requirements.txt    Dependencies
    README.md
```

## License

MIT
