# scan_blu

A Bluetooth / BLE scanner and enumerator written in C for Linux (Arch-friendly).
Built on top of **BlueZ** for radio access and **SQLite** for device history.

It can sweep classic BR/EDR and BLE devices, enumerate GATT services and
characteristics, run a lightweight security scan, monitor an area continuously,
and export results to CSV — all from a single CLI binary.

---

## Features

- **BR/EDR scan** — classic Bluetooth inquiry with vendor lookup
- **BLE scan** — Low Energy advertisement scan with RSSI
- **GATT enumeration** — list services and characteristics for a given MAC
- **Security scan** — flag exposed/sensitive characteristics by UUID
- **Continuous monitor** — track devices over time with first/last seen
- **CSV export** — dump scan results to a timestamped CSV file
- **Device history** — every sighting is recorded into `ble_devices.db` (SQLite, WAL mode)
- **Vendor OUI lookup** — built-in table for common manufacturers
- **Interactive mode** — pick a device from a list, then enumerate it
- **Headless mode** — `--headless` strips ANSI colors for logs/pipelines
- **Robust CLI** — strict argument validation, signal-safe `SIGINT`/`SIGTERM` handling

---

## Build

### Dependencies (Arch Linux)

```bash
sudo pacman -S bluez bluez-libs sqlite
```

### Compile

```bash
gcc scan_blu.c -o scan_blu \
    $(pkg-config --cflags --libs bluez) \
    -lsqlite3 -lm -Wall -Wextra -O2
```

The binary needs raw HCI access, so most commands must be run as **root**
(or with `CAP_NET_ADMIN` / `CAP_NET_RAW`).

---

## Usage

```
scan_blu [--headless] <command> [options]
```

### Commands

| Command       | Arguments                       | Description                             |
|---------------|---------------------------------|-----------------------------------------|
| `list`        | `[-w SECS]`                     | Quick BLE device list                   |
| `scan`        | `[-b] [-t SECS]`                | Scan for BR/EDR (default) or BLE (`-b`) |
| `enum`        | `<MAC> [-b]`                    | Enumerate SDP / GATT services           |
| `interactive` | `[-b]`                          | Scan, pick a device, then enumerate     |
| `export`      | `[-b] [-t SECS] [-o FILE]`      | Scan and dump to CSV                    |
| `monitor`     | `[-d SECS] [-i SECS]`           | Continuous BLE monitor                  |
| `security`    | `<MAC>`                         | BLE security scan                       |
| `history`     | `<MAC> [-n LIMIT]`              | Show stored sightings for a MAC         |
| `vendors`     |                                 | List known OUI prefixes                 |

### Global options

- `--headless` — disable ANSI colors (good for logs / pipes)
- `-h`, `--help` — show usage

### Examples

```bash
# Classic BR/EDR scan
sudo ./scan_blu scan

# BLE scan with a 10-second timeout
sudo ./scan_blu scan --ble -t 10

# Quick BLE list
sudo ./scan_blu list

# Enumerate GATT services on a BLE device
sudo ./scan_blu enum AA:BB:CC:DD:EE:FF --ble

# Continuous monitor for 5 minutes, refreshing every 10 seconds
sudo ./scan_blu monitor -d 300 -i 10

# Run a BLE security scan
sudo ./scan_blu security AA:BB:CC:DD:EE:FF

# Export a BLE scan to CSV (auto-named ble_scan_YYYYMMDD_HHMMSS.csv)
sudo ./scan_blu export --ble -t 8

# Show the last 100 sightings of a device
sudo ./scan_blu history AA:BB:CC:DD:EE:FF -n 100

# Headless logging (no colors)
sudo ./scan_blu --headless scan --ble
```

---

## Database

Sightings are persisted to `ble_devices.db` in the current working directory.
The schema is initialized on first run:

- `device_history` — one row per sighting (MAC, name, RSSI, vendor, type, timestamp)
- `device_profiles` — one row per device (first seen, last seen, times seen)

WAL journaling is enabled and a 5-second busy timeout is set, so concurrent
reads (e.g. via the `sqlite3` CLI) won't block writes.

---

## Notes

- `python` on Arch already points to Python 3 — no `python3` needed for the
  helper scripts in this tree.
- ANSI color output is auto-disabled with `--headless`, which is what you want
  when piping logs into `journald`, `tee`, or a file.
- The vendor OUI table is intentionally small and hardcoded; extend
  `VENDORS[]` in `scan_blu.c` to add more.
- All MAC inputs are validated (`XX:XX:XX:XX:XX:XX`, hex only) before any
  socket call.

---

## License

MIT License

Copyright (c) 2026 Acheron-HSR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
