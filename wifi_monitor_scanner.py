#!/usr/bin/env python3
"""
WiFi Monitor Scanner - deteksi jaringan Wi-Fi sekitar dari interface monitor mode.

Gunakan hanya untuk audit jaringan milik sendiri atau lingkungan yang diizinkan.
Tool ini pasif: hanya membaca beacon/probe response dan tidak mengirim deauth,
tidak cracking password, dan tidak mengambil isi trafik pengguna.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff
except ImportError:  # pragma: no cover - pesan runtime untuk user
    Dot11 = Dot11Beacon = Dot11Elt = Dot11ProbeResp = RadioTap = None
    sniff = None


DEFAULT_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161]


@dataclass
class Network:
    bssid: str
    ssid: str = "<hidden>"
    channel: int | None = None
    frequency: int | None = None
    security: str = "unknown"
    signal_dbm: int | None = None
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    frames: int = 0


class ScannerState:
    def __init__(self) -> None:
        self.networks: dict[str, Network] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()


def require_scapy() -> None:
    if sniff is None:
        raise RuntimeError(
            "Scapy belum tersedia. Install dengan: python3 -m pip install scapy"
        )


def decode_ssid(raw: bytes | str | None) -> str:
    if raw is None:
        return "<hidden>"
    if isinstance(raw, str):
        value = raw
    else:
        value = raw.decode("utf-8", errors="replace")
    value = value.replace("\x00", "").strip()
    return value or "<hidden>"


def parse_elements(packet) -> tuple[str, int | None, str]:
    ssid = "<hidden>"
    channel = None
    security_flags = set()

    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        elt_id = elt.ID
        info = elt.info

        if elt_id == 0:
            ssid = decode_ssid(info)
        elif elt_id == 3 and info:
            channel = int(info[0])
        elif elt_id == 48:
            security_flags.add("WPA2/RSN")
        elif elt_id == 221 and info:
            if info.startswith(b"\x00P\xf2\x01\x01\x00"):
                security_flags.add("WPA")
            elif info.startswith(b"\x00P\xf2\x04"):
                security_flags.add("WPS")

        elt = elt.payload.getlayer(Dot11Elt)

    capability = int(packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}") or 0)
    privacy = bool(capability & 0x10)
    if privacy and not security_flags:
        security_flags.add("WEP/unknown")
    if not privacy and not security_flags:
        security_flags.add("open")

    return ssid, channel, "+".join(sorted(security_flags))


def packet_frequency(packet) -> int | None:
    try:
        if packet.haslayer(RadioTap) and getattr(packet[RadioTap], "ChannelFrequency", None):
            return int(packet[RadioTap].ChannelFrequency)
    except Exception:
        return None
    return None


def packet_signal(packet) -> int | None:
    for attr in ("dBm_AntSignal", "dBm_ant_signal"):
        try:
            value = getattr(packet, attr, None)
            if value is not None:
                return int(value)
        except Exception:
            pass
    try:
        if packet.haslayer(RadioTap):
            value = getattr(packet[RadioTap], "dBm_AntSignal", None)
            if value is not None:
                return int(value)
    except Exception:
        pass
    return None


def oui_prefix(mac: str) -> str:
    parts = mac.upper().split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def handle_packet(packet, state: ScannerState) -> None:
    if not packet.haslayer(Dot11):
        return
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    bssid = (packet[Dot11].addr3 or packet[Dot11].addr2 or "").lower()
    if not bssid:
        return

    try:
        ssid, channel, security = parse_elements(packet)
    except Exception:
        ssid, channel, security = "<hidden>", None, "unknown"

    now = time.time()
    signal_dbm = packet_signal(packet)
    frequency = packet_frequency(packet)

    with state.lock:
        existing = state.networks.get(bssid)
        if existing is None:
            state.networks[bssid] = Network(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                frequency=frequency,
                security=security,
                signal_dbm=signal_dbm,
                vendor=oui_prefix(bssid),
                first_seen=now,
                last_seen=now,
                frames=1,
            )
            return

        if existing.ssid == "<hidden>" and ssid != "<hidden>":
            existing.ssid = ssid
        if channel is not None:
            existing.channel = channel
        if frequency is not None:
            existing.frequency = frequency
        if security != "unknown":
            existing.security = security
        if signal_dbm is not None:
            existing.signal_dbm = signal_dbm
        existing.last_seen = now
        existing.frames += 1


def sorted_networks(state: ScannerState) -> list[Network]:
    with state.lock:
        items = list(state.networks.values())
    return sorted(
        items,
        key=lambda item: (
            item.signal_dbm is None,
            -(item.signal_dbm or -999),
            item.channel or 999,
            item.ssid,
        ),
    )


def print_table(state: ScannerState, clear: bool = True) -> None:
    networks = sorted_networks(state)
    if clear:
        print("\033[2J\033[H", end="")

    print(f"WiFi Monitor Scanner - jaringan ditemukan: {len(networks)}")
    print("Tekan Ctrl+C untuk berhenti.\n")
    print(f"{'RSSI':>5}  {'CH':>3}  {'SECURITY':<16}  {'BSSID':<17}  SSID")
    print("-" * 78)
    for net in networks[:80]:
        rssi = str(net.signal_dbm) if net.signal_dbm is not None else "?"
        channel = str(net.channel) if net.channel is not None else "?"
        ssid = net.ssid[:40]
        print(f"{rssi:>5}  {channel:>3}  {net.security:<16}  {net.bssid:<17}  {ssid}")
    print()


def display_loop(state: ScannerState, interval: float) -> None:
    while not state.stop_event.wait(interval):
        print_table(state)


def set_channel(interface: str, channel: int) -> bool:
    if shutil.which("iw") is None:
        return False
    result = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def channel_hopper(state: ScannerState, interface: str, channels: list[int], dwell: float) -> None:
    idx = 0
    while not state.stop_event.is_set():
        set_channel(interface, channels[idx % len(channels)])
        idx += 1
        state.stop_event.wait(dwell)


def parse_channels(raw: str) -> list[int]:
    channels = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(f"Range channel tidak valid: {part}")
            channels.extend(range(start, end + 1))
        else:
            channels.append(int(part))

    unique = sorted({channel for channel in channels if channel > 0})
    if not unique:
        raise argparse.ArgumentTypeError("Daftar channel kosong.")
    return unique


def save_json(path: str, networks: list[Network]) -> None:
    payload = [asdict(item) for item in networks]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def save_csv(path: str, networks: list[Network]) -> None:
    fields = [
        "ssid",
        "bssid",
        "channel",
        "frequency",
        "security",
        "signal_dbm",
        "vendor",
        "first_seen",
        "last_seen",
        "frames",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in networks:
            writer.writerow(asdict(item))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deteksi jaringan Wi-Fi sekitar memakai interface monitor mode secara pasif."
    )
    parser.add_argument("-i", "--interface", required=True, help="Interface monitor mode, contoh: wlan0mon")
    parser.add_argument("-t", "--time", type=int, default=30, help="Durasi scan dalam detik. Default: 30")
    parser.add_argument("--no-hop", action="store_true", help="Jangan lakukan channel hopping.")
    parser.add_argument(
        "--channels",
        type=parse_channels,
        default=DEFAULT_CHANNELS,
        help="Daftar channel, contoh: 1,6,11 atau 1-13. Default: channel umum 2.4/5 GHz.",
    )
    parser.add_argument("--dwell", type=float, default=0.75, help="Durasi per channel saat hopping. Default: 0.75")
    parser.add_argument("--refresh", type=float, default=1.0, help="Refresh tampilan dalam detik. Default: 1.0")
    parser.add_argument("--json", help="Simpan hasil akhir ke file JSON.")
    parser.add_argument("--csv", help="Simpan hasil akhir ke file CSV.")
    parser.add_argument("--quiet", action="store_true", help="Tidak menampilkan tabel live, hanya ringkasan akhir.")
    return parser.parse_args(list(argv))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.time < 1 or args.dwell <= 0 or args.refresh <= 0:
        print("Argumen time, dwell, dan refresh harus valid.", file=sys.stderr)
        return 2

    try:
        require_scapy()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    state = ScannerState()

    def stop_handler(signum, frame) -> None:
        state.stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    threads: list[threading.Thread] = []
    if not args.no_hop:
        hopper = threading.Thread(
            target=channel_hopper,
            args=(state, args.interface, args.channels, args.dwell),
            daemon=True,
        )
        hopper.start()
        threads.append(hopper)

    if not args.quiet:
        display = threading.Thread(target=display_loop, args=(state, args.refresh), daemon=True)
        display.start()
        threads.append(display)

    try:
        sniff(
            iface=args.interface,
            prn=lambda packet: handle_packet(packet, state),
            store=False,
            timeout=args.time,
            stop_filter=lambda packet: state.stop_event.is_set(),
        )
    except PermissionError:
        print("Error: butuh root/capability untuk sniffing. Jalankan dengan sudo.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error interface: {exc}", file=sys.stderr)
        return 1
    finally:
        state.stop_event.set()
        for thread in threads:
            thread.join(timeout=1)

    networks = sorted_networks(state)
    print_table(state, clear=not args.quiet)

    if args.json:
        save_json(args.json, networks)
        print(f"Hasil JSON disimpan ke {args.json}")
    if args.csv:
        save_csv(args.csv, networks)
        print(f"Hasil CSV disimpan ke {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
