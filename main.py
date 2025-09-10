#!/usr/bin/env python3
# Zero-config BACnet/IP discovery (like YABE)
import asyncio
from datetime import datetime
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
import argparse
import json
import psutil

from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.ipv4.link import IPv4Address


DEFAULT_PORT = 47808
DEFAULT_SCAN_INTERVAL = 30
DEFAULT_TIMEOUT = 7


def detect_primary_ipv4() -> tuple[str, str]:
    """
    Return (interface_cidr, broadcast_ip) for the first 'up' non-loopback IPv4 NIC.
    Example: ("192.168.163.100/24", "192.168.163.255")
    """
    # Prefer adapters with private IPv4 ranges
    candidates = []
    for ifname, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(ifname)
        if not stats or not stats.isup:
            continue
        for a in addrs:
            if getattr(a, "family", None).__class__.__name__ != "AddressFamily":
                # older psutil on Windows shows .family == 2 for AF_INET
                pass
            if getattr(a, "family", None) != psutil.AddressFamily.AF_INET:
                if getattr(a, "family", None) != 2:  # AF_INET value on some builds
                    continue
            ip = a.address
            if ip.startswith("127."):
                continue
            netmask = a.netmask or "255.255.255.0"
            iface = IPv4Interface(f"{ip}/{netmask}")
            network: IPv4Network = iface.network
            bcast = str(network.broadcast_address)
            cidr = f"{ip}/{iface.network.prefixlen}"
            # Private ranges get priority
            private = IPv4Interface(f"{ip}/32").ip.is_private
            candidates.append(((cidr, bcast), 0 if private else 1))

    if not candidates:
        # last resort: let stack decide
        return ("0.0.0.0/24", "255.255.255.255")

    # pick best (private first)
    candidates.sort(key=lambda x: x[1])
    return candidates[0][0]


def load_config(optional_path: str | None) -> dict:
    cfg: dict = {}
    path = Path(optional_path) if optional_path else Path("config.json")
    if path.exists():
        with path.open() as f:
            cfg = json.load(f)
    # Autofill missing fields
    if not cfg.get("interface"):
        iface_cidr, bcast = detect_primary_ipv4()
        cfg["interface"] = iface_cidr
        cfg.setdefault("broadcast_address", bcast)
    cfg.setdefault("local_port", DEFAULT_PORT)
    cfg.setdefault("port", DEFAULT_PORT)
    cfg.setdefault("local_device_id", 12345)
    cfg.setdefault("vendor_identifier", 999)
    cfg.setdefault("vendor_name", "BACnetViewer")
    cfg.setdefault("scan_interval", DEFAULT_SCAN_INTERVAL)
    cfg.setdefault("request_timeout", DEFAULT_TIMEOUT)
    return cfg


def print_device_table(rows: list[tuple]):
    headers = ["Timestamp", "Device ID", "Name", "Address"]
    colw = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            colw[i] = max(colw[i], len(str(cell)))
    sep = "+" + "+".join("-" * (w + 2) for w in colw) + "+"
    print(sep)
    print("| " + " | ".join(h.ljust(colw[i]) for i, h in enumerate(headers)) + " |")
    print(sep)
    for r in rows:
        print("| " + " | ".join(str(r[i]).ljust(colw[i]) for i in range(len(headers))) + " |")
    print(sep)


async def main():
    parser = argparse.ArgumentParser(description="Zero-config BACnet/IP device discovery")
    parser.add_argument("--config", help="Optional path to config.json (if omitted, auto-detect NIC)")
    parser.add_argument("--iface", help="Override interface CIDR (e.g. 192.168.1.10/24)")
    parser.add_argument("--port", type=int, help="Local UDP port (default 47808)")
    parser.add_argument("--interval", type=int, help="Seconds between scans")
    parser.add_argument("--timeout", type=float, help="Request timeout (s)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    # CLI overrides
    if args.iface:
        cfg["interface"] = args.iface
    if args.port:
        cfg["local_port"] = args.port
        cfg["port"] = args.port
    if args.interval:
        cfg["scan_interval"] = args.interval
    if args.timeout:
        cfg["request_timeout"] = args.timeout

    # Local scanner device
    scanner = DeviceObject(
        objectName="BACnetDebugger",
        objectIdentifier=("device", cfg["local_device_id"]),
        vendorIdentifier=cfg["vendor_identifier"],
        vendorName=cfg["vendor_name"],
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )

    local_addr = IPv4Address(cfg["interface"], cfg["local_port"])
    app = NormalApplication(scanner, local_addr)

    print(f"[INFO] Bound to {cfg['interface']} on UDP {cfg['local_port']}")
    print(f"[INFO] Will broadcast Who-Is every {cfg['scan_interval']}s (timeout={cfg['request_timeout']}s)")

    try:
        while True:
            print("\n[INFO] Sending Who-Is…")
            # Let bacpypes3 choose the correct broadcast for the bound interface
            i_ams = await app.who_is(timeout=cfg["request_timeout"])

            if not i_ams:
                print("[INFO] Discovered devices:\n  (no replies)")
            else:
                rows = []
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for apdu in i_ams:
                    # apdu.iAmDeviceIdentifier is a ('device', instance) tuple
                    dev_id = apdu.iAmDeviceIdentifier
                    try:
                        name = await app.read_property(apdu.pduSource, dev_id, "objectName")
                    except Exception:
                        name = ""
                    rows.append((now, f"{dev_id[0]},{dev_id[1]}", name, str(apdu.pduSource)))
                print("[INFO] Discovered devices:")
                print_device_table(rows)

            await asyncio.sleep(cfg["scan_interval"])

    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        app.close()


if __name__ == "__main__":
    asyncio.run(main())
