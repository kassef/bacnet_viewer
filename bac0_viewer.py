#!/usr/bin/env python3
"""BAC0 based zero-config BACnet/IP discovery and inspection.

This script mirrors the behaviour of ``main.py`` but uses the BAC0
stack instead of bacpypes3.  It keeps a simple interactive command
line interface and tries to be usable without any configuration
files.  When ``config.json`` is present it can override the auto
configuration values.
"""

import argparse
import asyncio
import csv
import json
import socket
import time
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import BAC0
import psutil

DEFAULT_PORT = 47808
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 7
DEFAULT_RETRIES = 1
DEFAULT_CONCURRENCY = 16
DEFAULT_MAX_INDEX = 256

# common object types probed when objectList is not available
COMMON_TYPES = [
    "analogValue",
    "analogInput",
    "analogOutput",
    "binaryValue",
    "binaryInput",
    "binaryOutput",
    "multiStateValue",
    "multiStateInput",
    "multiStateOutput",
]


def detect_primary_ipv4() -> Tuple[str, str]:
    """Return ``(interface_cidr, broadcast)`` for first up non-loopback NIC."""
    candidates: List[Tuple[Tuple[str, str], int]] = []
    for ifname, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(ifname)
        if not stats or not stats.isup:
            continue
        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            ip = a.address
            if ip.startswith("127."):
                continue
            netmask = a.netmask or "255.255.255.0"
            iface = IPv4Interface(f"{ip}/{netmask}")
            network: IPv4Network = iface.network
            bcast = str(network.broadcast_address)
            cidr = f"{ip}/{network.prefixlen}"
            private = IPv4Interface(f"{ip}/32").ip.is_private
            candidates.append(((cidr, bcast), 0 if private else 1))
    if not candidates:
        return ("0.0.0.0/24", "255.255.255.255")
    candidates.sort(key=lambda x: x[1])
    return candidates[0][0]


def load_config(optional_path: Optional[str]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    path = Path(optional_path) if optional_path else Path("config.json")
    if path.exists():
        with path.open() as f:
            cfg = json.load(f)
    if not cfg.get("interface"):
        iface_cidr, _ = detect_primary_ipv4()
        cfg["interface"] = iface_cidr
    cfg.setdefault("port", DEFAULT_PORT)
    cfg.setdefault("interval", DEFAULT_INTERVAL)
    cfg.setdefault("timeout", DEFAULT_TIMEOUT)
    cfg.setdefault("retries", DEFAULT_RETRIES)
    cfg.setdefault("concurrency", DEFAULT_CONCURRENCY)
    cfg.setdefault("max_index", DEFAULT_MAX_INDEX)
    cfg.setdefault("types", COMMON_TYPES)
    return cfg


def print_device_table(rows: List[Tuple[Any, ...]]):
    headers = ["Idx", "Device ID", "Name", "Address"]
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


def print_objects_table(rows: List[Dict[str, Any]]):
    headers = ["ObjectIdentifier", "ObjectType", "Name", "PresentValue"]
    fmt_rows: List[List[str]] = []
    widths = [len(h) for h in headers]
    for r in rows:
        oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
        row = [oid, str(r.get("objectType", "")), str(r.get("objectName", "")), str(r.get("presentValue", ""))]
        fmt_rows.append(row)
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "| " + " | ".join("{:<%d}" % w for w in widths) + " |"
    print(sep)
    print(fmt.format(*headers))
    print(sep)
    for row in fmt_rows:
        print(fmt.format(*row))
    print(sep)


def export_devices_csv(rows: List[Tuple], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["idx", "device_id", "name", "address"])
        writer.writerows(rows)


def export_objects_csv(rows: List[Dict[str, Any]], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["objectIdentifier", "objectType", "objectName", "presentValue"])
        for r in rows:
            oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
            writer.writerow([oid, r.get("objectType", ""), r.get("objectName", ""), r.get("presentValue", "")])


def format_address(addr) -> str:
    try:
        ip, port = addr.addrTuple  # type: ignore[attr-defined]
        return f"{ip}:{port}"
    except Exception:
        return str(addr)


def safe_read(bacnet, target: str, *, arr_index: Optional[int] = None, timeout: int = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES):
    for attempt in range(retries + 1):
        try:
            return bacnet.read(target, arr_index=arr_index, timeout=timeout)
        except Exception:
            if attempt >= retries:
                raise
            time.sleep(0.1)
    raise RuntimeError("unreachable")


def get_object_list(
    bacnet,
    addr: str,
    device_id: int,
    timeout: int,
    retries: int,
    bruteforce: bool,
    max_index: int,
    types: Iterable[str],
) -> List[Tuple[str, int]]:
    prefix = f"{addr} device {device_id} objectList"
    try:
        lst = safe_read(bacnet, prefix, timeout=timeout, retries=retries)
        if isinstance(lst, list):
            return [tuple(x) for x in lst]  # type: ignore[arg-type]
    except Exception as e:
        print(f"[WARN] bulk objectList read failed on {device_id}: {e}")
    # try indexed
    try:
        count = safe_read(bacnet, prefix, arr_index=0, timeout=timeout, retries=retries)
        if isinstance(count, int) and count > 0:
            entries: List[Tuple[str, int]] = []
            for i in range(1, count + 1):
                try:
                    oid = safe_read(bacnet, prefix, arr_index=i, timeout=timeout, retries=retries)
                    if isinstance(oid, (tuple, list)) and len(oid) == 2:
                        entries.append((oid[0], int(oid[1])))
                except Exception as ex:
                    print(f"[WARN] objectList[{i}] read failed: {ex}")
            if entries:
                return entries
    except Exception as e:
        print(f"[WARN] objectList length read failed on {device_id}: {e}")

    if bruteforce:
        print(f"[INFO] Falling back to brute-force scan (max-index={max_index})…")
        found: List[Tuple[str, int]] = []
        for obj_type in types:
            for i in range(max_index):
                try:
                    _ = safe_read(bacnet, f"{addr} {obj_type} {i} objectName", timeout=timeout, retries=retries)
                    found.append((obj_type, i))
                except Exception:
                    continue
        if found:
            return found

    return [("device", device_id)]


def read_object_snapshot(bacnet, addr: str, oid: Tuple[str, int], timeout: int, retries: int) -> Dict[str, Any]:
    obj_type, instance = oid
    prefix = f"{addr} {obj_type} {instance}"
    name = ""
    pv: Any = "(n/a)"
    try:
        name = safe_read(bacnet, f"{prefix} objectName", timeout=timeout, retries=retries)
    except Exception:
        pass
    try:
        pv = safe_read(bacnet, f"{prefix} presentValue", timeout=timeout, retries=retries)
    except Exception:
        pass
    return {
        "objectIdentifier": (obj_type, instance),
        "objectType": obj_type,
        "objectName": name,
        "presentValue": pv,
    }


def read_device_info(bacnet, addr: str, device_id: int, timeout: int, retries: int) -> Dict[str, Any]:
    props = [
        "objectName",
        "vendorName",
        "modelName",
        "applicationSoftwareVersion",
        "protocolVersion",
        "protocolRevision",
        "maxApduLengthAccepted",
        "segmentationSupported",
        "apduTimeout",
        "numberOfApduRetries",
        "protocolObjectTypesSupported",
    ]
    info: Dict[str, Any] = {}
    for prop in props:
        target = f"{addr} device {device_id} {prop}"
        try:
            info[prop] = safe_read(bacnet, target, timeout=timeout, retries=retries)
        except Exception:
            continue
    return info


def select_device(choice: str, devices: List[Tuple[str, int, str]]):
    try:
        idx = int(choice)
        if 0 <= idx < len(devices):
            return devices[idx]
    except Exception:
        pass
    try:
        did = int(choice)
        for d in devices:
            if d[1] == did:
                return d
    except Exception:
        pass
    return None


async def inspect_loop(
    bacnet,
    devices: List[Tuple[str, int, str]],
    current: Tuple[str, int, str],
    timeout: int,
    retries: int,
    bruteforce: bool,
    max_index: int,
    types: Iterable[str],
):
    addr, dev_id, name = current
    print(f"[INFO] Reading objectList for device {dev_id} @ {addr}")
    oids = get_object_list(
        bacnet,
        addr,
        dev_id,
        timeout,
        retries,
        bruteforce,
        max_index,
        types,
    )
    rows = [read_object_snapshot(bacnet, addr, oid, timeout, retries) for oid in oids]
    dev_info = read_device_info(bacnet, addr, dev_id, timeout, retries)
    print_objects_table(rows)
    while True:
        cmd = input("Command: [f <text>=filter] [e <file.csv>=export] [d <idx|id>=another device] [r=rescan] [q=quit] \n").strip()
        if not cmd:
            continue
        if cmd.lower() == 'q':
            return "quit"
        if cmd.lower() == 'r':
            return "rescan"
        if cmd.startswith('f '):
            needle = cmd[2:].strip().lower()
            filtered = [r for r in rows if needle in str(r.get('objectType','')).lower() or needle in str(r.get('objectName','')).lower()]
            print_objects_table(filtered)
            continue
        if cmd.startswith('e '):
            path = cmd[2:].strip()
            try:
                export_objects_csv(rows, path)
                print(f"[INFO] Exported to {path}")
            except Exception as e:
                print(f"[WARN] export failed: {e}")
            continue
        if cmd.startswith('d '):
            sel = select_device(cmd[2:].strip(), devices)
            if sel:
                return sel
            print("[WARN] Invalid selection")
            continue
        print("[WARN] Unknown command")
    return None


async def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-config BAC0 BACnet viewer")
    parser.add_argument("--iface", help="Interface CIDR to bind", default=None)
    parser.add_argument("--interval", type=int, default=None, help="Who-Is interval")
    parser.add_argument("--timeout", type=int, default=None, help="Request timeout")
    parser.add_argument("--retries", type=int, default=None, help="Read retries")
    parser.add_argument("--concurrency", type=int, default=None, help="Concurrency during bruteforce")
    parser.add_argument("--max-index", type=int, default=None, help="Max index when bruteforcing")
    parser.add_argument("--types", help="Comma separated object types for bruteforce")
    parser.add_argument("--bruteforce", action="store_true", help="Probe common object types if objectList fails")
    parser.add_argument("--config", help="Optional config.json path")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.iface:
        cfg["interface"] = args.iface
    if args.interval:
        cfg["interval"] = args.interval
    if args.timeout:
        cfg["timeout"] = args.timeout
    if args.retries is not None:
        cfg["retries"] = args.retries
    if args.concurrency is not None:
        cfg["concurrency"] = args.concurrency
    if args.max_index is not None:
        cfg["max_index"] = args.max_index
    if args.types:
        cfg["types"] = [t.strip() for t in args.types.split(",") if t.strip()]

    print(f"[INFO] Bound to {cfg['interface']} on UDP {cfg['port']}")
    print(f"[INFO] Will broadcast Who-Is every {cfg['interval']}s (timeout={cfg['timeout']}s)")

    bacnet = BAC0.lite(cfg["interface"])

    try:
        while True:
            print("\n[INFO] Sending Who-Is…")
            iams = await bacnet.who_is()
            devices: List[Tuple[str, int, str]] = []
            rows: List[Tuple[Any, ...]] = []
            if not iams:
                print("[INFO] Discovered devices:\n  (no replies)")
            else:
                for idx, apdu in enumerate(iams):
                    dev_id = apdu.iAmDeviceIdentifier[1]
                    addr_str = format_address(apdu.pduSource)
                    try:
                        name = safe_read(bacnet, f"{addr_str} device {dev_id} objectName", timeout=cfg['timeout'], retries=cfg['retries'])
                    except Exception:
                        name = ""
                    rows.append((idx, dev_id, name, addr_str))
                    devices.append((addr_str, dev_id, name))
                print("[INFO] Discovered devices:")
                print_device_table(rows)

            choice = input("\nSelect device by index or device-instance (Enter=rescan, q=quit): ").strip()
            if choice == "q":
                break
            if choice == "":
                continue
            sel = select_device(choice, devices)
            if not sel:
                print("[WARN] Invalid selection")
                continue
            result = await inspect_loop(
                bacnet,
                devices,
                sel,
                cfg["timeout"],
                cfg["retries"],
                args.bruteforce,
                cfg["max_index"],
                cfg["types"],
            )
            if result == "quit":
                break
            if result == "rescan":
                continue
            if isinstance(result, tuple):
                # switched device
                sel = result
                continue
            await asyncio.sleep(cfg["interval"])
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        try:
            bacnet.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
