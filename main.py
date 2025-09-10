#!/usr/bin/env python3
"""Interactive BACnet/IP device scanner using bacpypes3."""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.ipv4.link import IPv4Address
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import Address


# ---------------------------------------------------------------------------
# configuration helpers


def load_config(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive BACnet/IP scanner")
    parser.add_argument("--iface", help="Local interface with CIDR (e.g. 192.168.1.10/24)")
    parser.add_argument("--bcast", help="Broadcast address with CIDR")
    parser.add_argument("--port", type=int, help="BACnet UDP port")
    parser.add_argument("--interval", type=int, help="Seconds between discovery scans")
    parser.add_argument("--timeout", type=float, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, help="Number of request retries")
    return parser.parse_args()


def resolve_iface_and_bcast(cfg: Dict[str, Any]) -> Tuple[IPv4Address, IPv4Address]:
    local_addr = IPv4Address(cfg["interface"], cfg.get("local_port", 0))
    target_addr = IPv4Address(cfg["broadcast_address"], cfg["port"])
    return local_addr, target_addr


# ---------------------------------------------------------------------------
# BACnet helpers


async def who_is_discover(
    app: NormalApplication,
    target: IPv4Address,
    timeout: float,
    retries: int,
) -> Sequence[Any]:
    """Send Who-Is and collect I-Am responses."""
    result: Sequence[Any] = []
    for attempt in range(retries + 1):
        try:
            result = await app.who_is(address=target, timeout=timeout)
            break
        except Exception as err:  # pragma: no cover - network failure
            print(f"[WARN] Who-Is attempt {attempt + 1} failed: {err}")
    return result


async def safe_read_property(
    app: NormalApplication,
    addr: Address,
    obj_id: Tuple[str, int],
    prop: str,
    timeout: float,
    retries: int,
) -> Any:
    """Read a property with timeout and retries."""
    for attempt in range(retries + 1):
        try:
            return await asyncio.wait_for(app.read_property(addr, obj_id, prop), timeout)
        except Exception as err:  # pragma: no cover - network failure
            if attempt >= retries:
                raise err
    raise RuntimeError("unreachable")


async def get_device_name(
    app: NormalApplication,
    addr: Address,
    device_id: int,
    timeout: float,
    retries: int,
) -> str:
    try:
        return await safe_read_property(app, addr, ("device", device_id), "objectName", timeout, retries)
    except Exception:
        return ""


async def get_object_list(
    app: NormalApplication,
    addr: Address,
    device_id: int,
    timeout: float,
    retries: int,
) -> List[Tuple[str, int]]:
    try:
        objs = await safe_read_property(app, addr, ("device", device_id), "objectList", timeout, retries)
        return list(objs)
    except Exception as err:
        print(f"[WARN] objectList read failed: {err}")
        return []


async def read_object_snapshot(
    app: NormalApplication,
    addr: Address,
    obj_id: Tuple[str, int],
    timeout: float,
    retries: int,
) -> Dict[str, Any]:
    """Read objectName, objectType and presentValue for an object."""
    name = ""
    obj_type = obj_id[0]
    pv: Any = "(n/a)"
    try:
        obj_type = await safe_read_property(app, addr, obj_id, "objectType", timeout, retries)
    except Exception:
        pass
    try:
        name = await safe_read_property(app, addr, obj_id, "objectName", timeout, retries)
    except Exception:
        pass
    try:
        pv = await safe_read_property(app, addr, obj_id, "presentValue", timeout, retries)
    except Exception:
        pv = "(n/a)"
    return {
        "objectIdentifier": obj_id,
        "objectType": obj_type,
        "objectName": name,
        "presentValue": pv,
    }


def format_addr(addr: Address) -> str:
    try:
        ip, port = addr.addrTuple
        return f"{ip}:{port}"
    except Exception:  # pragma: no cover - depends on address type
        return str(addr)


def print_devices_table(devices: List[Dict[str, Any]]) -> None:
    headers = ["[#]", "Timestamp", "Device-Instance", "Name", "Address"]
    rows = []
    for idx, dev in enumerate(devices):
        rows.append([
            str(idx),
            dev["timestamp"],
            str(dev["id"]),
            dev["name"],
            format_addr(dev["addr"]),
        ])
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    sep = " ".join("-" * w for w in widths)
    fmt = " ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(sep)
    for row in rows:
        print(fmt.format(*row))


def print_objects_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["ObjectIdentifier", "ObjectType", "Name", "PresentValue"]
    formatted = []
    for r in rows:
        oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
        formatted.append([oid, str(r["objectType"]), str(r["objectName"]), str(r["presentValue"])])
    widths = [len(h) for h in headers]
    for row in formatted:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = " ".join("-" * w for w in widths)
    fmt = " ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(sep)
    for row in formatted:
        print(fmt.format(*row))


def export_devices_csv(path: str, devices: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "device_instance", "name", "address"])
        for dev in devices:
            writer.writerow([
                dev["timestamp"],
                dev["id"],
                dev["name"],
                format_addr(dev["addr"]),
            ])
    print(f"[INFO] Saved device table to {path}")


def export_objects_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["objectIdentifier", "objectType", "objectName", "presentValue"])
        for r in rows:
            oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
            writer.writerow([oid, r["objectType"], r["objectName"], r["presentValue"]])
    print(f"[INFO] Saved object table to {path}")


def resolve_selection(token: str, devices: List[Dict[str, Any]]) -> Optional[Tuple[Address, int]]:
    if token.isdigit():
        idx = int(token)
        if 0 <= idx < len(devices):
            d = devices[idx]
            return d["addr"], d["id"]
    try:
        did = int(token)
        for d in devices:
            if d["id"] == did:
                return d["addr"], d["id"]
    except ValueError:
        pass
    return None


async def prompt_device_selection(devices: List[Dict[str, Any]]) -> Optional[Tuple[Address, int]]:
    if not devices:
        return None
    while True:
        choice = input("Select device by index or device-instance (q to quit): ").strip()
        if choice.lower() == "q":
            return None
        sel = resolve_selection(choice, devices)
        if sel:
            return sel
        print("[WARN] Invalid selection")


async def inspect_device(
    app: NormalApplication,
    addr: Address,
    device_id: int,
    cfg: Dict[str, Any],
) -> List[Dict[str, Any]]:
    timeout = cfg.get("request_timeout", 3)
    retries = cfg.get("request_retries", 1)
    print(
        f"[INFO] Reading objectList for device {device_id} @ {format_addr(addr)}"
    )
    obj_list = await get_object_list(app, addr, device_id, timeout, retries)
    if not obj_list:
        return []
    sem = asyncio.Semaphore(cfg.get("concurrency", 16))

    async def _read(oid: Tuple[str, int]) -> Dict[str, Any]:
        async with sem:
            try:
                return await read_object_snapshot(app, addr, oid, timeout, retries)
            except Exception as err:
                print(f"[WARN] {oid} read failed: {err}")
                return {
                    "objectIdentifier": oid,
                    "objectType": oid[0],
                    "objectName": "",
                    "presentValue": "(error)",
                }

    tasks = [_read(oid) for oid in obj_list]
    return await asyncio.gather(*tasks)


async def discover(
    app: NormalApplication,
    target: IPv4Address,
    cfg: Dict[str, Any],
) -> List[Dict[str, Any]]:
    timeout = cfg.get("request_timeout", 3)
    retries = cfg.get("request_retries", 1)
    print("[INFO] Sending Who-Is...")
    i_ams = await who_is_discover(app, target, timeout, retries)
    devices: Dict[int, Dict[str, Any]] = {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for apdu in i_ams:
        device_id = apdu.iAmDeviceIdentifier[1]
        addr = apdu.pduSource
        name = await get_device_name(app, addr, device_id, timeout, retries)
        devices[device_id] = {
            "id": device_id,
            "name": name,
            "addr": addr,
            "timestamp": now,
        }
    print("[INFO] Discovered devices:")
    return list(devices.values())


# ---------------------------------------------------------------------------
# main routine


async def main() -> None:
    args = parse_args()
    cfg = load_config("config.json")
    # overrides
    if args.iface:
        cfg["interface"] = args.iface
    if args.bcast:
        cfg["broadcast_address"] = args.bcast
    if args.port is not None:
        cfg["port"] = args.port
    if args.interval is not None:
        cfg["scan_interval"] = args.interval
    if args.timeout is not None:
        cfg["request_timeout"] = args.timeout
    if args.retries is not None:
        cfg["request_retries"] = args.retries

    local_addr, target_addr = resolve_iface_and_bcast(cfg)
    scanner = DeviceObject(
        objectName="BACnetViewer",
        objectIdentifier=("device", cfg["local_device_id"]),
        vendorIdentifier=cfg["vendor_identifier"],
        vendorName=cfg["vendor_name"],
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )
    app = NormalApplication(scanner, local_addr)

    print(
        f"[INFO] Listening on {local_addr}, broadcasting Who-Is to {target_addr}"
    )

    try:
        while True:
            devices = await discover(app, target_addr, cfg)
            if devices:
                print_devices_table(devices)
                if path := cfg.get("csv_export_path"):
                    export_devices_csv(path, devices)
            else:
                print("[WARN] No devices responded")

            selection = await prompt_device_selection(devices)
            if selection is None:
                break
            addr, dev_id = selection
            rows = await inspect_device(app, addr, dev_id, cfg)
            print_objects_table(rows)

            while True:
                cmd = input(
                    "Command: [d <idx|id>] [r] [f <text>] [e <csv>] [q] "
                ).strip()
                if cmd.lower() == "q":
                    return
                if cmd.lower() == "r":
                    break
                if cmd.startswith("d "):
                    token = cmd.split(maxsplit=1)[1]
                    sel = resolve_selection(token, devices)
                    if sel is None:
                        print("[WARN] invalid device selection")
                        continue
                    addr, dev_id = sel
                    rows = await inspect_device(app, addr, dev_id, cfg)
                    print_objects_table(rows)
                    continue
                if cmd.startswith("f "):
                    substr = cmd.split(maxsplit=1)[1].lower()
                    filtered = [
                        r
                        for r in rows
                        if substr in str(r["objectType"]).lower()
                        or substr in str(r["objectName"]).lower()
                    ]
                    print_objects_table(filtered)
                    continue
                if cmd.startswith("e "):
                    path = cmd.split(maxsplit=1)[1]
                    export_objects_csv(path, rows)
                    continue
                print("[WARN] Unknown command")
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        app.close()


if __name__ == "__main__":
    asyncio.run(main())
