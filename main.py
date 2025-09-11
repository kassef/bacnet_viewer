#!/usr/bin/env python3
# Zero-config BACnet/IP discovery (like YABE)
import asyncio
from datetime import datetime
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
import argparse
import csv
import json
import psutil

from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.ipv4.link import IPv4Address



DEFAULT_PORT = 47808
DEFAULT_SCAN_INTERVAL = 30
DEFAULT_TIMEOUT = 7
DEFAULT_CONCURRENCY = 16


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


def format_address(addr) -> str:
    try:
        ip, port = addr.addrTuple  # type: ignore[attr-defined]
        return f"{ip}:{port}"
    except Exception:
        return str(addr)


# read with timeout/retries
async def safe_read_property(app, addr, obj_id, prop, timeout=7.0, retries=1):
    for attempt in range(retries + 1):
        try:
            return await asyncio.wait_for(app.read_property(addr, obj_id, prop), timeout)
        except Exception:
            if attempt >= retries:
                raise
    raise RuntimeError("unreachable")


async def get_object_list(app, addr, device_instance, timeout=7.0, retries=1,
                          bruteforce=False, max_index=64, concurrency=16) -> list[tuple[str, int]]:
    dev_oid = ("device", device_instance)

    # Try bulk read
    try:
        lst = await safe_read_property(app, addr, dev_oid, "objectList", timeout, retries)
        return list(lst)
    except Exception as e:
        print(f"[WARN] bulk objectList read failed on {device_instance}: {e}")

    # Try indexed array access (length at [0], then 1..N)
    try:
        count = await safe_read_property(app, addr, dev_oid, ("objectList", 0), timeout, retries)
        if isinstance(count, int) and count > 0:
            sem = asyncio.Semaphore(concurrency)
            async def _read_idx(i: int):
                async with sem:
                    try:
                        oid = await safe_read_property(app, addr, dev_oid, ("objectList", i), timeout, retries)
                        return tuple(oid)
                    except Exception as ex:
                        print(f"[WARN] objectList[{i}] read failed: {ex}")
                        return None
            entries = await asyncio.gather(*(_read_idx(i) for i in range(1, count + 1)))
            entries = [e for e in entries if e]
            if entries:
                return entries
    except Exception as e:
        print(f"[WARN] objectList length read failed on {device_instance}: {e}")

    # Brute-force fallback
    if bruteforce:
        print(f"[INFO] Falling back to brute-force scan (max-index={max_index})…")
        found = await bruteforce_object_ids(
            app, addr, max_index=max_index, timeout=timeout, retries=retries, concurrency=concurrency
        )
        if found:
            return found

    # Minimal fallback: return the device object so UI still shows something
    return [("device", device_instance)]


async def read_object_snapshot(app, addr, oid, timeout=7.0, retries=1) -> dict:
    obj_type = oid[0]
    name = ""
    pv = "(n/a)"
    try:
        obj_type = await safe_read_property(app, addr, oid, "objectType", timeout, retries)
    except Exception:
        pass
    try:
        name = await safe_read_property(app, addr, oid, "objectName", timeout, retries)
    except Exception:
        pass
    try:
        pv = await safe_read_property(app, addr, oid, "presentValue", timeout, retries)
    except Exception:
        pv = "(n/a)"
    return {
        "objectIdentifier": oid,
        "objectType": obj_type,
        "objectName": name,
        "presentValue": pv,
    }


def print_objects_table(rows: list[dict]):
    headers = ["ObjectIdentifier", "ObjectType", "Name", "PresentValue"]
    fmt_rows = []
    widths = [len(h) for h in headers]
    for r in rows:
        oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
        row = [oid, str(r["objectType"]), str(r["objectName"]), str(r["presentValue"])]
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


def export_devices_csv(rows: list[tuple], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "device_id", "name", "address"])
        writer.writerows(rows)


def export_objects_csv(rows: list[dict], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["objectIdentifier", "objectType", "objectName", "presentValue"])
        for r in rows:
            oid = f"{r['objectIdentifier'][0]},{r['objectIdentifier'][1]}"
            writer.writerow([oid, r["objectType"], r["objectName"], r["presentValue"]])


def select_device(choice: str, devices: list[tuple]):
    if choice.isdigit():
        idx = int(choice)
        if 0 <= idx < len(devices):
            return devices[idx]
    try:
        inst = int(choice)
    except ValueError:
        return None
    for d in devices:
        if d[1] == inst:
            return d
    return None


async def inspect_loop(app, devices, selected, inspect_timeout, retries, concurrency):
    current = selected
    while True:
        addr, dev_id, _ = current
        print(f"[INFO] Reading objectList for device {dev_id} @ {format_address(addr)}")
        # obj_list = await get_object_list(app, addr, dev_id, inspect_timeout, retries)
        obj_list = await get_object_list(
            app, addr, dev_id,
            timeout=inspect_timeout, retries=retries,
            bruteforce=True,              # enable fallback
            max_index=64,
            concurrency=concurrency
        )
        sem = asyncio.Semaphore(concurrency)

        async def _snap(oid):
            async with sem:
                try:
                    return await read_object_snapshot(app, addr, oid, inspect_timeout, retries)
                except Exception as e:
                    print(f"[WARN] {oid} read failed: {e}")
                    return {
                        "objectIdentifier": oid,
                        "objectType": oid[0],
                        "objectName": "",
                        "presentValue": "(error)",
                    }

        rows = await asyncio.gather(*[_snap(oid) for oid in obj_list])
        orig_rows = rows
        filtered_rows = rows
        print_objects_table(filtered_rows)
        while True:
            cmd = input(
                "Command: [f <text>=filter] [e <file.csv>=export] [d <idx|id>=another device] [r=rescan] [q=quit]\n> "
            ).strip()
            if not cmd:
                continue
            if cmd == "r":
                return "rescan"
            if cmd == "q":
                return "quit"
            if cmd.startswith("f "):
                term = cmd[2:].strip().lower()
                filtered_rows = [
                    r
                    for r in orig_rows
                    if term in str(r["objectType"]).lower()
                    or term in str(r["objectName"]).lower()
                ]
                print_objects_table(filtered_rows)
            elif cmd.startswith("e "):
                file = cmd[2:].strip()
                try:
                    export_objects_csv(filtered_rows, file)
                    print(f"[INFO] Exported to {file}")
                except Exception as e:
                    print(f"[WARN] Export failed: {e}")
            elif cmd.startswith("d "):
                ch = cmd[2:].strip()
                new_sel = select_device(ch, devices)
                if new_sel:
                    current = new_sel
                    break
                else:
                    print("[WARN] Invalid device selection")
            else:
                print("[WARN] Unknown command")
        # continue outer loop with new current


COMMON_TYPES = [
    "analogInput", "analogValue", "analogOutput",
    "binaryInput", "binaryValue", "binaryOutput",
    "multiStateInput", "multiStateValue", "multiStateOutput",
    # add more if you like: 'device','schedule','trendLog','lifeSafetyPoint', ...
]

async def probe_object_exists(app, addr, obj_id, timeout=7.0, retries=1) -> bool:
    # Fast existence test: try to read objectName (or objectType)
    try:
        _ = await safe_read_property(app, addr, obj_id, "objectName", timeout, retries)
        return True
    except Exception:
        try:
            _ = await safe_read_property(app, addr, obj_id, "objectType", timeout, retries)
            return True
        except Exception:
            return False

async def bruteforce_object_ids(app, addr, max_index=64, timeout=7.0, retries=1,
                                types: list[str] = None, concurrency=16) -> list[tuple[str, int]]:
    if types is None:
        types = COMMON_TYPES
    sem = asyncio.Semaphore(concurrency)

    async def _try_one(typ: str, idx: int):
        oid = (typ, idx)
        async with sem:
            ok = await probe_object_exists(app, addr, oid, timeout, retries)
            return oid if ok else None

    tasks = []
    for typ in types:
        for i in range(max_index + 1):
            tasks.append(_try_one(typ, i))

    results = await asyncio.gather(*tasks, return_exceptions=False)
    return [r for r in results if r]


async def main():
    parser = argparse.ArgumentParser(description="Zero-config BACnet/IP device discovery")
    parser.add_argument("--config", help="Optional path to config.json (if omitted, auto-detect NIC)")
    parser.add_argument("--iface", help="Override interface CIDR (e.g. 192.168.1.10/24)")
    parser.add_argument("--port", type=int, help="Local UDP port (default 47808)")
    parser.add_argument("--interval", type=int, help="Seconds between scans")
    parser.add_argument("--timeout", type=float, help="Request timeout (s)")
    parser.add_argument("--inspect-timeout", type=float, help="Timeout for property reads during inspect (s)")
    parser.add_argument("--retries", type=int, default=1, help="Retries for property reads")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent property reads")
    parser.add_argument("--bruteforce", action="store_true",
                    help="Probe common object types if objectList is unavailable")
    parser.add_argument("--max-index", type=int, default=64,
                        help="Max index per object type when bruteforcing (default 64)")
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

    inspect_timeout = args.inspect_timeout if args.inspect_timeout else cfg["request_timeout"]
    retries = args.retries
    concurrency = args.concurrency

    # Local scanner device
    # scanner = DeviceObject(
    #     objectName="BACnetDebugger",
    #     objectIdentifier=("device", cfg["local_device_id"]),
    #     vendorIdentifier=cfg["vendor_identifier"],
    #     vendorName=cfg["vendor_name"],
    #     maxApduLengthAccepted=1024,
    #     segmentationSupported="noSegmentation",
    # )

    scanner = DeviceObject(
        objectName="BACnetDebugger",
        objectIdentifier=("device", cfg["local_device_id"]),
        vendorIdentifier=cfg["vendor_identifier"],
        vendorName=cfg["vendor_name"],
        maxApduLengthAccepted=1476,          # was 1024
        segmentationSupported="segmentedBoth"  # was "noSegmentation"
    )


    local_addr = IPv4Address(cfg["interface"], cfg["local_port"])
    app = NormalApplication(scanner, local_addr)
    # app = NormalApplication(scanner, IPv4ForeignDevice("192.168.163.100/24", 47808, bbmd_addr, ttl=300))


    print(f"[INFO] Bound to {cfg['interface']} on UDP {cfg['local_port']}")
    print(
        f"[INFO] Will broadcast Who-Is every {cfg['scan_interval']}s (timeout={cfg['request_timeout']}s)"
    )

    try:
        while True:
            print("\n[INFO] Sending Who-Is…")
            i_ams = await app.who_is(timeout=cfg["request_timeout"])
            devices: list[tuple] = []
            rows: list[tuple] = []
            if not i_ams:
                print("[INFO] Discovered devices:\n  (no replies)")
            else:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for apdu in i_ams:
                    dev_id = apdu.iAmDeviceIdentifier
                    try:
                        name = await safe_read_property(
                            app,
                            apdu.pduSource,
                            dev_id,
                            "objectName",
                            timeout=inspect_timeout,
                            retries=retries,
                        )
                    except Exception:
                        name = ""
                    addr_str = format_address(apdu.pduSource)
                    rows.append((now, f"{dev_id[0]},{dev_id[1]}", name, addr_str))
                    devices.append((apdu.pduSource, dev_id[1], name))
                print("[INFO] Discovered devices:")
                print_device_table(rows)

            while True:
                choice = input(
                    "\nSelect device by index or device-instance (Enter=rescan, q=quit): "
                ).strip()
                if choice == "":
                    break
                if choice.lower() == "q":
                    raise KeyboardInterrupt
                sel = select_device(choice, devices)
                if not sel:
                    print("[WARN] Invalid selection")
                    continue
                result = await inspect_loop(app, devices, sel, inspect_timeout, retries, concurrency)
                if result == "rescan":
                    break
                if result == "quit":
                    raise KeyboardInterrupt
            await asyncio.sleep(cfg["scan_interval"])

    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        app.close()



if __name__ == "__main__":
    asyncio.run(main())
