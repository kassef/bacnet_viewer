# main.py
import json
import asyncio
from datetime import datetime
from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app    import NormalApplication
from bacpypes3.ipv4.link   import IPv4Address

def print_table(rows):
    headers = ["Timestamp", "Device ID", "Name", "Address"]
    # compute column widths
    col_widths = []
    for i, h in enumerate(headers):
        max_cell = max((len(str(r[i])) for r in rows), default=0)
        col_widths.append(max(len(h), max_cell))
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    # header
    print(sep)
    print("| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |")
    print(sep)
    # data rows
    for r in rows:
        print("| " + " | ".join(str(r[i]).ljust(col_widths[i]) for i in range(len(headers))) + " |")
    print(sep)

async def main():
    # load config
    with open("config.json") as f:
        cfg = json.load(f)

    # build our “scanner” device
    scanner = DeviceObject(
        objectName="BACnetDebugger",
        objectIdentifier=("device", cfg["local_device_id"]),
        vendorIdentifier=cfg["vendor_identifier"],
        vendorName=cfg["vendor_name"],
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )

    # bind & target
    local_addr  = IPv4Address(cfg["interface"], cfg.get("local_port", 47808))
    target_addr = IPv4Address(cfg["broadcast_address"], cfg["port"])

    app = NormalApplication(scanner, local_addr)

    interval = cfg.get("scan_interval", 30)
    print(f"[INFO] Listening on {local_addr}, broadcasting Who-Is every {interval}s to {target_addr}")

    try:
        while True:
            print(f"\n[INFO] Sending Who-Is to {target_addr}")
            # i_ams = await app.who_is(0, 4_194_303, address=target_addr)
            i_ams = await app.who_is(timeout=cfg.get("request_timeout", 5))

            print("[INFO] Discovered devices:")
            if i_ams:
                rows = []
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for apdu in i_ams:
                    name = await app.read_property(
                        apdu.pduSource, apdu.iAmDeviceIdentifier, "objectName"
                    )
                    rows.append((now, apdu.iAmDeviceIdentifier, name, apdu.pduSource))
                print_table(rows)
            else:
                print("  (no replies)")

            await asyncio.sleep(interval)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        app.close()

if __name__ == "__main__":
    asyncio.run(main())
