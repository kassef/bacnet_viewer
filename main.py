# main.py
import json
import asyncio

from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.ipv4.link import IPv4Address


async def main():
    # load config
    with open("config.json") as f:
        cfg = json.load(f)

    # build our local “scanner” device
    scanner = DeviceObject(
        objectName="BACnetDebugger",
        objectIdentifier=tuple(cfg["local_device_id"]),
        vendorIdentifier=cfg["vendor_identifier"],
        vendorName=cfg["vendor_name"],
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )

    # bind to an ephemeral local port and unicast a Who-Is to the target
    local_addr = IPv4Address(f"{cfg['interface']}/24", cfg.get('local_port', 0))
    target_addr = IPv4Address(
        f"{cfg['broadcast_address']}/24", cfg['port']
    )
    app = NormalApplication(scanner, local_addr)
    print(
        f"[INFO] Listening on {local_addr}, sending Who-Is to {target_addr}"
    )

    # do a Who-Is for the full device range 0–4194303
    i_ams = await app.who_is(0, 4_194_303, address=target_addr)
    print("[INFO] Discovered devices:")
    if i_ams:
        for apdu in i_ams:
            name = await app.read_property(
                apdu.pduSource, apdu.iAmDeviceIdentifier, "objectName"
            )
            print(
                f"  – ID {apdu.iAmDeviceIdentifier} ({name}) @ {apdu.pduSource}"
            )
    else:
        print("  (no replies)")

    app.close()

if __name__ == "__main__":
    asyncio.run(main())
