# main.py
import json
import asyncio

from bacpypes3.local.device import DeviceObject
from bacpypes3.app import Application
from bacpypes3.pdu import Address


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

    # bind it to UDP port on loopback
    local_addr = Address(f"{cfg['interface']}:{cfg['port']}")
    broadcast_addr = Address(f"{cfg['broadcast_address']}:{cfg['port']}")
    app = Application(scanner, local_addr)
    print(
        f"[INFO] Listening on {local_addr}, broadcasting Who-Is to {broadcast_addr}")

    # do a Who-Is for the full device range 0–4194303
    i_ams = await app.who_is(0, 4_194_303)
    print("[INFO] Discovered devices:")
    if i_ams:
        for apdu in i_ams:
            print(f"  – ID {apdu.iAmDeviceIdentifier} @ {apdu.pduSource}")
    else:
        print("  (no replies)")

    app.close()

if __name__ == "__main__":
    asyncio.run(main())
