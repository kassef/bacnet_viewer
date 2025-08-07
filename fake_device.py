# fake_device.py
import asyncio

from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.ipv4.link import IPv4Address


async def main():
    # create the fake device instance 1001
    device = DeviceObject(
        objectName="FakeDevice1",
        objectIdentifier=("device", 1001),
        vendorIdentifier=999,
        vendorName="MyCompany",
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )

    addr = IPv4Address("127.0.0.1/24", 47808)
    app = NormalApplication(device, addr)
    print(f"[SIM] Fake device listening on {addr}")

    # keep the application alive
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
