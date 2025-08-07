# fake_device.py
import asyncio

from bacpypes3.local.device import DeviceObject
from bacpypes3.app import Application
from bacpypes3.pdu import Address
from bacpypes3.apdu import IAmRequest


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

    addr = Address("127.0.0.1:47808")
    app = Application(device, addr)
    print(f"[SIM] Fake device listening on {addr}")

    # wait for the Who-Is to arrive, then send I-Am
    await asyncio.sleep(2)
    iam = IAmRequest(
        source=addr,
        iAmDeviceIdentifier=("device", 1001),
        maxAPDULengthAccepted=1024,
        segmentationSupported="noSegmentation",
        vendorID=999,
    )
    await app.request(iam)
    print(f"[SIM] Sent I-Am from FakeDevice1")

    # keep the application alive
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
