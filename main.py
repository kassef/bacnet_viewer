import json
from bacpypes.local.device import LocalDeviceObject
from bacpypes.app import BIPSimpleApplication
from bacpypes.pdu import Address
from bacpypes.apdu import WhoIsRequest, IAmRequest
from bacpypes.core import run


class BACnetApp(BIPSimpleApplication):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.devices = []

    def indication(self, apdu):
        if isinstance(apdu, IAmRequest):
            info = (apdu.iAmDeviceIdentifier, str(apdu.pduSource))
            if info not in self.devices:
                self.devices.append(info)
        super().indication(apdu)


class BACnetClient:
    def __init__(self, config_path):
        # Load settings
        with open(config_path) as f:
            cfg = json.load(f)

        # Create a local BACnet device
        self.device = LocalDeviceObject(
            objectName="BACnetDebugger",
            objectIdentifier=tuple(cfg["local_device_id"]),
            vendorIdentifier=cfg["vendor_identifier"],
            vendorName=cfg["vendor_name"],
            maxApduLengthAccepted=1024,
            segmentationSupported="noSegmentation"
        )

        # Bind to interface and port
        addr = Address(f"{cfg['interface']}:{cfg['port']}")
        self.app = BACnetApp(self.device, addr)

        # Broadcast target
        self.broadcast_address = Address(f"{cfg['broadcast_address']}:{cfg['port']}")

    def discover(self):
        # Send Who-Is
        req = WhoIsRequest()
        req.pduDestination = self.broadcast_address
        self.app.request(req)

        # Run the BACnet event loop
        run()
        return self.app.devices


if __name__ == "__main__":
    client = BACnetClient("config.json")
    devices = client.discover()
    print("Discovered devices:")
    for dev_id, addr in devices:
        print(f"- Device ID: {dev_id}, Address: {addr}")


class BACnetApp(BIPSimpleApplication):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.devices = []

    def indication(self, apdu):
        if isinstance(apdu, IAmRequest):
            info = (apdu.iAmDeviceIdentifier, str(apdu.pduSource))
            if info not in self.devices:
                self.devices.append(info)
        super().indication(apdu)


class BACnetClient:
    def __init__(self, config_path):
        # Load settings
        with open(config_path) as f:
            cfg = json.load(f)

        # Create a local BACnet device
        self.device = LocalDeviceObject(
            objectName="BACnetDebugger",
            objectIdentifier=tuple(cfg["local_device_id"]),
            vendorIdentifier=cfg["vendor_identifier"],
            vendorName=cfg["vendor_name"],
            maxApduLengthAccepted=1024,
            segmentationSupported="noSegmentation"
        )

        # Bind to interface and port
        addr = Address(f"{cfg['interface']}:{cfg['port']}")
        self.app = BACnetApp(self.device, addr)

        # Broadcast target
        self.broadcast_address = Address(
            f"{cfg['broadcast_address']}:{cfg['port']}")

    def discover(self):
        # Send Who-Is
        req = WhoIsRequest()
        req.pduDestination = self.broadcast_address
        self.app.request(req)

        # Run the BACnet event loop
        run()
        return self.app.devices


if __name__ == "__main__":
    client = BACnetClient("config.json")
    devices = client.discover()
    print("Discovered devices:")
    for dev_id, addr in devices:
        print(f"- Device ID: {dev_id}, Address: {addr}")
