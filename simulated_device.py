#!/usr/bin/env python3
import asyncio
import argparse

from bacpypes3.local.device import DeviceObject
from bacpypes3.ipv4.app    import NormalApplication
from bacpypes3.ipv4.link   import IPv4Address

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a simulated BACnet/IP device")
    parser.add_argument(
        "ip_cidr",
        help="Local IP/CIDR to bind the UDP socket (e.g. 192.168.1.100/24)")
    parser.add_argument(
        "index",
        type=int,
        help="Index for this device: used to form name SimulatedDevice<index> and device ID = 1000+index")
    parser.add_argument(
        "--port",
        type=int,
        default=47808,
        help="UDP port to bind (default: 47808)")
    return parser.parse_args()

async def main():
    args = parse_args()

    # compute your device ID and name from the index
    device_id   = 1000 + args.index
    device_name = f"SimulatedDevice{args.index}"

    device = DeviceObject(
        objectName           = device_name,
        objectIdentifier     = ("device", device_id),
        vendorIdentifier     = 999,
        vendorName           = "MyCompany",
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
    )

    addr = IPv4Address(args.ip_cidr, args.port)
    app  = NormalApplication(device, addr)

    print(f"[SIM] {device_name} (ID {device_id}) listening on {addr}")

    # keep running until you Ctrl+C
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
