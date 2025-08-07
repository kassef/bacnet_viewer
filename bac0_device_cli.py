#!/usr/bin/env python3
"""Start a simple BAC0 device using command line arguments."""
import argparse
import time

import BAC0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a simulated BACnet/IP device using BAC0"
    )
    parser.add_argument(
        "ip_cidr",
        help="Local IP address with CIDR notation (e.g. 192.168.1.10/24)",
    )
    parser.add_argument(
        "--device-id",
        type=int,
        default=2000,
        help="Device identifier (default: 2000)",
    )
    parser.add_argument(
        "--name",
        default="BAC0Device",
        help="Object name for the simulated device",
    )
    parser.add_argument(
        "--vendor-id",
        type=int,
        default=999,
        help="Vendor identifier (default: 999)",
    )
    parser.add_argument(
        "--vendor-name",
        default="BAC0Sim",
        help="Vendor name to advertise",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    device = BAC0.lite(
        args.ip_cidr,
        deviceId=args.device_id,
        name=args.name,
        vendorId=args.vendor_id,
        vendorName=args.vendor_name,
    )
    print(
        f"[SIM] {args.name} (ID {args.device_id}) listening on {args.ip_cidr}. "
        "Press Ctrl+C to stop"
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SIM] Shutting down")
    finally:
        device.disconnect()


if __name__ == "__main__":
    main()
