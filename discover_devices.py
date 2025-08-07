#!/usr/bin/env python3
"""Continuously display BACnet devices that respond to Who-Is"""
import argparse
import time

import BAC0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continuously discover BACnet/IP devices using BAC0",
    )
    parser.add_argument(
        "ip_cidr",
        help="Local IP address with CIDR (e.g. 192.168.1.10/24)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Seconds between discovery requests",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bacnet = BAC0.lite(args.ip_cidr)
    print(
        f"[INFO] Listening on {args.ip_cidr}, sending Who-Is every {args.interval}s"
    )
    try:
        while True:
            devices = bacnet.whois()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            if devices:
                print(f"\n[INFO] {now} Discovered devices:")
                for dev in devices:
                    print(f"  {dev}")
            else:
                print(f"\n[INFO] {now} No devices responded")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        bacnet.disconnect()


if __name__ == "__main__":
    main()
