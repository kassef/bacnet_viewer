# BACnet Viewer

This project provides simple tools for **simulating** and **discovering**
BACnet/IP devices.

## Simulated devices

You can spin up local BACnet/IP devices visible to explorers such as
[YABE](https://sourceforge.net/projects/yetanotherbacnetexplorer/):

- `simulated_device.py` (using **bacpypes3**). Example:
  ```bash
  python simulated_device.py 192.168.1.100/24 1
bac0_device_cli.py (using BAC0). Example:

bash
Copier le code
python bac0_device_cli.py 192.168.1.100/24 --device-id 2001 --name MyDevice
These scripts run a simulated BACnet/IP device until interrupted.

Discovering devices
Zero-config scanner (recommended)
main.py is a zero-configuration BACnet/IP scanner.
It automatically detects your active IPv4 interface and broadcast address (like YABE does).

Run it directly:

bash
Copier le code
python main.py
Optional overrides:

bash
Copier le code
python main.py --iface 192.168.1.100/24 --port 47808 --interval 10 --timeout 5
No config.json required – but if present, it will be used for defaults.

Devices are displayed in a table with timestamp, device ID, name, and address.

Legacy discovery
discover_devices.py continuously sends Who-Is requests and shows responses,
but requires you to provide an interface:

bash
Copier le code
python discover_devices.py 192.168.1.100/24 --interval 10
Installation
Install dependencies before running any script:

bash
Copier le code
pip install -r requirements.txt
Requirements include:

bacpypes3

BAC0

psutil (for auto NIC detection)