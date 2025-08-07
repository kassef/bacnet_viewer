# BACnet Viewer

This project provides simple tools for simulating and discovering BACnet/IP
devices.

## Simulated devices

Two scripts can create BACnet devices that are visible to explorers such as
[YABE](https://sourceforge.net/projects/yetanotherbacnetexplorer/):

- `simulated_device.py` uses **bacpypes3**. Example:
  ```bash
  python simulated_device.py 192.168.1.100/24 1
  ```
- `bac0_device_cli.py` uses **BAC0**. Example:
  ```bash
  python bac0_device_cli.py 192.168.1.100/24 --device-id 2001 --name MyDevice
  ```

These scripts run a local BACnet/IP device until interrupted.

## Discovering devices

Use `discover_devices.py` to continuously send Who-Is requests and display
responses:

```bash
python discover_devices.py 192.168.1.100/24 --interval 10
```

`main.py` is an alternative scanner that loads its configuration from
`config.json` and uses bacpypes3.

## Installation

Install dependencies before running any script:

```bash
pip install -r requirements.txt
```

## YABE

Run any of the simulated device scripts above and the devices should appear in
YABE's device list on the same network.
