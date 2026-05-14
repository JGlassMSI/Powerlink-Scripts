#!/usr/bin/env -S uv run --script

import argparse
from ipaddress import ip_address

from pyModbusTCP.client import ModbusClient

parser = argparse.ArgumentParser(
    description="Simple command line interface to turn on/off powerlink panels"
)

parser.add_argument("ip", type=ip_address, help="The IP address to send the message to")
parser.add_argument("coil", type=int, help="Coil to control")
parser.add_argument("on_off", type=str.upper, choices=['ON', 'OFF'], help="Whether to turn the targeted device(s) on or off")

if __name__ == "__main__":
    args = parser.parse_args()

    # Initialize Modbus client
    client = ModbusClient(host=str(args.ip), port=502, auto_open=True, timeout=10)

    if client.write_single_coil(args.coil, (1 if args.on_off == "ON" else 0)):
        print("Write successful")
    else:
        print("Write error")