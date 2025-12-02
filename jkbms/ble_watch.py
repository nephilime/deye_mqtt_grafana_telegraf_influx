#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Watch BLE devices: show which addresses appear or disappear between scans.
# Use this to identify your JK-BMS: power it ON/OFF and see which MAC changes.

import asyncio
import time
from typing import Set
from bleak import BleakScanner


async def main():
    seen: Set[str] = set()
    print("Watching BLE devices. Press Ctrl+C to stop.")
    print("Tip: keep script running, then power your JK-BMS OFF and ON.")

    try:
        while True:
            devices = await BleakScanner.discover(timeout=5.0)
            current = {d.address.upper() for d in devices}

            # New devices
            new = current - seen
            gone = seen - current

            ts = time.strftime("%H:%M:%S")
            if new or gone:
                print(f"\n[{ts}] Scan diff:")
                if new:
                    for addr in sorted(new):
                        name = next(
                            (d.name or "(no name)" for d in devices if d.address.upper() == addr),
                            "(no name)",
                        )
                        print(f"  + {addr}  name={name}")
                if gone:
                    for addr in sorted(gone):
                        print(f"  - {addr}  (disappeared)")

            seen = current
            await asyncio.sleep(2.0)

    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    asyncio.run(main())
