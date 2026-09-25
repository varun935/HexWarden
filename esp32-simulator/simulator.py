"""Simulate an ESP32 enforcing a ledger-backed firmware update decision."""

import hashlib
import json
import sys
from urllib.error import HTTPError
from urllib.request import urlopen


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python simulator.py FIRMWARE")
        return 2
    with open(sys.argv[1], "rb") as firmware:
        digest = hashlib.sha256(firmware.read()).hexdigest()
    endpoint = f"{__import__('os').environ.get('HEXWARDEN_BACKEND', 'http://127.0.0.1:4000')}/api/firmware/{digest}"
    print(f"Firmware hash: {digest.upper()}")
    try:
        with urlopen(endpoint, timeout=10) as response:
            record = json.load(response)
        status = "APPROVED" if record.get("approved") else "REVOKED"
    except HTTPError as error:
        if error.code == 404:
            status = "NOT APPROVED"
        else:
            raise
    print(f"\nLedger status: {status}\n")
    accepted = status == "APPROVED"
    print("UPDATE ACCEPTED" if accepted else "UPDATE REJECTED")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())