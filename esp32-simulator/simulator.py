"""Simulate an ESP32 enforcing a ledger-backed firmware update decision."""

import hashlib
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen


def check_hash(digest: str) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("firmware hash must be a 64-character SHA-256 hex string")
    digest = digest.lower()
    endpoint = f"{__import__('os').environ.get('HEXWARDEN_BACKEND', 'http://127.0.0.1:4000')}/api/firmware/{digest}"
    try:
        with urlopen(endpoint, timeout=10) as response:
            record = json.load(response)
        status = "APPROVED" if record.get("approved") else "REVOKED"
    except HTTPError as error:
        if error.code == 404:
            status = "NOT APPROVED"
        else:
            raise
    return {
        "firmware_hash": digest,
        "ledger_status": status,
        "decision": "ACCEPT" if status == "APPROVED" else "REJECT",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a firmware image against the trust ledger.")
    parser.add_argument("firmware", nargs="?", help="Firmware file to hash and check")
    parser.add_argument("--hash", dest="firmware_hash", help="Check an existing SHA-256 digest")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable result")
    args = parser.parse_args()
    if bool(args.firmware) == bool(args.firmware_hash):
        parser.error("provide either a firmware file or --hash")
    if args.firmware:
        with Path(args.firmware).open("rb") as firmware:
            digest = hashlib.sha256(firmware.read()).hexdigest()
    else:
        digest = args.firmware_hash
    try:
        result = check_hash(digest)
    except Exception as error:
        if args.json:
            print(json.dumps({"error": str(error)}))
        else:
            print(f"Simulator check failed: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result))
    else:
        print(f"Firmware hash: {result['firmware_hash'].upper()}")
        print(f"\nLedger status: {result['ledger_status']}\n")
        print("UPDATE ACCEPTED" if result["decision"] == "ACCEPT" else "UPDATE REJECTED")
    return 0 if result["decision"] == "ACCEPT" else 1


if __name__ == "__main__":
    raise SystemExit(main())