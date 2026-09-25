"""Command-line JSON interface used by the TypeScript backend."""

import json
import sys

from .scanner import analyze_firmware


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m trust_adapter.cli FIRMWARE", file=sys.stderr)
        return 2
    print(json.dumps(analyze_firmware(sys.argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())