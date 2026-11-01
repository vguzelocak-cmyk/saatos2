import argparse
import json
from pathlib import Path
import sys

from .pe import PE, PEError


def main():
    parser = argparse.ArgumentParser(description="Inspect a Windows PE32+ driver without executing it.")
    parser.add_argument("driver", type=Path, help="Path to a driver you already have")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable report")
    args = parser.parse_args()
    try:
        with args.driver.open("rb") as source:
            data = source.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024:
            raise PEError("Input exceeds 128 MiB analysis limit")
        report = PE(data).report()
    except (OSError, PEError) as exc:
        print(f"driverlab: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"SHA-256: {report['sha256']}")
        print(f"Image: {report['machine']}, subsystem: {report['subsystem']}")
        print(f"Entry RVA: 0x{report['entry_point_rva']:x}")
        print(f"Static import symbols: {report['import_symbol_count']}")
        for module in report["imports"]:
            print(f"\n{module['module']}:")
            for symbol in module["symbols"]:
                print("  " + (symbol["name"] if "name" in symbol else f"ordinal #{symbol['ordinal']}"))
        print("\nDriver execution: NOT IMPLEMENTED")
        for limitation in report["limitations"]:
            print("- " + limitation)
    return 0


if __name__ == "__main__":
    sys.exit(main())
