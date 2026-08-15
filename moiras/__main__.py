"""Command-line entry point for the offline synthetic gate."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .harness import run_gate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the offline Moiras shadow gate.")
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Also write the sanitized gate report to PATH.",
    )
    args = parser.parse_args(argv)

    result = run_gate()
    payload = result.to_dict()
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if args.json is not None:
        Path(args.json).write_text(serialized + "\n", encoding="utf-8")
    print(serialized)
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
