"""Handshake worker used only to test the campaign timing contract."""

from __future__ import annotations

import argparse
import json
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-delay", type=float, default=0)
    parser.add_argument("--runtime-delay", type=float, default=0)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    time.sleep(args.preflight_delay)
    print(json.dumps({"status": "ready", "mode": args.mode}), flush=True)
    request = json.loads(sys.stdin.readline())
    time.sleep(args.runtime_delay)
    print(json.dumps({"status": "ok", "value": request["value"], "mode": args.mode}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
