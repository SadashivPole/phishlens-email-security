#!/usr/bin/env python3
"""Command-line entry point for the local PhishLens foundation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from src.phishlens.config import Settings
from src.phishlens.pipeline.analyzer import Analyzer


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an .eml file locally.")
    parser.add_argument("eml_file", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    try:
        raw = args.eml_file.read_bytes()
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        print(f"error: unable to read input file: {detail}", file=sys.stderr)
        return 2

    settings = Settings()
    result = Analyzer(settings).analyze(raw)
    payload = result.to_safe_dict() if args.as_json else result.to_dict()

    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"VERDICT: {payload['verdict']['final']}")
        print(f"RISK SCORE: {payload['scoring']['total_score']}/{payload['scoring']['maximum_score']}")
        print(f"ANALYSIS STATUS: {payload['verdict']['analysis_status']}")
        print(f"REASON: {payload['verdict']['reason']}")
        for finding in payload["evidence"]:
            print(f"- {finding['signal_id']}: {finding['explanation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
