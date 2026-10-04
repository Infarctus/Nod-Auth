#!/usr/bin/env python3
"""Snapshot an explicitly selected PC state directory for one-time Android import."""
import argparse
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from app.state_bundle import BundleError, export_bundle as export_setup


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        export_setup(args.state_dir, args.output)
    except (BundleError, OSError, sqlite3.Error) as exc:
        parser.exit(1, str(exc) + '\n' if isinstance(exc, BundleError) else 'Could not export setup. Check file permissions.\n')
    print('Setup ZIP created. Import it once, then use the phone as the sole listener.')
