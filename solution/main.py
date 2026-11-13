#!/usr/bin/env python3
from __future__ import annotations
import argparse
from ledger import Ledger

def main() -> None:
    parser = argparse.ArgumentParser(description="Interaction Ledger & Reporting Pipeline")
    parser.add_argument("--db", default="solution/ledger.sqlite3")
    parser.add_argument("--key", default=None, help="PII encryption key; alternatively set LEDGER_ENCRYPTION_KEY")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest"); ingest.add_argument("drop")
    report = commands.add_parser("report"); report.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        ledger = Ledger(args.db, args.key)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        if args.command == "ingest": ledger.ingest(args.drop)
        else: ledger.report(args.out)
    finally: ledger.close()

if __name__ == "__main__": main()
