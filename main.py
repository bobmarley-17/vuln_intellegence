"""CLI entry point for the vulnerability intelligence tool.

Usage:
    python main.py run          # download articles, extract & enrich CVEs
    python main.py dashboard     # launch the Flask web dashboard
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import sys

from config import config


def setup_logging() -> None:
    root = logging.getLogger("vuln_intel")
    root.setLevel(logging.DEBUG)

    file_handler = logging.handlers.RotatingFileHandler(
        config.log_file_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    root.addHandler(file_handler)
    root.addHandler(console_handler)


def run_pipeline() -> None:
    from modules.pipeline import Pipeline

    pipeline = Pipeline(config)
    stats = pipeline.run()
    print(
        f"\nDone. Articles: {stats['articles']}  Unique CVEs: {stats['cves']}  "
        f"Freshly enriched: {stats['enriched']}  From cache: {stats['cached']}"
    )


def run_dashboard(host: str, port: int, debug: bool) -> None:
    from dashboard.app import create_app

    app = create_app(config)
    app.run(host=host, port=port, debug=debug, threaded=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnerability Intelligence Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Download articles and enrich CVEs")

    dash_parser = subparsers.add_parser("dashboard", help="Launch the web dashboard")
    dash_parser.add_argument("--host", default="127.0.0.1")
    dash_parser.add_argument("--port", type=int, default=5000)
    dash_parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()
    setup_logging()

    if args.command == "run":
        run_pipeline()
    elif args.command == "dashboard":
        run_dashboard(args.host, args.port, args.debug)


if __name__ == "__main__":
    main()
