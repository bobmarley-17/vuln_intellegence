"""CLI entry point for the vulnerability intelligence tool.

Usage:
    python main.py run              # download articles, extract & enrich CVEs
    python main.py dashboard        # launch the Flask web dashboard
    python main.py create-user      # create a dashboard login account
    python main.py list-users       # list dashboard login accounts
    python main.py enable-user <u>  # re-enable a disabled account
    python main.py disable-user <u> # disable an account without deleting it
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

    app = create_app(config, debug=debug)
    app.run(host=host, port=port, debug=debug, threaded=True)


def run_create_user() -> None:
    import getpass

    from modules.cache import DuplicateUserError, VulnCache

    cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)

    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if cache.get_user_by_username(username):
        print(f"User '{username}' already exists.", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)
    if getpass.getpass("Confirm password: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    try:
        user_id = cache.create_user(username, password)
    except DuplicateUserError:
        print(f"User '{username}' already exists.", file=sys.stderr)
        sys.exit(1)
    print(f"Created user '{username}' (id={user_id}). They can now sign in at /login.")


def run_list_users() -> None:
    from modules.cache import VulnCache

    cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)
    users = cache.list_users()
    if not users:
        print("No users yet. Create one with: python main.py create-user")
        return
    print(f"{'USERNAME':<24}{'STATUS':<10}{'CREATED':<34}{'LAST LOGIN'}")
    for u in users:
        status = "enabled" if u["is_active"] else "disabled"
        print(f"{u['username']:<24}{status:<10}{u['created_at']:<34}{u['last_login_at'] or 'never'}")


def run_set_user_active(username: str, active: bool) -> None:
    from modules.cache import VulnCache

    cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)
    if not cache.set_user_active(username, active):
        print(f"No such user: {username}", file=sys.stderr)
        sys.exit(1)
    print(f"User '{username}' {'enabled' if active else 'disabled'}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnerability Intelligence Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Download articles and enrich CVEs")

    dash_parser = subparsers.add_parser("dashboard", help="Launch the web dashboard")
    dash_parser.add_argument("--host", default="127.0.0.1")
    dash_parser.add_argument("--port", type=int, default=5000)
    dash_parser.add_argument("--debug", action="store_true")

    subparsers.add_parser("create-user", help="Create a login account for the dashboard")
    subparsers.add_parser("list-users", help="List dashboard login accounts")

    enable_parser = subparsers.add_parser("enable-user", help="Re-enable a disabled login account")
    enable_parser.add_argument("username")

    disable_parser = subparsers.add_parser("disable-user", help="Disable a login account without deleting it")
    disable_parser.add_argument("username")

    args = parser.parse_args()
    setup_logging()

    if args.command == "run":
        run_pipeline()
    elif args.command == "dashboard":
        run_dashboard(args.host, args.port, args.debug)
    elif args.command == "create-user":
        run_create_user()
    elif args.command == "list-users":
        run_list_users()
    elif args.command == "enable-user":
        run_set_user_active(args.username, True)
    elif args.command == "disable-user":
        run_set_user_active(args.username, False)


if __name__ == "__main__":
    main()
