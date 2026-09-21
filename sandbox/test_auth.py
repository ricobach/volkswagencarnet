#!/usr/bin/env python3
"""Small Docker-only authentication harness for volkswagencarnet."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
import sys

from aiohttp import ClientSession

from volkswagencarnet.vw_connection import Connection


SANDBOX_DIR = Path(__file__).resolve().parent
STATE_DIR = SANDBOX_DIR / "state"
DEBUG_DIR = SANDBOX_DIR / "debug"


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


async def run(args: argparse.Namespace) -> int:
    username = os.getenv("VW_USERNAME", "").strip()
    password = os.getenv("VW_PASSWORD", "")
    country = os.getenv("VW_COUNTRY", "DK").strip().upper() or "DK"

    if not username or not password:
        print(
            "Missing VW_USERNAME or VW_PASSWORD. "
            "Copy sandbox/.env.example to sandbox/.env and add your credentials.",
            file=sys.stderr,
        )
        return 2

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    async with ClientSession(headers={"Connection": "keep-alive"}) as session:
        connection = Connection(
            session,
            username,
            password,
            country=country,
            auth_cookies_file=STATE_DIR / "auth_cookies.json",
            auth_debug_dump_dir=DEBUG_DIR,
            use_fake_user_agent=env_bool("VW_FAKE_USER_AGENT"),
        )

        print(f"Attempting Volkswagen login for {username} ({country})...")
        logged_in = await connection.doLogin(tries=args.tries)

        if not logged_in:
            print("LOGIN FAILED")
            last_error = getattr(connection, "_last_login_error", None)
            if last_error:
                print(f"Last login error: {last_error}")
            print(f"Debug files, if generated: {DEBUG_DIR}")
            return 1

        print("LOGIN OK")
        vehicles = list(connection.vehicles)
        print(f"Vehicles found: {len(vehicles)}")
        for vehicle in vehicles:
            vin = getattr(vehicle, "vin", None) or getattr(vehicle, "_vin", "<unknown>")
            print(f"  - {vin}")

        if args.update:
            print("Running connection.update()...")
            updated = await connection.update()
            print(f"UPDATE {'OK' if updated else 'FAILED'}")
            if not updated:
                return 1

        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test volkswagencarnet authentication inside Docker."
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="After login, also run connection.update().",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    parser.add_argument(
        "--tries",
        type=int,
        default=1,
        help="Number of login attempts (default: 1).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run(parse_args())))
