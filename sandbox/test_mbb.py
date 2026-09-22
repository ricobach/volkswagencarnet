#!/usr/bin/env python3
"""End-to-end Volkswagen EU legacy MBB/Car-Net authentication probe.

This deliberately runs as a sandbox probe before the MBB path is wired into
Connection. It uses RFC 8628 device authorization, asks the user to approve
the login in Volkswagen's browser page, exchanges the resulting VW ID token
for a legacy MBB bearer, then probes both account-level garage enumeration and
VIN-scoped MBB permission/discovery endpoints.

Account-level garage enumeration is expected to return HTTP 403 for the
``sc2:fal`` MBB bearer. Set ``VW_VIN`` in sandbox/.env to test the vehicle-level
path instead.

Tokens are never printed.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from typing import Any

import aiohttp

IDP_DEVICE_URL = "https://identity.vwgroup.io/oidc/v1/device_authorization"
IDP_TOKEN_URL = "https://identity.vwgroup.io/oidc/v1/token"

MBB_DEVICE_CLIENTS = (
    "9496332b-ea03-4091-a224-8c746b885068@apps_vw-dilab_com",
    "40945ec0-b870-4bb1-8583-a99325f99c65@apps_vw-dilab_com",
)
MBB_DEVICE_SCOPE = "openid profile mbb cars"

MBB_BASE = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth"
MBB_REGISTER_URL = f"{MBB_BASE}/mobile/register/v1"
MBB_TOKEN_URL = f"{MBB_BASE}/mobile/oauth2/v1/token"
MBB_SCOPE = "sc2:fal"

APP_ID = "de.volkswagen.carnet.eu.eremote"
APP_NAME = "WeConnect"
APP_VERSION = "5.17.6"
REGISTER_UA = f"WeConnect/{APP_VERSION} (Android 14; okhttp/3.14.9)"
TOKEN_UA = "okhttp/3.14.9"

MAL_LEGACY = "https://mal-1a.prd.ece.vwg-connect.com"
MAL_MODERN = "https://mal-3a.prd.eu.dp.vwg-connect.com"


def _jwt_claims(token: str) -> dict[str, Any]:
    """Decode public JWT claims only; never validates or logs the raw token."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def _mbb_audience(id_token: str) -> str | None:
    aud = _jwt_claims(id_token).get("aud")
    if isinstance(aud, str):
        return aud
    if isinstance(aud, list):
        values = [x for x in aud if isinstance(x, str) and x]
        delivery = [x for x in values if x.upper().endswith("DELIV1")]
        if delivery:
            return delivery[0]
        mbb = [x for x in values if x.upper().startswith("VWGMBB")]
        if mbb:
            return mbb[0]
        return values[0] if values else None
    return None


def _headers(bearer: str, client_id: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json",
        "X-App-Name": "Volkswagen",
        "X-App-Version": "3.51.1",
        "User-Agent": TOKEN_UA,
        "X-Client-Id": client_id,
    }
    user_id = str(_jwt_claims(bearer).get("sub") or "")
    if user_id:
        headers["X-MbbUserId"] = user_id
    return headers


async def request_device_code(session: aiohttp.ClientSession) -> tuple[str, dict]:
    last_error = ""
    for client_id in MBB_DEVICE_CLIENTS:
        async with session.post(
            IDP_DEVICE_URL,
            data={"client_id": client_id, "scope": MBB_DEVICE_SCOPE},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        ) as response:
            body = await response.text()
            if response.status == 200:
                payload = json.loads(body)
                print(f"Device authorization OK using client {client_id.split('@')[0]}")
                return client_id, payload
            last_error = f"HTTP {response.status}: {body[:250]}"
            print(f"Device client {client_id.split('@')[0]} rejected: {last_error}")
    raise RuntimeError(f"No MBB device client was accepted: {last_error}")


async def poll_device_token(
    session: aiohttp.ClientSession,
    client_id: str,
    device: dict,
) -> dict:
    device_code = str(device["device_code"])
    interval = max(1, int(device.get("interval", 5)))
    deadline = time.monotonic() + min(int(device.get("expires_in", 300)), 900)

    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        async with session.post(
            IDP_TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        ) as response:
            payload = await response.json(content_type=None)

        if response.status == 200:
            if not payload.get("id_token"):
                raise RuntimeError("IDP returned 200 but no id_token")
            print(
                "VW device approval complete "
                f"(refresh_token from IDP: {bool(payload.get('refresh_token'))})"
            )
            return payload

        error = payload.get("error", "")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise RuntimeError(
            f"Device token polling failed: HTTP {response.status} {error}: "
            f"{payload.get('error_description', '')}"
        )

    raise RuntimeError("Device authorization expired before approval")


async def register_mbb(
    session: aiohttp.ClientSession,
    id_token: str,
) -> str:
    desired_client_id = _mbb_audience(id_token)
    if not desired_client_id:
        raise RuntimeError("Could not determine an MBB audience from the VW id_token")

    claims = _jwt_claims(id_token)
    print(
        "ID token audience selected for MBB registration: "
        f"{desired_client_id}; aud={claims.get('aud')}"
    )

    body = {
        "client_name": "volkswagencarnet-sandbox",
        "platform": "google",
        "client_brand": "VW",
        "appId": APP_ID,
        "appName": APP_NAME,
        "appVersion": APP_VERSION,
        "id_token": id_token,
        "client_id": desired_client_id,
        "scope": MBB_SCOPE,
    }
    headers = {
        "Authorization": f"Bearer {id_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": REGISTER_UA,
    }

    async with session.post(MBB_REGISTER_URL, json=body, headers=headers) as response:
        text = await response.text()
        print(f"MBB register: HTTP {response.status}")
        if response.status not in (200, 201):
            raise RuntimeError(f"MBB register failed: {text[:500]}")
        payload = json.loads(text)

    registered = payload.get("client_id") or desired_client_id
    print(
        "MBB registration OK "
        f"(client_id returned: {bool(payload.get('client_id'))}, "
        f"client_secret returned: {bool(payload.get('client_secret'))})"
    )
    return str(registered)


async def exchange_mbb(
    session: aiohttp.ClientSession,
    id_token: str,
    client_id: str,
) -> dict:
    headers = {
        "X-Client-Id": client_id,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": TOKEN_UA,
    }
    data = {
        "grant_type": "id_token",
        "token": id_token,
        "scope": MBB_SCOPE,
    }

    async with session.post(MBB_TOKEN_URL, data=data, headers=headers) as response:
        text = await response.text()
        print(f"MBB token exchange: HTTP {response.status}")
        if response.status != 200:
            raise RuntimeError(f"MBB token exchange failed: {text[:500]}")
        payload = json.loads(text)

    if not payload.get("access_token"):
        raise RuntimeError("MBB token exchange returned no access_token")
    print(
        "MBB bearer acquired "
        f"(refresh_token: {bool(payload.get('refresh_token'))}, "
        f"expires_in: {payload.get('expires_in')})"
    )
    return payload


async def probe_garage(
    session: aiohttp.ClientSession,
    bearer: str,
    client_id: str,
) -> None:
    claims = _jwt_claims(bearer)
    print(
        "MBB bearer metadata: "
        f"sys={claims.get('sys')} cor={claims.get('cor')} "
        f"sub_present={bool(claims.get('sub'))}"
    )

    headers = _headers(bearer, client_id)
    candidates = (
        "https://msg.volkswagen.de/fs-car/usermanagement/users/v1/VW/DK/vehicles",
        "https://msg.volkswagen.de/fs-car/usermanagement/users/v1/VW/DE/vehicles",
        f"{MAL_LEGACY}/api/usermanagement/users/v1/vehicles",
    )

    got_200 = False
    for url in candidates:
        try:
            async with session.get(url, headers=headers) as response:
                text = await response.text()
                print(f"Garage probe {url}: HTTP {response.status}")
                if response.status == 200:
                    got_200 = True
                    try:
                        payload = json.loads(text)
                    except ValueError:
                        payload = None
                    print("Garage response:")
                    print(json.dumps(payload, indent=2)[:4000] if payload else text[:4000])
                else:
                    print(text[:500])
        except Exception as exc:
            print(f"Garage probe {url}: connection error: {exc}")

    if not got_200:
        print(
            "Garage enumeration was denied. This is expected for the "
            "sc2:fal MBB bearer; continuing with VW_VIN if configured."
        )


async def _probe_url(
    session: aiohttp.ClientSession,
    label: str,
    url: str,
    headers: dict[str, str],
) -> tuple[int, str]:
    try:
        async with session.get(url, headers=headers) as response:
            text = await response.text()
            print(f"{label}: HTTP {response.status}")
            print(text[:2000])
            return response.status, text
    except Exception as exc:
        print(f"{label}: connection error: {exc}")
        return 0, str(exc)


async def probe_vehicle(
    session: aiohttp.ClientSession,
    bearer: str,
    client_id: str,
    vin: str,
    country: str,
) -> bool:
    vin = vin.strip().upper()
    if len(vin) != 17:
        raise RuntimeError("VW_VIN must be a 17-character VIN")

    headers = _headers(bearer, client_id)
    print(f"\nTesting VIN-scoped MBB access for {vin[:3]}...{vin[-4:]}")

    probes: list[tuple[str, str]] = [
        (
            "homeRegion",
            f"{MAL_LEGACY}/api/cs/vds/v1/vehicles/{vin}/homeRegion",
        ),
        (
            "operationList/v3",
            f"{MAL_LEGACY}/api/rolesrights/operationlist/v3/vehicles/{vin}",
        ),
    ]

    countries = [country.upper()]
    if "DE" not in countries:
        countries.append("DE")
    for cc in countries:
        probes.append(
            (
                f"fetched-role ({cc})",
                f"{MAL_MODERN}/api/rolesrights/permissions/v1/VW/{cc}/vehicles/{vin}/fetched-role",
            )
        )

    any_success = False
    for label, url in probes:
        status, _ = await _probe_url(session, label, url, headers)
        if status == 200:
            any_success = True

    return any_success


async def main() -> int:
    vin = os.getenv("VW_VIN", "").strip().upper()
    country = os.getenv("VW_COUNTRY", "DK").strip().upper() or "DK"

    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        client_id, device = await request_device_code(session)
        verification_url = (
            device.get("verification_uri_complete")
            or device.get("verification_uri")
        )
        print("\nOpen this URL and approve the Volkswagen login:")
        print(verification_url)
        print(
            f"User code: {device.get('user_code')}  "
            f"(expires in {device.get('expires_in')} seconds)\n"
        )

        idp_tokens = await poll_device_token(session, client_id, device)
        id_token = str(idp_tokens["id_token"])
        registered_client_id = await register_mbb(session, id_token)
        mbb_tokens = await exchange_mbb(session, id_token, registered_client_id)
        bearer = str(mbb_tokens["access_token"])

        await probe_garage(session, bearer, registered_client_id)

        if not vin:
            print(
                "\nMBB authentication is OK, but VW_VIN is not configured. "
                "Add VW_VIN=<17-character VIN> to sandbox/.env and rerun to "
                "test vehicle-level access."
            )
            return 2

        vehicle_ok = await probe_vehicle(
            session,
            bearer,
            registered_client_id,
            vin,
            country,
        )

    if not vehicle_ok:
        print("\nMBB AUTH OK, BUT NO VIN-SCOPED ENDPOINT RETURNED HTTP 200")
        return 1

    print("\nMBB END-TO-END VEHICLE PROBE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
