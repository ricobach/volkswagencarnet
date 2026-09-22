"""Volkswagen EU OIDC/PKCE login flow.

Volkswagen EU does not allow the consumer VW client to use RFC 8628
device_authorization.  This flow therefore uses the normal OIDC authorize
endpoint with PKCE and the existing Auth0/IDK username/password form.

The hybrid response_type is intentional: current VW EU deployments can return
usable access/id tokens in the app callback even when the CARIAD token exchange
is restricted.  When an authorization code is available we still attempt the
current CARIAD token exchange with x-qmauth in order to obtain a refresh token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup
from yarl import URL

from ..vw_const import APP_URI, CLIENT_ID, CLIENT_SCOPE
from ..vw_exceptions import LoginCredentialsError, LoginError
from ..vw_utilities import dump_html_debug

_LOGGER = logging.getLogger(__name__)

_IDK_BASE = "https://identity.vwgroup.io"
_AUTHORIZE_URL = f"{_IDK_BASE}/oidc/v1/authorize"
_CARIAD_TOKEN_URL = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"

# Current VW Android identity.  Keep this local to the auth flow so changing the
# general API user-agent is not required to test authentication.
_VW_USER_AGENT = "Volkswagen/4.2.1-android/14"
_FIREFOX_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) "
    "Gecko/20100101 Firefox/130.0"
)

# x-qmauth values currently used by the VW/Audi CARIAD token endpoint.
# The previous pair is retained as a single retry because these values have
# rotated before.
_QM_CLIENT_ID = "01da27b0"
_QM_SECRET = "1ab69925ac179aaa4e83abe671a9476d176418b85bd706f1436ca15be647989c"
_QM_PRIOR_CLIENT_ID = "c95f4fd2"
_QM_PRIOR_SECRET = "e47866378ef0658ce75d71007a809f34616b9635e2ec228245784c1f63e88d06"

_AUTH_ERROR_MESSAGES = {
    "login.errors.password_invalid": "Incorrect password.",
    "login.error.throttled": "Too many failed login attempts — please wait before trying again.",
    "login.error.locked": "Account has been locked due to too many failed attempts.",
    "login.error.blocked": "Login blocked by VW identity service.",
}


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoginError(f"Missing or invalid {field}")
    return value


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _x_qmauth(client_id: str, secret_hex: str) -> str:
    bucket = int(time.time() / 100)
    signature = hmac.new(
        bytes.fromhex(secret_hex),
        str(bucket).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"v1:{client_id}:{signature}"


def _callback_params(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    result: dict[str, str] = {}
    for source in (parsed.query, parsed.path.lstrip("?"), parsed.fragment):
        if not source:
            continue
        for key, values in parse_qs(source).items():
            if values and key not in result:
                result[key] = values[0]
    return result


def _safe_url(url: str) -> str:
    """Return host + path only; never log callback query/fragment tokens."""
    parsed = urlparse(url)
    return f"{parsed.netloc}{parsed.path}"


class VWLoginFlow:
    """VW EU PKCE/hybrid authentication."""

    def __init__(
        self,
        verifier=None,  # retained for API compatibility with the previous flow
        html_debug_dir: Path | None = None,
        use_fake_user_agent: bool = False,
        client_id: str = CLIENT_ID,
        client_scope: str = CLIENT_SCOPE,
    ) -> None:
        del verifier
        self._html_debug_dir = html_debug_dir
        self._use_fake_user_agent = use_fake_user_agent
        self._client_id = _require_str(client_id, "client_id")
        self._client_scope = _require_str(client_scope, "client_scope")

    def _browser_headers(self) -> dict[str, str]:
        return {
            "User-Agent": (
                _FIREFOX_USER_AGENT if self._use_fake_user_agent else _VW_USER_AGENT
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def login(
        self,
        username: str,
        password: str,
        *,
        cookies_file: Path | None = None,
    ) -> dict:
        username = _require_str(username, "username")
        password = _require_str(password, "password")

        jar = aiohttp.CookieJar(unsafe=True)
        if cookies_file is not None:
            await _load_cookies(jar, cookies_file)

        verifier, challenge = _pkce_pair()

        async with aiohttp.ClientSession(
            headers=self._browser_headers(),
            cookie_jar=jar,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            callback_url = await self._authorize_and_login(
                session,
                username=username,
                password=password,
                code_challenge=challenge,
            )
            params = _callback_params(callback_url)

            error = params.get("error")
            if error:
                raise LoginCredentialsError(
                    _AUTH_ERROR_MESSAGES.get(
                        error, f"Authentication rejected by VW: {error!r}"
                    )
                )

            auth_code = params.get("code")
            callback_access = params.get("access_token")
            callback_id = params.get("id_token")

            if not auth_code and not (callback_access and callback_id):
                raise LoginError(
                    "VW callback contained neither an authorization code nor "
                    "hybrid access/id tokens"
                )

            token_payload: dict | None = None
            if auth_code:
                token_payload = await self._exchange_code(
                    session,
                    auth_code=auth_code,
                    code_verifier=verifier,
                )

            # Prefer the exchange response because it may contain a refresh_token.
            # If VW blocks that exchange but the hybrid callback supplied usable
            # tokens, keep those rather than failing the entire login.
            result: dict | None = None
            if token_payload and token_payload.get("access_token"):
                if not token_payload.get("id_token") and callback_id:
                    token_payload["id_token"] = callback_id
                if token_payload.get("id_token"):
                    result = token_payload

            if result is None and callback_access and callback_id:
                _LOGGER.info(
                    "Using OIDC hybrid callback tokens; no refresh token is available"
                )
                result = {
                    "access_token": callback_access,
                    "id_token": callback_id,
                    "token_type": "Bearer",
                }

            if result is None:
                raise LoginError(
                    "Authorization succeeded, but no usable VW access/id token pair "
                    "was returned"
                )

            if cookies_file is not None:
                await _save_cookies(jar, cookies_file)

            return result

    async def _authorize_and_login(
        self,
        session: aiohttp.ClientSession,
        *,
        username: str,
        password: str,
        code_challenge: str,
    ) -> str:
        scope = self._client_scope
        if "offline_access" not in scope.split():
            scope = f"{scope} offline_access"

        params = {
            "client_id": self._client_id,
            "redirect_uri": APP_URI,
            "response_type": "code id_token token",
            "scope": scope,
            "nonce": uuid.uuid4().hex,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        _LOGGER.debug("GET %s (PKCE hybrid authorize)", _AUTHORIZE_URL)
        async with session.get(
            _AUTHORIZE_URL,
            params=params,
            allow_redirects=False,
        ) as response:
            first_location = response.headers.get("Location")
            if not first_location:
                body = await response.text()
                await self._maybe_dump("authorize_no_redirect", body, str(response.url))
                raise LoginError(
                    f"VW authorize returned HTTP {response.status} without Location"
                )
            current = urljoin(str(response.url), first_location)

        # Follow redirect(s) until the login HTML is reached.  Do not let aiohttp
        # follow the final custom weconnect:// URI.
        login_html = ""
        login_url = current
        for _ in range(10):
            if login_url.startswith(APP_URI):
                raise LoginError("VW redirected to app callback before credentials")
            _LOGGER.debug("GET %s", _safe_url(login_url))
            async with session.get(login_url, allow_redirects=False) as response:
                location = response.headers.get("Location")
                if location:
                    login_url = urljoin(str(response.url), location)
                    continue
                login_html = await response.text()
                if response.status != 200:
                    await self._maybe_dump(
                        "login_page_http_error", login_html, str(response.url)
                    )
                    raise LoginError(
                        f"VW login page returned HTTP {response.status}"
                    )
                break
        else:
            raise LoginError("Too many redirects before VW login page")

        state = _extract_state(login_html)
        if not state:
            await self._maybe_dump("login_page_no_state", login_html, login_url)
            raise LoginError("VW login page did not contain an Auth0 state token")

        login_post_url = f"{_IDK_BASE}/u/login?state={state}"
        login_headers = self._browser_headers()
        login_headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": _IDK_BASE,
                "Referer": login_url,
            }
        )
        form = {
            "username": username,
            "password": password,
            "state": state,
            # Current VW hybrid flow requires the default action.  Without it,
            # some IDK templates return to identifier-first instead of checking
            # the password.
            "action": "default",
        }

        _LOGGER.debug("POST %s", _safe_url(login_post_url))
        async with session.post(
            login_post_url,
            headers=login_headers,
            data=form,
            allow_redirects=False,
        ) as response:
            location = response.headers.get("Location")
            if not location:
                body = await response.text()
                await self._maybe_dump("login_post_no_redirect", body, str(response.url))
                _raise_login_page_error(body, response.status)
            current = urljoin(str(response.url), location)

        # Follow the callback chain until the app URI.  Never log query strings
        # or fragments because they contain authorization material.
        for _ in range(15):
            error = _callback_params(current).get("error")
            if error:
                raise LoginCredentialsError(
                    _AUTH_ERROR_MESSAGES.get(
                        error, f"Authentication rejected by VW: {error!r}"
                    )
                )

            if current.startswith(APP_URI):
                _LOGGER.debug("Reached VW app callback")
                return current

            _LOGGER.debug("GET redirect %s", _safe_url(current))
            async with session.get(current, allow_redirects=False) as response:
                location = response.headers.get("Location")
                if location:
                    current = urljoin(str(response.url), location)
                    continue

                body = await response.text()
                if _looks_like_terms_page(body):
                    await self._maybe_dump(
                        "terms_required", body, str(response.url)
                    )
                    raise LoginError(
                        "Volkswagen terms/consent must be accepted in the VW portal/app"
                    )
                await self._maybe_dump(
                    "redirect_chain_stopped", body, str(response.url)
                )
                raise LoginError(
                    f"VW login redirect chain stopped at HTTP {response.status}"
                )

        raise LoginError("Too many redirects during VW login")

    async def _exchange_code(
        self,
        session: aiohttp.ClientSession,
        *,
        auth_code: str,
        code_verifier: str,
    ) -> dict | None:
        payload = {
            "client_id": self._client_id,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": APP_URI,
            "code_verifier": code_verifier,
        }

        pairs = (
            (_QM_CLIENT_ID, _QM_SECRET),
            (_QM_PRIOR_CLIENT_ID, _QM_PRIOR_SECRET),
        )
        for index, (qm_client_id, qm_secret) in enumerate(pairs, start=1):
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Accept-Charset": "utf-8",
                "User-Agent": _VW_USER_AGENT,
                "x-qmauth": _x_qmauth(qm_client_id, qm_secret),
            }
            _LOGGER.debug(
                "POST %s (authorization_code exchange, x-qmauth pair %s)",
                _CARIAD_TOKEN_URL,
                index,
            )
            async with session.post(
                _CARIAD_TOKEN_URL,
                headers=headers,
                data=payload,
                allow_redirects=False,
            ) as response:
                body = await response.text()
                _LOGGER.debug("CARIAD token exchange: HTTP %s", response.status)
                if response.status == 200:
                    try:
                        result = json.loads(body)
                    except json.JSONDecodeError as error:
                        raise LoginError(
                            "CARIAD token endpoint returned invalid JSON"
                        ) from error
                    _LOGGER.debug(
                        "CARIAD token exchange keys: %s", sorted(result.keys())
                    )
                    return result

                # Body contains useful OAuth diagnostics but no credentials; log
                # only a bounded representation.
                _LOGGER.warning(
                    "CARIAD token exchange failed (HTTP %s, pair %s): %s",
                    response.status,
                    index,
                    body[:500],
                )

        return None

    async def _maybe_dump(self, stage: str, html: str, url: str) -> None:
        if self._html_debug_dir is not None and html:
            await dump_html_debug(stage, html, self._html_debug_dir, url)


def _extract_state(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    element = soup.select_one('input[name="state"]')
    if element and element.get("value"):
        return str(element["value"])
    return None


def _raise_login_page_error(html: str, status: int) -> None:
    soup = BeautifulSoup(html, "html.parser")
    for field_id in ("error-element-username", "error-element-password"):
        span = soup.select_one(f'span[id="{field_id}"]')
        if span and span.get("data-error-code") == "wrong-email-credentials":
            raise LoginCredentialsError("Incorrect username or password")
    raise LoginError(f"VW credential submission failed with HTTP {status}")


def _looks_like_terms_page(html: str) -> bool:
    lowered = html.lower()
    return "termsandconditions" in lowered or "dataprivacy" in lowered


async def _load_cookies(jar: aiohttp.CookieJar, file_path: Path) -> None:
    try:
        raw = await _read_text(file_path)
        if not raw:
            return
        entries = json.loads(raw)
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            value = entry.get("value")
            domain = entry.get("domain", "identity.vwgroup.io")
            if name and value:
                jar.update_cookies(
                    {str(name): str(value)},
                    response_url=URL.build(
                        scheme="https",
                        host=str(domain).lstrip("."),
                    ),
                )
    except (OSError, json.JSONDecodeError, ValueError):
        _LOGGER.debug("Could not load persisted VW auth cookies", exc_info=True)


async def _save_cookies(jar: aiohttp.CookieJar, file_path: Path) -> None:
    entries: list[dict[str, str]] = []
    for cookie in jar:
        entries.append(
            {
                "name": cookie.key,
                "value": cookie.value,
                "domain": cookie["domain"] or "identity.vwgroup.io",
            }
        )
    try:
        await _write_text(
            file_path,
            json.dumps(entries, indent=2),
        )
    except OSError:
        _LOGGER.warning("Could not persist VW auth cookies", exc_info=True)


async def _read_text(path: Path) -> str:
    import asyncio

    try:
        return await asyncio.to_thread(path.read_text, encoding="utf-8")
    except FileNotFoundError:
        return ""


async def _write_text(path: Path, content: str) -> None:
    import asyncio

    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(path.write_text, content, encoding="utf-8")
