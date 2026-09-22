"""Volkswagen EU PKCE / IDK authorization-code login.

Volkswagen EU does not permit the OAuth device_code grant for its consumer
client.  This flow uses the standard OIDC authorization endpoint with PKCE,
drives the VW/Auth0 login form, follows the redirect back to the app URI, and
exchanges the resulting authorization code at the current CARIAD BFF token
endpoint.
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
from ..vw_exceptions import (
    LoginCredentialsError,
    LoginError,
    LoginFlowChangedError,
    TermsAndConditionsError,
)

_LOGGER = logging.getLogger(__name__)

AUTHORIZE_URL = "https://identity.vwgroup.io/oidc/v1/authorize"
TOKEN_URL = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"

# Current VW Android identity seen in the 2026 app generation.
APP_USER_AGENT = "Volkswagen/4.2.1-android/14"

# x-qmauth rotates independently of the OAuth client ID. Keep the immediately
# previous pair as a fallback so a partially rolled-out edge does not make the
# whole login fail on the first attempt.
_QMAUTH_PAIRS = (
    ("01da27b0", "1ab69925ac179aaa4e83abe671a9476d176418b85bd706f1436ca15be647989c"),
    ("c95f4fd2", "e47866378ef0658ce75d71007a809f34616b9635e2ec228245784c1f63e88d06"),
)

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) "
        "Gecko/20100101 Firefox/130.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _x_qmauth(client_id: str, secret_hex: str) -> str:
    bucket = str(int(time.time() / 100)).encode("ascii")
    signature = hmac.new(bytes.fromhex(secret_hex), bucket, hashlib.sha256).hexdigest()
    return f"v1:{client_id}:{signature}"


def _extract_callback_param(url: str, name: str) -> str | None:
    parsed = urlparse(url)
    for source in (parsed.query, parsed.fragment, parsed.path.lstrip("?")):
        if not source:
            continue
        values = parse_qs(source).get(name)
        if values and values[0]:
            return values[0]
    return None


class VWLoginFlow:
    """VW EU authorization-code + PKCE login.

    The constructor intentionally keeps the same public signature as the former
    device-flow implementation so Connection does not need to change.
    """

    def __init__(
        self,
        verifier=None,  # kept for API compatibility with the old login class
        html_debug_dir: Path | None = None,
        use_fake_user_agent: bool = False,
        client_id: str = CLIENT_ID,
        client_scope: str = CLIENT_SCOPE,
    ) -> None:
        del verifier
        self._html_debug_dir = Path(html_debug_dir) if html_debug_dir else None
        self._use_fake_user_agent = use_fake_user_agent
        self._client_id = client_id
        self._client_scope = client_scope

    async def login(
        self,
        username: str,
        password: str,
        *,
        cookies_file: Path | None = None,
    ) -> dict:
        if not username or not password:
            raise LoginCredentialsError("Username and password are required")

        code_verifier, code_challenge = _pkce_pair()
        oidc_state = uuid.uuid4().hex
        nonce = uuid.uuid4().hex

        jar = aiohttp.CookieJar(unsafe=True)
        if cookies_file:
            self._load_cookies(jar, Path(cookies_file))

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(
            headers=self._browser_headers(),
            cookie_jar=jar,
            timeout=timeout,
        ) as session:
            login_page_url, login_html = await self._authorization_page(
                session,
                code_challenge=code_challenge,
                state=oidc_state,
                nonce=nonce,
            )
            callback_url = await self._submit_credentials(
                session,
                login_page_url=login_page_url,
                login_html=login_html,
                username=username,
                password=password,
            )

            if cookies_file:
                self._save_cookies(jar, Path(cookies_file))

            callback_error = _extract_callback_param(callback_url, "error")
            if callback_error:
                description = (
                    _extract_callback_param(callback_url, "error_description")
                    or callback_error
                )
                raise LoginCredentialsError(
                    f"Authentication rejected by VW: {description}"
                )

            returned_state = _extract_callback_param(callback_url, "state")
            if returned_state and returned_state != oidc_state:
                raise LoginFlowChangedError(stage="oidc_state_mismatch")

            auth_code = _extract_callback_param(callback_url, "code")
            if not auth_code:
                raise LoginFlowChangedError(stage="missing_authorization_code")

            return await self._exchange_code(
                session,
                auth_code=auth_code,
                code_verifier=code_verifier,
            )

    def _browser_headers(self) -> dict[str, str]:
        headers = dict(_BROWSER_HEADERS)
        if not self._use_fake_user_agent:
            headers["X-VW-Client"] = APP_USER_AGENT
        return headers

    async def _authorization_page(
        self,
        session: aiohttp.ClientSession,
        *,
        code_challenge: str,
        state: str,
        nonce: str,
    ) -> tuple[str, str]:
        params = {
            "client_id": self._client_id,
            "scope": self._client_scope,
            "response_type": "code",
            "redirect_uri": APP_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce,
        }

        _LOGGER.debug("GET %s (PKCE authorization)", AUTHORIZE_URL)
        async with session.get(
            AUTHORIZE_URL,
            params=params,
            allow_redirects=False,
        ) as response:
            _LOGGER.debug("authorize response: HTTP %s", response.status)
            if response.status not in (301, 302, 303, 307, 308):
                body = await response.text()
                self._dump_debug("authorize_error", body)
                raise LoginError(
                    f"Authorization endpoint returned HTTP {response.status}: "
                    f"{body[:300]}"
                )
            location = response.headers.get("Location")

        if not location:
            raise LoginFlowChangedError(stage="authorize_missing_location")

        current = urljoin(AUTHORIZE_URL, location)
        for hop in range(10):
            if current.startswith(APP_URI):
                raise LoginFlowChangedError(stage="authorize_redirected_without_login")

            _LOGGER.debug("GET auth redirect hop %s: %s", hop + 1, self._safe_url(current))
            async with session.get(current, allow_redirects=False) as response:
                body = await response.text()
                if response.status == 200:
                    self._dump_debug("login_page", body)
                    return str(response.url), body
                if response.status not in (301, 302, 303, 307, 308):
                    self._dump_debug("authorize_redirect_error", body)
                    raise LoginError(
                        f"Authorization redirect returned HTTP {response.status}"
                    )
                location = response.headers.get("Location")

            if not location:
                raise LoginFlowChangedError(stage="authorize_redirect_missing_location")
            current = urljoin(current, location)

        raise LoginFlowChangedError(stage="authorize_redirect_loop")

    async def _submit_credentials(
        self,
        session: aiohttp.ClientSession,
        *,
        login_page_url: str,
        login_html: str,
        username: str,
        password: str,
    ) -> str:
        soup = BeautifulSoup(login_html, "html.parser")
        state_input = soup.select_one('input[name="state"]')
        form_state = state_input.get("value") if state_input else None
        if not form_state:
            self._dump_debug("missing_form_state", login_html)
            raise LoginFlowChangedError(stage="login_form_missing_state")

        form = soup.find("form")
        form_action = form.get("action") if form else None
        if form_action:
            login_url = urljoin(login_page_url, form_action)
        else:
            parsed = urlparse(login_page_url)
            login_url = f"{parsed.scheme}://{parsed.netloc}/u/login?state={form_state}"

        payload = {
            "username": username,
            "password": password,
            "state": form_state,
            "action": "default",
        }
        headers = {
            "Origin": f"{urlparse(login_url).scheme}://{urlparse(login_url).netloc}",
            "Referer": login_page_url,
        }

        _LOGGER.debug("POST %s (credentials)", self._safe_url(login_url))
        async with session.post(
            login_url,
            data=payload,
            headers=headers,
            allow_redirects=False,
        ) as response:
            body = await response.text()
            _LOGGER.debug("credential response: HTTP %s", response.status)

            if response.status == 400:
                self._dump_debug("credentials_400", body)
                self._raise_credentials_error(body)
            if response.status not in (301, 302, 303, 307, 308):
                self._dump_debug("credentials_error", body)
                raise LoginError(
                    f"Credential submission returned HTTP {response.status}"
                )
            location = response.headers.get("Location")

        if not location:
            raise LoginFlowChangedError(stage="credentials_missing_location")

        return await self._follow_callback(session, login_url, location)

    async def _follow_callback(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        location: str,
    ) -> str:
        current = urljoin(base_url, location)

        for hop in range(15):
            if current.startswith(APP_URI):
                _LOGGER.debug("Reached VW app callback after %s redirect(s)", hop)
                return current

            _LOGGER.debug("GET callback hop %s: %s", hop + 1, self._safe_url(current))
            async with session.get(current, allow_redirects=False) as response:
                body = await response.text()

                if response.status == 200 and "Location" not in response.headers:
                    self._dump_debug("callback_non_redirect", body)
                    if (
                        "termsAndConditions" in body
                        or '"page":"termsAndConditions"' in body
                    ):
                        raise TermsAndConditionsError(
                            "Terms and Conditions must be accepted in the "
                            "Volkswagen portal before logging in."
                        )
                    raise LoginFlowChangedError(stage="unexpected_callback_page")

                if response.status not in (301, 302, 303, 307, 308):
                    self._dump_debug("callback_error", body)
                    raise LoginError(
                        f"Callback redirect returned HTTP {response.status}"
                    )
                next_location = response.headers.get("Location")

            if not next_location:
                raise LoginFlowChangedError(stage="callback_missing_location")
            current = urljoin(current, next_location)

        raise LoginFlowChangedError(stage="callback_redirect_loop")

    async def _exchange_code(
        self,
        session: aiohttp.ClientSession,
        *,
        auth_code: str,
        code_verifier: str,
    ) -> dict:
        data = {
            "client_id": self._client_id,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": APP_URI,
            "code_verifier": code_verifier,
        }

        last_status = 0
        last_body = ""
        for index, (qm_client_id, qm_secret) in enumerate(_QMAUTH_PAIRS, start=1):
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Accept-Charset": "utf-8",
                "User-Agent": APP_USER_AGENT,
                "x-qmauth": _x_qmauth(qm_client_id, qm_secret),
            }
            _LOGGER.debug(
                "POST %s (authorization_code exchange, qmauth candidate %s)",
                TOKEN_URL,
                index,
            )
            async with session.post(
                TOKEN_URL,
                data=data,
                headers=headers,
                allow_redirects=False,
            ) as response:
                last_status = response.status
                last_body = await response.text()

            if last_status == 200:
                try:
                    token_payload = json.loads(last_body)
                except json.JSONDecodeError as exc:
                    raise LoginError("CARIAD token response was not valid JSON") from exc

                if not token_payload.get("access_token"):
                    raise LoginError("CARIAD token response missing access_token")
                _LOGGER.debug(
                    "CARIAD token exchange succeeded; fields=%s",
                    sorted(token_payload.keys()),
                )
                return token_payload

            _LOGGER.debug(
                "CARIAD token exchange candidate %s returned HTTP %s: %s",
                index,
                last_status,
                last_body[:300],
            )

            if last_status < 400 or last_status >= 500:
                break

        raise LoginError(
            f"CARIAD token exchange failed with HTTP {last_status}: "
            f"{last_body[:300]}"
        )

    @staticmethod
    def _raise_credentials_error(html: str) -> None:
        soup = BeautifulSoup(html, "html.parser")
        for field_id in ("error-element-username", "error-element-password"):
            span = soup.select_one(f'span[id="{field_id}"]')
            if not span:
                continue
            code = span.get("data-error-code")
            if code == "wrong-email-credentials":
                raise LoginCredentialsError("Incorrect username or password")
        lowered = html.lower()
        if "password_invalid" in lowered or "wrong password" in lowered:
            raise LoginCredentialsError("Incorrect username or password")
        if "throttled" in lowered:
            raise LoginCredentialsError(
                "Too many failed login attempts; Volkswagen has throttled the account."
            )
        raise LoginCredentialsError("Volkswagen rejected the login credentials")

    def _dump_debug(self, name: str, body: str) -> None:
        if not self._html_debug_dir:
            return
        self._html_debug_dir.mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        (self._html_debug_dir / f"{timestamp}_{name}.html").write_text(
            body, encoding="utf-8"
        )

    @staticmethod
    def _safe_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    @staticmethod
    def _load_cookies(jar: aiohttp.CookieJar, path: Path) -> None:
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for item in raw:
                name = item.get("name")
                value = item.get("value")
                domain = item.get("domain") or "identity.vwgroup.io"
                if name and value:
                    jar.update_cookies(
                        {name: value}, response_url=URL(f"https://{domain}/")
                    )
        except (OSError, ValueError, TypeError):
            _LOGGER.debug("Could not restore cached authentication cookies", exc_info=True)

    @staticmethod
    def _save_cookies(jar: aiohttp.CookieJar, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        items = []
        for cookie in jar:
            items.append(
                {
                    "name": cookie.key,
                    "value": cookie.value,
                    "domain": cookie["domain"] or "identity.vwgroup.io",
                }
            )
        try:
            path.write_text(json.dumps(items, indent=2), encoding="utf-8")
        except OSError:
            _LOGGER.debug("Could not persist authentication cookies", exc_info=True)
