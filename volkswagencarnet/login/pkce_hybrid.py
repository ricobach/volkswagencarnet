"""Volkswagen EU PKCE hybrid login.

VW EU currently rejects the CARIAD authorization-code token exchange unless
Play Integrity assertion headers are valid.  The OIDC hybrid flow avoids that
exchange by asking identity.vwgroup.io to return access_token + id_token in the
app callback itself.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp

from ..vw_const import APP_URI, CLIENT_ID, CLIENT_SCOPE
from ..vw_exceptions import (
    LoginCredentialsError,
    LoginError,
    LoginFlowChangedError,
)
from .pkce import (
    AUTHORIZE_URL,
    VWLoginFlow as _PKCELoginFlow,
    _extract_callback_param,
    _pkce_pair,
)


class VWLoginFlow(_PKCELoginFlow):
    """VW EU hybrid OIDC flow using tokens returned by the callback."""

    async def login(
        self,
        username: str,
        password: str,
        *,
        cookies_file: Path | None = None,
    ) -> dict:
        if not username or not password:
            raise LoginCredentialsError("Username and password are required")

        _code_verifier, code_challenge = _pkce_pair()
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
        access_token = _extract_callback_param(callback_url, "access_token")
        id_token = _extract_callback_param(callback_url, "id_token")
        token_type = _extract_callback_param(callback_url, "token_type") or "Bearer"
        expires_in = _extract_callback_param(callback_url, "expires_in")

        if not auth_code:
            raise LoginFlowChangedError(stage="missing_authorization_code")
        if not access_token or not id_token:
            raise LoginError(
                "VW hybrid callback did not contain access_token and id_token"
            )

        payload: dict[str, object] = {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": token_type,
            "auth_strategy": "hybrid_full",
        }
        if expires_in:
            try:
                payload["expires_in"] = int(expires_in)
            except ValueError:
                pass

        return payload

    async def _authorization_page(
        self,
        session: aiohttp.ClientSession,
        *,
        code_challenge: str,
        state: str,
        nonce: str,
    ) -> tuple[str, str]:
        scope = self._client_scope
        if "offline_access" not in scope.split():
            scope = f"{scope} offline_access"

        params = {
            "client_id": self._client_id,
            "scope": scope,
            "response_type": "code id_token token",
            "redirect_uri": APP_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce,
        }

        import logging

        logger = logging.getLogger(__name__)
        logger.debug("GET %s (PKCE hybrid_full authorization)", AUTHORIZE_URL)
        async with session.get(
            AUTHORIZE_URL,
            params=params,
            allow_redirects=False,
        ) as response:
            logger.debug("authorize response: HTTP %s", response.status)
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

            logger.debug(
                "GET auth redirect hop %s: %s", hop + 1, self._safe_url(current)
            )
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
