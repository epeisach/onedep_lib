from __future__ import annotations

import time
from urllib.parse import urljoin

import jwt as pyjwt
import requests

from onedep_lib.config import DepositConfig, _hostname_to_fqdn_key
from onedep_lib.exceptions import AuthError, ConfigError

_REFRESH_PATH = "auth/tokens/refresh"
_EXCHANGE_PATH = "auth/tokens/exchange"
_REVOKE_PATH = "auth/tokens/revoke"


class TokenStore:
    def __init__(self, config: DepositConfig) -> None:
        self._config = config
        self._entries = self._load_auth_entries()
        active_key = self._fqdn_key()
        if self._config.refresh_token is not None:
            entry = {"refresh_token": self._config.refresh_token}
            if self._config.access_token is not None:
                entry["access_token"] = self._config.access_token
            self._entries[active_key] = entry

    def store_tokens(self, access_token: str, refresh_token: str) -> None:
        self._store_tokens_for_key(self._fqdn_key(), access_token, refresh_token)

    def get_access_token(self) -> str:
        entry = self._read_entry()
        token = entry.get("access_token")
        if token is None or self._is_expired(token):
            return self.refresh()
        return token

    def refresh(self) -> str:
        entry = self._read_entry()
        access_token, refresh_token = self._request_refresh(self._config.hostname, entry["refresh_token"])
        self.store_tokens(access_token, refresh_token)
        return access_token

    def activate_site(self, site_base_url: str) -> str:
        key = _hostname_to_fqdn_key(site_base_url)
        if not key:
            raise AuthError(f"Invalid hostname for token storage: {site_base_url!r}")
        self._entries = self._load_auth_entries() | self._entries
        entry = self._entries.get(key)
        if entry is None:
            entry = self._read_entry()
            access_token, refresh_token = self._request_exchange(site_base_url, entry["refresh_token"])
        else:
            access_token, refresh_token = self._request_refresh(site_base_url, entry["refresh_token"])
        self._config.hostname = site_base_url
        self._store_tokens_for_key(key, access_token, refresh_token)
        return access_token

    def revoke(self) -> None:
        entry = self._read_entry()
        access_token = self.get_access_token()
        try:
            response = requests.post(
                self._url(_REVOKE_PATH),
                headers={"Authorization": f"Bearer {access_token}"},
                json={"refresh_token": entry["refresh_token"]},
                verify=self._config.ssl_verify,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AuthError(f"Token revoke failed: {exc}") from exc

        if response.status_code != 204:
            raise AuthError(f"Token revoke failed with status {response.status_code}")
        self.clear_tokens()

    def clear_tokens(self) -> None:
        self._config.access_token = None
        self._config.refresh_token = None
        try:
            key = self._fqdn_key()
            self._config.delete_auth_entry(key)
            self._entries.pop(key, None)
        except ConfigError as exc:
            raise AuthError(str(exc)) from exc

    def _load_auth_entries(self) -> dict[str, dict[str, str]]:
        try:
            raw_entries = self._config.read_auth_entries()
        except ConfigError as exc:
            raise AuthError(str(exc)) from exc
        entries: dict[str, dict[str, str]] = {}
        for key, entry in raw_entries.items():
            access_token = entry.get("access_token")
            refresh_token = entry.get("refresh_token")
            if access_token is not None and not isinstance(access_token, str):
                raise AuthError(f"Malformed token data in [auths.{key}]")
            if refresh_token is not None and not isinstance(refresh_token, str):
                raise AuthError(f"Malformed token data in [auths.{key}]")
            if refresh_token is None:
                continue
            values = {"refresh_token": refresh_token}
            if access_token is not None:
                values["access_token"] = access_token
            entries[key] = values
        return entries

    def _store_tokens_for_key(self, key: str, access_token: str, refresh_token: str) -> None:
        try:
            self._config.write_auth_entry(
                key,
                {"access_token": access_token, "refresh_token": refresh_token},
            )
        except ConfigError as exc:
            raise AuthError(str(exc)) from exc
        self._entries[key] = {"access_token": access_token, "refresh_token": refresh_token}
        self._config.access_token = access_token
        self._config.refresh_token = refresh_token

    def _request_refresh(self, hostname: str, refresh_token: str) -> tuple[str, str]:
        return self._request_token_pair(hostname, _REFRESH_PATH, refresh_token, "refresh")

    def _request_exchange(self, hostname: str, refresh_token: str) -> tuple[str, str]:
        return self._request_token_pair(hostname, _EXCHANGE_PATH, refresh_token, "exchange")

    def _request_token_pair(
        self,
        hostname: str,
        path: str,
        refresh_token: str,
        operation: str,
    ) -> tuple[str, str]:
        try:
            response = requests.post(
                self._url_for(hostname, path),
                json={"refresh_token": refresh_token},
                verify=self._config.ssl_verify,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AuthError(f"Token {operation} failed: {exc}") from exc

        if response.status_code == 401:
            raise AuthError("Refresh token is expired, revoked, or invalid; generate and paste a new token pair.")

        try:
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            raise AuthError(f"Token {operation} failed: {exc}") from exc

        access_token = body.get("access_token")
        refresh_token_out = body.get("refresh_token")
        if not isinstance(access_token, str) or not isinstance(refresh_token_out, str):
            raise AuthError(f"Token {operation} response missing access_token or refresh_token")
        return access_token, refresh_token_out

    def _read_entry(self) -> dict[str, str]:
        key = self._fqdn_key()
        entry = self._entries.get(key)
        config_entry = self._entry_from_config()
        if config_entry is not None and (
            entry is None or config_entry.get("refresh_token") != entry.get("refresh_token")
        ):
            entry = config_entry
            self._entries[key] = entry
        if entry is None:
            access_token = self._config.access_token
            refresh_token = self._config.refresh_token
            if refresh_token is None:
                raise AuthError("No refresh token stored. Paste a refresh token first.")
            entry = {"refresh_token": refresh_token}
            if access_token is not None:
                entry["access_token"] = access_token
            self._entries[key] = entry
        if entry.get("refresh_token") is None:
            raise AuthError("No refresh token stored. Paste a refresh token first.")
        return dict(entry)

    def _entry_from_config(self) -> dict[str, str] | None:
        refresh_token = self._config.refresh_token
        if refresh_token is None:
            return None
        entry = {"refresh_token": refresh_token}
        if self._config.access_token is not None:
            entry["access_token"] = self._config.access_token
        return entry

    def _fqdn_key(self) -> str:
        key = _hostname_to_fqdn_key(self._config.hostname)
        if not key:
            raise AuthError(f"Invalid hostname for token storage: {self._config.hostname!r}")
        return key

    def _url(self, path: str) -> str:
        return self._url_for(self._config.hostname, path)

    def _url_for(self, hostname: str, path: str) -> str:
        base = hostname.rstrip("/") + "/"
        return urljoin(base, path)

    def _is_expired(self, token: str) -> bool:
        try:
            payload = pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["HS256", "RS256", "none"],
            )
            exp = payload.get("exp")
            return not isinstance(exp, int) or exp < time.time() + 60
        except Exception:
            return True
