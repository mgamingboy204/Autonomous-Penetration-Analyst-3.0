#!/usr/bin/env python3
"""Metasploit MessagePack RPC client with scheme probing and clear diagnostics."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

try:
    import msgpack
except ImportError:  # pragma: no cover - runtime dependency
    msgpack = None


class RpcClientError(RuntimeError):
    """Base RPC client error."""


class RpcAuthError(RpcClientError):
    """Authentication failure."""


class RpcTransportError(RpcClientError):
    """Transport/scheme/connection failure."""


class RpcDecodeError(RpcClientError):
    """RPC payload decode failure."""


@dataclass
class ProbeResult:
    scheme: str
    base_url: str
    token: str
    decoded_login_response: dict[str, Any]


class MsfRpcClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        ssl_pref: bool | None,
        *,
        connect_timeout_s: float = 2.0,
        read_timeout_s: float = 5.0,
    ) -> None:
        if msgpack is None:
            raise RpcClientError("msgpack is required for Metasploit RPC integration. Install with: pip install msgpack")
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.ssl_pref = ssl_pref
        self.connect_timeout_s = connect_timeout_s
        self.read_timeout_s = read_timeout_s
        self.endpoint = "/api/"
        self.scheme: str | None = None
        self.base_url: str | None = None
        self.token: str | None = None
        self.debug_attempts: list[dict[str, Any]] = []

    def _build_url(self, scheme: str) -> str:
        return f"{scheme}://{self.host}:{self.port}{self.endpoint}"

    def _decode_body(self, body: bytes, content_type: str) -> dict[str, Any]:
        lowered = (content_type or "").lower()
        try:
            if "binary/message-pack" in lowered or "application/msgpack" in lowered:
                decoded = msgpack.unpackb(body, raw=False)
                return decoded if isinstance(decoded, dict) else {"result": decoded}
            if "application/json" in lowered or "text/json" in lowered:
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                return parsed if isinstance(parsed, dict) else {"result": parsed}

            try:
                decoded = msgpack.unpackb(body, raw=False)
                return decoded if isinstance(decoded, dict) else {"result": decoded}
            except Exception:
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                return parsed if isinstance(parsed, dict) else {"result": parsed}
        except Exception as exc:
            raise RpcDecodeError(
                "RPC responded but payload decode failed (likely JSON/msgpack mismatch)."
            ) from exc

    def _classify_transport_error(self, exc: Exception, scheme: str) -> str:
        if isinstance(exc, ssl.SSLError):
            return "wrong scheme or SSL disabled"
        if isinstance(exc, TimeoutError | socket.timeout):
            return "wrong scheme or SSL disabled"
        if isinstance(exc, ConnectionResetError):
            return "likely wrong scheme (HTTP vs HTTPS)"
        if isinstance(exc, urllib.error.URLError):
            reason = exc.reason
            if isinstance(reason, ssl.SSLError):
                return "wrong scheme or SSL disabled"
            if isinstance(reason, TimeoutError | socket.timeout):
                return "wrong scheme or SSL disabled"
            if isinstance(reason, ConnectionResetError):
                return "likely wrong scheme (HTTP vs HTTPS)"
            if isinstance(reason, OSError) and "reset" in str(reason).lower():
                return "likely wrong scheme (HTTP vs HTTPS)"
        return f"transport error on {scheme}"

    def _post(self, scheme: str, method: str, args: list[Any]) -> dict[str, Any]:
        payload = msgpack.packb([method, *args], use_bin_type=True)
        request = urllib.request.Request(
            self._build_url(scheme),
            data=payload,
            method="POST",
            headers={"Content-Type": "binary/message-pack", "Accept": "*/*"},
        )
        context = ssl._create_unverified_context() if scheme == "https" else None

        try:
            with urllib.request.urlopen(request, timeout=self.read_timeout_s, context=context) as response:
                body = response.read()
                content_type = str(response.headers.get("Content-Type") or "")
                decoded = self._decode_body(body, content_type)
                return {
                    "ok": True,
                    "status": int(getattr(response, "status", 200)),
                    "decoded": decoded,
                    "content_type": content_type,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read() if hasattr(exc, "read") else b""
            content_type = str(exc.headers.get("Content-Type") or "") if getattr(exc, "headers", None) else ""
            decoded: dict[str, Any] | None = None
            decode_error: str | None = None
            if body:
                try:
                    decoded = self._decode_body(body, content_type)
                except RpcDecodeError as decode_exc:
                    decode_error = str(decode_exc)
            return {
                "ok": False,
                "status": int(getattr(exc, "code", 0) or 0),
                "decoded": decoded,
                "raw": body.decode("utf-8", errors="replace")[:300],
                "decode_error": decode_error,
                "transport_error": None,
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": None,
                "decoded": None,
                "raw": "",
                "decode_error": None,
                "transport_error": self._classify_transport_error(exc, scheme),
                "exception": f"{type(exc).__name__}: {exc}",
            }

    def probe_and_login(self) -> ProbeResult:
        if self.ssl_pref is True:
            schemes = ["https"]
        elif self.ssl_pref is False:
            schemes = ["http"]
        else:
            schemes = ["https", "http"]

        attempts: list[dict[str, Any]] = []

        for scheme in schemes:
            response = self._post(scheme, "auth.login", [self.username, self.password])
            attempt = {"scheme": scheme, "endpoint": self.endpoint, **response}
            attempts.append(attempt)
            self.debug_attempts = attempts

            if response["ok"]:
                decoded = response["decoded"] or {}
                if decoded.get("error") == "Invalid Message Format":
                    raise RpcClientError("your request format is wrong")
                if decoded.get("result") == "success" and decoded.get("token"):
                    self.scheme = scheme
                    self.base_url = self._build_url(scheme)
                    self.token = str(decoded["token"])
                    return ProbeResult(
                        scheme=scheme,
                        base_url=self.base_url,
                        token=self.token,
                        decoded_login_response=decoded,
                    )
                if decoded.get("error") == "Login failed" or response.get("status") in {401, 403}:
                    raise RpcAuthError(f"auth failed: {decoded}")
                raise RpcClientError(f"unexpected login response: {decoded}")

            if response.get("transport_error"):
                if self.ssl_pref is None and scheme == "https":
                    continue
                if self.ssl_pref is None and scheme == "http" and "wrong scheme" in response["transport_error"]:
                    continue
                raise RpcTransportError(
                    f"{response['transport_error']}; details={response.get('exception', 'n/a')}"
                )

            status = response.get("status")
            decoded = response.get("decoded") or {}
            if decoded.get("error") == "Invalid Message Format":
                raise RpcClientError("your request format is wrong")
            if status in {401, 403} or decoded.get("error") == "Login failed":
                raise RpcAuthError(f"auth failed: status={status}, response={decoded}")
            raise RpcClientError(f"rpc error: status={status}, response={decoded}, raw={response.get('raw')}")

        raise RpcTransportError(f"Unable to connect using probed schemes; attempts={attempts}")

    def call(self, method: str, *args: Any, token: str | None = None) -> dict[str, Any]:
        if not self.scheme:
            raise RpcClientError("call() requires probe_and_login() first")
        call_args = [token or self.token, *args] if (token or self.token) else list(args)
        response = self._post(self.scheme, method, call_args)

        if response.get("transport_error"):
            raise RpcTransportError(
                f"{response['transport_error']}; details={response.get('exception', 'n/a')}"
            )

        if not response["ok"]:
            decoded = response.get("decoded") or {}
            if response.get("status") in {401, 403} or decoded.get("error") == "Login failed":
                raise RpcAuthError(f"auth failed: status={response.get('status')}, response={decoded}")
            if decoded.get("error") == "Invalid Message Format":
                raise RpcClientError("your request format is wrong")
            raise RpcClientError(
                f"rpc call failed: status={response.get('status')}, response={decoded}, raw={response.get('raw')}"
            )

        decoded = response.get("decoded") or {}
        if decoded.get("error") == "Invalid Message Format":
            raise RpcClientError("your request format is wrong")
        return decoded
