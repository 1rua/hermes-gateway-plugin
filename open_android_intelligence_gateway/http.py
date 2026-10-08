"""Hermes HTTP exposure boundary for Gateway Protocol v2."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .admin import (
    HERMES_HOST_API,
    HostApiCompatibility,
    is_host_api_compatible,
    normalize_host_api,
)
from .core import (
    WIRE_PROTOCOL, GatewayCore, GatewayError, VerifiedGatewayRequest,
    create_gateway_core,
)


EXPOSURE_MODES = ("host-route", "loopback-reverse-proxy", "direct-tls")
# JSON/control requests stay bounded in memory. Binary attachment bodies use a
# separate streaming ingress path and are not constrained by this JSON limit.
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_RESPONSE_HEADERS = {"content-type": "application/json; charset=utf-8"}


def _get(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return default


_PRE_AUTH_TARGETS = (
    "/open-android-intelligence/v2/negotiate",
    "/open-android-intelligence/v2/sessions/invite/challenge",
    "/open-android-intelligence/v2/sessions/invite/exchange","/open-android-intelligence/v2/pairings/exchange","/open-android-intelligence/v2/sessions/device/challenge","/open-android-intelligence/v2/sessions/device",
    "/open-android-intelligence/v2/sessions/password",
    "/open-android-intelligence/v2/sessions/refresh",
    "/open-android-intelligence/v2/sessions/current",
)

_AUTHENTICATION_FAILURE_CODES = {
    "AUTHENTICATION_REQUIRED", "AUTHENTICATION_FAILED", "REFRESH_REUSED",
}


def _is_pre_auth(verified: Any) -> bool:
    """The endpoints that legitimately arrive without a verified context."""
    if _get(verified, "context") is not None:
        return False
    method = _get(verified, "method")
    target = _get(verified, "target")
    path = target.partition("?")[0] if isinstance(target, str) else ""
    if path not in _PRE_AUTH_TARGETS:
        return False
    return method == "DELETE" if path == "/open-android-intelligence/v2/sessions/current" else method == "POST"


def _account_exists(core: Any, account_id: Any) -> bool:
    """Whether the named account was registered on this host.

    Fails closed: an unknown account is never created by logging in, and a
    core that cannot answer the question cannot authenticate anyone.
    """
    if not isinstance(account_id, str) or not account_id:
        return False
    for name in ("account_exists", "has_gateway_account", "hasGatewayAccount"):
        checker = getattr(core, name, None)
        if callable(checker):
            try:
                return bool(checker(account_id))
            except Exception:
                return False
    return False


def _identity(request: Any) -> tuple[str, str]:
    verified = _get(request, "verifiedRequest", "verified_request")
    context = _get(verified, "context", default={})
    return (
        str(_get(context, "requestId", "request_id", default="open-android-intelligence-route")),
        str(_get(context, "correlationId", "correlation_id", default="open-android-intelligence-route")),
    )


def _failure(request: Any, code: str, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    request_id, correlation_id = _identity(request)
    return {
        "requestId": request_id, "correlationId": correlation_id, "protocol": WIRE_PROTOCOL,
        "error": {
            "code": code, "message": code,
            "retryable": code == "ATTACHMENT_STORAGE_UNAVAILABLE",
            "retryAfterSeconds": None, "details": dict(details or {}),
        },
    }


# Wire error code to HTTP status. Codes absent from this map are caller errors
# and answer 400, which is the contract's default for malformed input.
_ERROR_STATUS = {
    "HOST_INCOMPATIBLE": 503,
    "ATTACHMENT_STORAGE_UNAVAILABLE": 503,
    "AUTHENTICATION_REQUIRED": 401,
    "AUTHENTICATION_FAILED": 401,
    "REFRESH_REUSED": 401,
    "SESSION_EXPIRED": 401,
    "SESSION_REVOKED": 401,
    "SIGNATURE_INVALID": 401,
    "NON_CANONICAL_TARGET": 401,
    "REQUEST_REPLAYED": 401,
    "CLOCK_SKEWED": 401,
    "ACCOUNT_NOT_FOUND": 404,
    "PROTOCOL_INCOMPATIBLE": 406,
    "IDEMPOTENCY_CONFLICT": 409,
    "CURSOR_CONFLICT": 409,
    "CURSOR_EXPIRED": 410,
    "APPROVAL_NOT_FOUND": 404,
    "APPROVAL_EXPIRED": 409,
    "APPROVAL_ALREADY_RESOLVED": 409,
    "REQUEST_BODY_TOO_LARGE": 413,
    "RATE_LIMITED": 429,
}


def _status(body: Mapping[str, Any]) -> int:
    code = _get(_get(body, "error", default={}), "code")
    if code in _ERROR_STATUS:
        return _ERROR_STATUS[str(code)]
    return 400 if "error" in body else 200


@dataclass(frozen=True)
class ExposureAdmin:
    local_only: bool = True
    remote_port: None = None

    @property
    def localOnly(self) -> bool:
        return self.local_only

    @property
    def remotePort(self) -> None:
        return self.remote_port


class GatewayHttpRoute:
    def __init__(self, path: str, match: str, services: "_RouteServices"):
        self.path = path
        self.match = match
        self.auth = "plugin"
        self._services = services

    def handle(self, request: Any) -> dict[str, Any]:
        if not is_host_api_compatible(self._services.host_version, self._services.host_api):
            return {"statusCode": 503, "headers": dict(_RESPONSE_HEADERS), "body": _failure(request, "HOST_INCOMPATIBLE", {
                "hostVersion": self._services.host_version,
                "minVersion": self._services.host_api.min_version,
                "maxVersion": self._services.host_api.max_version,
                "verifiedCommit": self._services.host_api.verified_commit,
            })}
        verified = _get(request, "verifiedRequest", "verified_request")
        if verified is None:
            context = _get(request, "context")
            method = _get(request, "method")
            target = _get(request, "target", default=self.path)
            if context is None and method == "POST" and target == "/open-android-intelligence/v2/negotiate":
                # The negotiation body is validated exactly as the client sent it:
                # a request that omits or falsifies its schema hash is refused by
                # the contract check instead of being repaired at the boundary.
                verified = {
                    "method": method,
                    "target": target,
                    "body": _get(request, "body"),
                    "requestId": _get(request, "requestId", "request_id", default="open-android-intelligence-negotiate"),
                    "correlationId": _get(request, "correlationId", "correlation_id", default="open-android-intelligence-negotiate"),
                }
            elif context is None and method == "POST" and target in {"/open-android-intelligence/v2/sessions/password","/open-android-intelligence/v2/sessions/invite/challenge","/open-android-intelligence/v2/sessions/invite/exchange","/open-android-intelligence/v2/pairings/exchange","/open-android-intelligence/v2/sessions/device/challenge","/open-android-intelligence/v2/sessions/device"}:
                verified = {
                    "method": method,
                    "target": target,
                    "body": _get(request, "body"),
                    "remoteAddress": _get(request, "remoteAddress", "remote_address"),
                    "requestId": _get(request, "requestId", "request_id", default="open-android-intelligence-session"),
                    "correlationId": _get(request, "correlationId", "correlation_id", default="open-android-intelligence-session"),
                }
            elif context is None and target is not None and (
                (method == "POST" and target == "/open-android-intelligence/v2/sessions/refresh")
                or (method == "DELETE" and target.partition("?")[0] == "/open-android-intelligence/v2/sessions/current")
            ):
                verified = {
                    "method": method,
                    "target": target,
                    "body": _get(request, "body"),
                    "headers": dict(_get(request, "headers", default={}) or {}),
                    "requestId": _get(request, "requestId", "request_id", default="open-android-intelligence-session"),
                    "correlationId": _get(request, "correlationId", "correlation_id", default="open-android-intelligence-session"),
                }
            elif context is None or method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(request, "AUTHENTICATION_REQUIRED")}
            else:
                verified = {
                    "context": context, "method": method,
                    "target": target,
                    **({"body": _get(request, "body")} if _get(request, "body") is not None else {}),
                    **({"idempotencyKey": _get(request, "idempotencyKey", "idempotency_key")} if _get(request, "idempotencyKey", "idempotency_key") is not None else {}),
                    **({"lastEventId": _get(request, "lastEventId", "last_event_id")} if _get(request, "lastEventId", "last_event_id") is not None else {}),
                    **({"now": _get(request, "now")} if _get(request, "now") is not None else {}),
                }
        if not isinstance(verified, VerifiedGatewayRequest):
            if not _is_pre_auth(verified):
                return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(request, "AUTHENTICATION_REQUIRED")}
        body = self._services.core.handle(verified)
        status = _status(body)
        if _get(_get(body, "error", default={}), "code") in _AUTHENTICATION_FAILURE_CODES:
            status = 401
        return {"statusCode": status, "headers": dict(_RESPONSE_HEADERS), "body": body}

    def event_backlog(self, request: Any) -> dict[str, Any]:
        """Contract section 9 SSE handshake: verify the request, then read events.

        Authentication and cursor validity are decided here and only here, so a
        streaming transport never has to make a security decision of its own.
        A failure return carries the same envelope any other route would send;
        a success return names the verified account and the events to replay.
        """
        empty: dict[str, Any] = {}
        if not is_host_api_compatible(self._services.host_version, self._services.host_api):
            return {
                "statusCode": 503, "headers": dict(_RESPONSE_HEADERS),
                "body": _failure(empty, "HOST_INCOMPATIBLE"),
            }
        method = _get(request, "method")
        target = _get(request, "url", "target")
        verifier = self._services.verify_request
        if method != "GET" or not isinstance(target, str) or not target.startswith("/") or verifier is None:
            return {
                "statusCode": 401, "headers": dict(_RESPONSE_HEADERS),
                "body": _failure(empty, "AUTHENTICATION_REQUIRED"),
            }
        try:
            verified = verifier({
                "request": request, "req": request, "method": method, "target": target,
                "headers": dict(_get(request, "headers", default={}) or {}),
                "rawHeaders": tuple(_get(request, "rawHeaders", "raw_headers", default=()) or ()),
                "body": _raw_body(request),
            })
        except Exception:
            verified = None
        if not isinstance(verified, VerifiedGatewayRequest):
            return {
                "statusCode": 401, "headers": dict(_RESPONSE_HEADERS),
                "body": _failure(empty, "AUTHENTICATION_REQUIRED"),
            }
        body = self._services.core.handle(verified)
        status = _status(body)
        if status != 200:
            return {"statusCode": status, "headers": dict(_RESPONSE_HEADERS), "body": body}
        events = _get(_get(body, "data", default={}), "events", default=[]) or []
        return {
            "statusCode": 200, "headers": dict(_RESPONSE_HEADERS), "body": body,
            "accountId": str(verified.context.accountId), "events": list(events),
            "verifiedContext": verified.context,
        }

    def failure_response(
        self, request_id: str | None, correlation_id: str | None, code: str,
    ) -> dict[str, Any]:
        request = {
            "verifiedRequest": {"context": {
                "requestId": request_id or "open-android-intelligence-route",
                "correlationId": correlation_id or request_id or "open-android-intelligence-route",
            }},
        }
        body = _failure(request, code)
        return {"statusCode": _status(body), "headers": dict(_RESPONSE_HEADERS), "body": body}

    def handle_verified_request(self, verified: VerifiedGatewayRequest) -> dict[str, Any]:
        """Dispatch a fully verified request through the same Core seam as HTTP."""
        if not isinstance(verified, VerifiedGatewayRequest):
            return self.failure_response(None, None, "AUTHENTICATION_REQUIRED")
        if not is_host_api_compatible(self._services.host_version, self._services.host_api):
            body = _failure(verified, "HOST_INCOMPATIBLE", {
                "hostVersion": self._services.host_version,
                "minVersion": self._services.host_api.min_version,
                "maxVersion": self._services.host_api.max_version,
                "verifiedCommit": self._services.host_api.verified_commit,
            })
            return {"statusCode": 503, "headers": dict(_RESPONSE_HEADERS), "body": body}
        body = self._services.core.handle(verified)
        return {"statusCode": _status(body), "headers": dict(_RESPONSE_HEADERS), "body": body}

    def handler(self, request: Any, response: Any) -> bool:
        result = self._handle_raw(request)
        _set_response(response, result["statusCode"], result["headers"], result["body"])
        return True

    def _handle_raw(self, request: Any) -> dict[str, Any]:
        empty: dict[str, Any] = {}
        if not is_host_api_compatible(self._services.host_version, self._services.host_api):
            return {"statusCode": 503, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "HOST_INCOMPATIBLE")}
        method = _get(request, "method")
        target = _get(request, "url", "target")
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"} or not isinstance(target, str) or not target.startswith("/"):
            return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "AUTHENTICATION_REQUIRED")}
        body = _raw_body(request)
        if body is None:
            return {"statusCode": 400, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "REQUEST_BODY_INVALID")}
        if len(body) > self._services.max_body_bytes:
            return {"statusCode": 413, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "REQUEST_BODY_TOO_LARGE")}
        if method == "POST" and target == "/open-android-intelligence/v2/negotiate":
            try:
                decoded = _strict_json(body)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return {"statusCode": 400, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "SCHEMA_INVALID")}
            response_body = self._services.core.handle({
                "method": method,
                "target": target,
                "body": decoded,
                "requestId": str(_get(request, "requestId", "request_id", default="open-android-intelligence-negotiate")),
                "correlationId": str(_get(request, "correlationId", "correlation_id", default="open-android-intelligence-negotiate")),
            })
            return {"statusCode": _status(response_body), "headers": dict(_RESPONSE_HEADERS), "body": response_body}
        if method == "POST" and target in {"/open-android-intelligence/v2/sessions/password","/open-android-intelligence/v2/sessions/invite/challenge","/open-android-intelligence/v2/sessions/invite/exchange","/open-android-intelligence/v2/pairings/exchange","/open-android-intelligence/v2/sessions/device/challenge","/open-android-intelligence/v2/sessions/device"}:
            try:
                decoded = _strict_json(body)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return {"statusCode": 400, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "SCHEMA_INVALID")}
            response_body = self._services.core.handle({
                "method": method, "target": target, "body": decoded,
                "remoteAddress": _get(request, "remoteAddress", "remote_address"),
                "requestId": str(_get(request, "requestId", "request_id", default="session-password")),
                "correlationId": str(_get(request, "correlationId", "correlation_id", default="session-password")),
            })
            return {"statusCode": _status(response_body), "headers": dict(_RESPONSE_HEADERS), "body": response_body}
        session_target = target.partition("?")[0] if isinstance(target, str) else target
        if session_target in {"/open-android-intelligence/v2/sessions/refresh", "/open-android-intelligence/v2/sessions/current"}:
            if method != ("POST" if session_target.endswith("refresh") else "DELETE"):
                return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "AUTHENTICATION_REQUIRED")}
            if session_target.endswith("refresh"):
                try:
                    decoded = _strict_json(body)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                    return {"statusCode": 400, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "SCHEMA_INVALID")}
            else:
                decoded = None
            session_body = self._services.core.handle({
                "method": method,
                "target": target,
                "body": decoded,
                "headers": dict(_get(request, "headers", default={}) or {}),
                "requestId": str(_get(request, "requestId", "request_id", default="open-android-intelligence-session")),
                "correlationId": str(_get(request, "correlationId", "correlation_id", default="open-android-intelligence-session")),
            })
            status = _status(session_body)
            code = _get(_get(session_body, "error", default={}), "code")
            if code in _AUTHENTICATION_FAILURE_CODES:
                status = 401
            return {"statusCode": status, "headers": dict(_RESPONSE_HEADERS), "body": session_body}
        verifier = self._services.verify_request
        if verifier is None:
            return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "AUTHENTICATION_REQUIRED")}
        try:
            verified = verifier({
                "request": request, "req": request, "method": method, "target": target,
                "headers": dict(_get(request, "headers", default={}) or {}),
                "rawHeaders": tuple(_get(request, "rawHeaders", "raw_headers", default=()) or ()),
                "body": body,
            })
        except Exception:
            verified = None
        if verified is None:
            return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "AUTHENTICATION_REQUIRED")}
        if not isinstance(verified, VerifiedGatewayRequest):
            return {"statusCode": 401, "headers": dict(_RESPONSE_HEADERS), "body": _failure(empty, "AUTHENTICATION_REQUIRED")}
        return self.handle_verified_request(verified)


@dataclass(frozen=True)
class _RouteServices:
    core: Any
    host_version: str | None
    host_api: HostApiCompatibility
    verify_request: Callable[[Mapping[str, Any]], Any] | None
    max_body_bytes: int


def _raw_body(request: Any) -> bytes | None:
    body = _get(request, "body")
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    return None


def _strict_json(body: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(body.decode("utf-8"), object_pairs_hook=pairs)


def _set_response(response: Any, status: int, headers: Mapping[str, str], body: Mapping[str, Any]) -> None:
    if hasattr(type(response), "status_code") or hasattr(response, "status_code"):
        try:
            response.status_code = status
        except Exception:
            pass
    try:
        response.statusCode = status
    except Exception:
        pass
    setter = _get(response, "set_header", "setHeader")
    if callable(setter):
        for name, value in headers.items():
            setter(name, value)
    end = _get(response, "end")
    if callable(end):
        end(json.dumps(body, ensure_ascii=False, separators=(",", ":")))


def create_gateway_routes(
    core: Any, host_version: str | None = None,
    host_api: HostApiCompatibility | Mapping[str, Any] | None = None,
    verify_request: Callable[[Mapping[str, Any]], Any] | None = None,
    max_body_bytes: int | None = None,
) -> list[GatewayHttpRoute]:
    effective_body_limit = (
        DEFAULT_MAX_BODY_BYTES if max_body_bytes is None or max_body_bytes < 0
        else int(max_body_bytes)
    )
    services = _RouteServices(
        core=core, host_version=host_version, host_api=normalize_host_api(host_api),
        verify_request=verify_request,
        max_body_bytes=effective_body_limit,
    )
    definitions = (
        ("/open-android-intelligence/v2/negotiate", "exact"),
        ("/open-android-intelligence/v2/sessions/invite/challenge", "exact"),
        ("/open-android-intelligence/v2/sessions/invite/exchange", "exact"),
        ("/open-android-intelligence/v2/pairings/exchange", "exact"),
        ("/open-android-intelligence/v2/sessions/device/challenge", "exact"),
        ("/open-android-intelligence/v2/sessions/device", "exact"),
        ("/open-android-intelligence/v2/sessions/password", "exact"),
        ("/open-android-intelligence/v2/sessions/refresh", "exact"),
        ("/open-android-intelligence/v2/sessions/current", "exact"),
        # Contract §5.6 / Wave 0 decision D1: unpairing is its own management
        # endpoint and is fully signed — it never joins the pre-auth exemptions
        # that let `sessions/current` arrive without a verified context.
        ("/open-android-intelligence/v2/pairings/current", "exact"),
        ("/open-android-intelligence/v2/pairings/current/", "prefix"),
        ("/open-android-intelligence/v2/sync/snapshot", "exact"),
        ("/open-android-intelligence/v2/commands", "exact"),
        ("/open-android-intelligence/v2/events", "exact"),
        ("/open-android-intelligence/v2/conversations", "exact"), ("/open-android-intelligence/v2/conversations/", "prefix"),
        ("/open-android-intelligence/v2/attachments", "exact"), ("/open-android-intelligence/v2/attachments/", "prefix"),
        ("/open-android-intelligence/v2/device-requests/", "prefix"),
        # Contract §7.2: one decision per approval. The id is in the path, so the
        # route matches by prefix and the core validates the exact shape.
        ("/open-android-intelligence/v2/approvals/", "prefix"),
    )
    return [GatewayHttpRoute(path, match, services) for path, match in definitions]


class GatewayExposure:
    def __init__(self, mode: str, routes: list[GatewayHttpRoute], listener: Mapping[str, Any]):
        self.mode = mode
        self.routes = routes
        self.listener = dict(listener)
        self.admin = ExposureAdmin()


def create_gateway_exposure(
    mode: str, core: Any | None = None, storage_root: str | Path | None = None,
    host_version: str | None = None, host_api: HostApiCompatibility | Mapping[str, Any] | None = None,
    verify_request: Callable[[Mapping[str, Any]], Any] | None = None,
    max_body_bytes: int | None = None,
) -> GatewayExposure:
    if mode not in EXPOSURE_MODES:
        raise ValueError("SCHEMA_INVALID")
    active_core = core or create_gateway_core(storage_root)
    routes = create_gateway_routes(active_core, host_version, host_api, verify_request, max_body_bytes)
    listener = {
        "mode": mode,
        "protocol": "https",
        "network": "host-route" if mode == "host-route" else "loopback",
        "tlsTerminator": "host" if mode == "host-route" else ("reverse-proxy" if mode == "loopback-reverse-proxy" else "explicit-certificate"),
    }
    return GatewayExposure(mode, routes, listener)


# Host-adapter naming aliases.
createGatewayExposure = create_gateway_exposure
createGatewayRoutes = create_gateway_routes
isHostApiCompatible = is_host_api_compatible
