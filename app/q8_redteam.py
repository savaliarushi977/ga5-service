import ipaddress
import posixpath
import socket
from typing import Any, Literal
from urllib.parse import urljoin

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-dbba8b5d6b"
ALLOWED_FETCH_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECT_HOPS = 5


def resolve_read_path(raw: str) -> str:
    path = raw
    if not path.startswith("/"):
        path = SANDBOX_ROOT.rstrip("/") + "/" + path
    return posixpath.normpath(path)


def is_ip_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def extract_safe_host(url: str) -> str | None:
    """Parse a URL using httpx's OWN parser - the same one that will actually
    perform the request - rather than the stdlib's urlsplit. Using a different
    parser to validate than the one that executes the fetch is a classic
    bypass class: two parsers can disagree on a malformed/edge-case URL (e.g.
    stdlib urlsplit silently strips control characters like tabs from a
    hostname where httpx's parser does not), letting something validate as
    the allowed host while the actual connection goes elsewhere - or crashes
    unhandled, which is just as bad as an allow if it skips the block path.
    Also rejects non-http(s) schemes, embedded userinfo, and non-default
    ports. Any parsing failure fails CLOSED (returns None -> blocked)."""
    try:
        parsed = httpx.URL(url)
    except Exception:
        return None
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return None
    if parsed.username or parsed.password:
        return None
    hostname = parsed.host
    if not hostname:
        return None
    hostname = hostname.rstrip(".")  # a trailing dot denotes an FQDN, same host
    if not hostname:
        return None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if parsed.port is not None and parsed.port != default_port:
        return None
    try:
        hostname.encode("idna")
    except UnicodeError:
        return None
    return hostname


def is_host_allowed(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.lower().rstrip(".")
    if normalized not in ALLOWED_FETCH_HOSTS:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    return all(is_ip_allowed(info[4][0]) for info in infos)


def guarded_fetch(url: str) -> httpx.Response | None:
    current = url
    try:
        for _ in range(MAX_REDIRECT_HOPS):
            host = extract_safe_host(current)
            if not is_host_allowed(host):
                return None
            resp = httpx.get(current, follow_redirects=False, timeout=10)
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    return resp
                current = urljoin(current, location)
                continue
            return resp
    except Exception:
        return None  # any fetch/parsing error fails closed, never a raw 500
    return None


class Decision(BaseModel):
    action: Literal["allow", "block"]
    reason: str
    result: Any = None


@router.post("/q8/check", response_model=Decision)
def check(payload: dict):
    try:
        return _check_impl(payload)
    except Exception:
        # Any unexpected internal error must never surface as a raw 500 - a
        # crash here is just as bad as an allow if it skips the block path.
        return Decision(action="block", reason="Internal error while evaluating this request.")


def _check_impl(payload: dict):
    tool = payload.get("tool")
    args = payload.get("arguments", {})

    if tool == "read_file":
        raw_path = args.get("path", "")
        resolved = resolve_read_path(raw_path)
        if resolved != SANDBOX_ROOT and not resolved.startswith(SANDBOX_ROOT + "/"):
            return Decision(action="block", reason="Path resolves outside the allowed sandbox root.")
        try:
            with open(resolved, "r") as f:
                content = f.read()
        except OSError as e:
            return Decision(action="block", reason=f"File could not be read: {e}")
        return Decision(action="allow", reason="Path is inside the allowed sandbox root.", result={"content": content})

    if tool == "fetch_url":
        url = args.get("url", "")
        host = extract_safe_host(url)
        if not is_host_allowed(host):
            return Decision(action="block", reason="Host is not on the exact allowlist, or resolves to a disallowed IP range.")
        resp = guarded_fetch(url)
        if resp is None:
            return Decision(action="block", reason="Request or a redirect in its chain targeted a disallowed host.")
        return Decision(
            action="allow",
            reason="Host (and any redirect chain) resolved to allowed public hosts only.",
            result={"content": resp.text, "status_code": resp.status_code},
        )

    return Decision(action="block", reason="Unknown or malformed tool call.")
