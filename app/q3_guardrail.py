import base64
import posixpath
import re
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET_PATH = "/home/agent/.secrets"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com"}
EXTRA_BLOCKED_PATHS = {"/etc/shadow"}

SEGMENT_SPLIT_RE = re.compile(r"[;&|]{1,2}|`|\$\(|\)")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def resolve_path(raw: str, cwd: str) -> str:
    path = raw.strip().strip("'\"")
    path = path.replace("${HOME}", HOME).replace("$HOME", HOME)
    if path == "~" or path.startswith("~/"):
        path = HOME + path[1:]
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    return posixpath.normpath(path)


def try_base64_decode_all(text: str) -> list[str]:
    decoded = []
    for match in BASE64_RE.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=True)
            txt = raw.decode("utf-8")
            if txt.isprintable() or "\n" in txt:
                decoded.append(txt)
        except Exception:
            continue
    return decoded


def command_reads_secret(command: str) -> bool:
    texts = [command] + try_base64_decode_all(command)
    for text in texts:
        substituted = text.replace("${HOME}", HOME).replace("$HOME", HOME)
        if SECRET_PATH in substituted or ".secrets" in substituted:
            # confirm it's actually a path reference, not incidental prose
            if re.search(r"(^|[\s'\"/.~])\.secrets(\b|$)", substituted) or SECRET_PATH in substituted:
                return True

        cwd = WORKSPACE
        segments = SEGMENT_SPLIT_RE.split(substituted)
        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue
            cd_match = re.match(r"cd\s+(\S+)", seg)
            if cd_match:
                cwd = resolve_path(cd_match.group(1), cwd)
                continue
            for token in seg.split():
                token = token.strip("'\"")
                if not token or token.startswith("-"):
                    continue
                if "/" in token or token.startswith(".") or token.startswith("~") or "$" in token:
                    resolved = resolve_path(token, cwd)
                    if resolved == SECRET_PATH or resolved in EXTRA_BLOCKED_PATHS:
                        return True
    return False


def command_uses_sudo(command: str) -> bool:
    texts = [command] + try_base64_decode_all(command)
    return any(re.search(r"(^|[\s;&|`])sudo(\s|$)", t) for t in texts)


class BashCall(BaseModel):
    tool: Literal["bash"]
    command: str


class WriteFileCall(BaseModel):
    tool: Literal["write_file"]
    path: str
    content: str = ""


class HttpRequestCall(BaseModel):
    tool: Literal["http_request"]
    method: Literal["GET", "POST"]
    url: str


class Decision(BaseModel):
    decision: Literal["allow", "block"]
    reason: str


@router.post("/q3/check", response_model=Decision)
def check(payload: dict):
    tool = payload.get("tool")

    if tool == "bash":
        call = BashCall(**payload)
        if command_uses_sudo(call.command):
            return Decision(decision="block", reason="sudo / privilege escalation is never permitted by this agent's policy.")
        if command_reads_secret(call.command):
            return Decision(decision="block", reason="This command reads the restricted secrets path, directly or via an obfuscated reference.")
        return Decision(decision="allow", reason="No restricted-path read or privilege escalation detected in this command.")

    if tool == "write_file":
        call = WriteFileCall(**payload)
        resolved = resolve_path(call.path, WORKSPACE)
        if resolved == WRITE_ROOT or resolved.startswith(WRITE_ROOT + "/"):
            return Decision(decision="allow", reason="Write target is inside the allowed /srv/reports/ directory.")
        return Decision(decision="block", reason="Write target is outside the allowed /srv/reports/ directory.")

    if tool == "http_request":
        call = HttpRequestCall(**payload)
        host = (urlparse(call.url).hostname or "").lower().rstrip(".")
        if host in ALLOWED_HOSTS:
            return Decision(decision="allow", reason="Host is on the exact outbound allowlist.")
        return Decision(decision="block", reason="Host is not exactly one of the allowed hosts.")

    return Decision(decision="block", reason="Unknown or malformed tool call.")
