"""One-request JSON subprocess interface; no access to legacy module state."""
from __future__ import annotations
from pathlib import Path
import json
import sys
from .discovery import discover

MAX_REQUEST_BYTES = 8192


def handle(request: object) -> dict:
    if not isinstance(request, dict) or set(request) != {"api_version", "operation", "arguments"}:
        return {"api_version": 1, "ok": False, "error": "INVALID_ENVELOPE"}
    if type(request["api_version"]) is not int or request["api_version"] != 1:
        return {"api_version": 1, "ok": False, "error": "UNSUPPORTED_VERSION"}
    args = request["arguments"]
    if request["operation"] != "hardware.discover" or not isinstance(args, dict) or set(args) != {"disk_path"}:
        return {"api_version": 1, "ok": False, "error": "UNSUPPORTED_OPERATION"}
    if not isinstance(args["disk_path"], str) or not Path(args["disk_path"]).is_absolute():
        return {"api_version": 1, "ok": False, "error": "ABSOLUTE_DESTINATION_REQUIRED"}
    return {"api_version": 1, "ok": True, "result": discover(Path(args["disk_path"]))}


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    try:
        result = handle(json.loads(raw)) if len(raw) <= MAX_REQUEST_BYTES else {
            "api_version": 1, "ok": False, "error": "REQUEST_TOO_LARGE"}
    except (ValueError, TypeError):
        result = {"api_version": 1, "ok": False, "error": "INVALID_JSON"}
    except Exception:
        # Do not include paths, provider values, subprocess output or traceback in protocol errors.
        result = {"api_version": 1, "ok": False, "error": "DISCOVERY_FAILED"}
    print(json.dumps(result, allow_nan=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
