import re
from pathlib import Path
from urllib.parse import urlsplit

from .security import Denied, origin

NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")


def only(obj, allowed, required=()):
    if not isinstance(obj, dict) or set(obj) - set(allowed) or set(required) - set(obj):
        raise Denied("Policy contains missing or unknown keys")


def text(value):
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise Denied("Policy requires a nonempty bounded string")


def validate(policy):
    only(policy, {"version", "actions"}, {"version", "actions"})
    if policy["version"] != 1 or not isinstance(policy["actions"], dict):
        raise Denied("Unsupported policy version or actions")
    for name, a in policy["actions"].items():
        if not NAME.fullmatch(name):
            raise Denied("Invalid action name")
        common = {"kind", "description", "secrets", "timeout"}
        kind = a.get("kind") if isinstance(a, dict) else None
        if kind == "http":
            only(a, common | {"url", "method", "headers", "json", "outputs"}, {"kind", "url"})
            origin(a["url"])
            if "{{" in a["url"]:
                raise Denied("Secrets are not permitted in URLs")
            if a.get("method", "GET") not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                raise Denied("Invalid HTTP method")
            if not isinstance(a.get("headers", {}), dict):
                raise Denied("Headers must be an object")
            for key, value in a.get("headers", {}).items():
                if not re.fullmatch(r"[A-Za-z0-9-]+", key) or key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}:
                    raise Denied("Unsafe header name")
                text(value)
                if "\r" in value or "\n" in value:
                    raise Denied("Invalid header value")
            outputs = a.get("outputs", {})
            if not isinstance(outputs, dict) or any(not isinstance(v, str) for v in outputs.values()):
                raise Denied("Outputs must map names to JSON dot paths")
        elif kind == "command":
            only(a, common | {"argv", "cwd", "env", "output"}, {"kind", "argv", "cwd"})
            argv = a["argv"]
            if not isinstance(argv, list) or not argv:
                raise Denied("argv must be a nonempty array")
            for arg in argv:
                text(arg)
                if "{{" in arg:
                    raise Denied("Secrets belong in child environment, never argv")
            if not Path(argv[0]).is_absolute() or not Path(a["cwd"]).is_absolute():
                raise Denied("Executable and cwd must be absolute paths")
            if Path(argv[0]).suffix.lower() in {".bat", ".cmd", ".ps1"}:
                raise Denied("Use an executable with fixed arguments; shell scripts cannot be the executable")
            if a.get("output", "none") not in {"none", "text"}:
                raise Denied("Invalid command output mode")
            if not isinstance(a.get("env", {}), dict):
                raise Denied("env must be an object")
            for key, value in a.get("env", {}).items():
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                    raise Denied("Invalid environment name")
                text(value)
        elif kind == "browser":
            only(a, common | {"origins", "steps", "headless", "channel"}, {"kind", "origins", "steps"})
            if not isinstance(a["origins"], list) or not a["origins"]:
                raise Denied("Browser requires explicit HTTPS origins")
            allowed = set()
            for url in a["origins"]:
                parsed = urlsplit(url)
                if parsed.path not in {"", "/"} or parsed.query:
                    raise Denied("Origins cannot contain paths or queries")
                allowed.add(origin(url))
            if a.get("channel") not in {None, "msedge", "chrome"}:
                raise Denied("Unsupported browser channel")
            if not isinstance(a.get("headless", True), bool):
                raise Denied("headless must be boolean")
            if not isinstance(a["steps"], list) or not 1 <= len(a["steps"]) <= 50:
                raise Denied("Browser requires 1 to 50 steps")
            for step in a["steps"]:
                op = step.get("op")
                fields = {"goto": {"url"}, "fill": {"selector", "value"},
                          "click": {"selector"}, "wait": {"selector"},
                          "text": {"selector", "name"}}
                if op not in fields:
                    raise Denied("Unsupported browser step")
                only(step, {"op"} | fields[op], {"op"} | fields[op])
                for value in step.values():
                    text(value)
                if op == "goto" and ("{{" in step["url"] or origin(step["url"]) not in allowed):
                    raise Denied("Navigation outside approved origins")
                if any("{{" in v for k, v in step.items() if k != "value"):
                    raise Denied("Secrets only permitted in fill values")
        else:
            raise Denied("Unsupported action kind")
        if type(a.get("timeout", 60)) is not int or not 1 <= a.get("timeout", 60) <= 300:
            raise Denied("timeout must be 1 to 300 seconds")
        refs = a.get("secrets", {})
        if not isinstance(refs, dict):
            raise Denied("secrets must be an object")
        for alias, ref in refs.items():
            if not NAME.fullmatch(alias):
                raise Denied("Invalid secret alias")
            only(ref, {"record", "field", "transform"}, {"record", "field"})
            text(ref["record"])
            text(ref["field"])
            if ref.get("transform") not in {None, "totp"}:
                raise Denied("Unsupported secret transform")
    return policy
