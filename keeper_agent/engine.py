from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
import time

import httpx
import pyotp
import psutil

from .policy import PLACEHOLDER
from .security import Denied, origin, scrub

LIMIT = 256 * 1024


def render(value, secrets):
    if isinstance(value, str):
        def substitute(match):
            if match[1] not in secrets:
                raise Denied("Unknown secret alias in policy")
            return secrets[match[1]]
        return PLACEHOLDER.sub(substitute, value)
    if isinstance(value, list):
        return [render(v, secrets) for v in value]
    if isinstance(value, dict):
        return {k: render(v, secrets) for k, v in value.items()}
    return value


def select(document, path):
    for part in path.split("."):
        document = document[int(part)] if isinstance(document, list) else document[part]
    return document


class Engine:
    def __init__(self, policy, provider):
        self.policy = policy
        self.provider = provider

    def run(self, name, policy=None):
        # The broker passes the policy it authorized against, so a concurrent
        # reload cannot swap the definition between the check and the run.
        policy = policy or self.policy
        if name not in policy["actions"]:
            raise Denied("Action not permitted")
        action = policy["actions"][name]
        secrets = {}
        redact = []
        if action.get("secrets"):
            self.provider.sync()
        for alias, ref in action.get("secrets", {}).items():
            value = self.provider.get(ref)
            redact.append(value)
            if ref.get("transform") == "totp":
                value = (pyotp.parse_uri(value) if value.startswith("otpauth://") else pyotp.TOTP(value)).now()
                redact.append(value)
            secrets[alias] = value
        # Redact complete auth headers too (including Basic user:password encodings).
        headers = render(action.get("headers", {}), secrets)
        redact.extend(v for k, v in headers.items() if k.lower() in {"authorization", "x-api-key"})
        if action["kind"] == "http":
            result = self.http(action, secrets)
        elif action["kind"] == "command":
            result = self.command(action, secrets)
        else:
            result = self.browser(action, secrets)
        result = scrub(result, redact)
        if len(json.dumps(result).encode()) > LIMIT:
            raise Denied("Result exceeds output limit")
        return result

    def http(self, action, secrets):
        headers = render(action.get("headers", {}), secrets)
        if any("\r" in x or "\n" in x for x in headers.values()):
            raise Denied("Secret contains invalid header characters")
        timeout = action.get("timeout", 60)
        start = time.monotonic()
        # No inherited proxies, cookies, redirects or TLS overrides.
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout) as client:
            with client.stream(action.get("method", "GET"), action["url"], headers=headers,
                               **({"json": render(action["json"], secrets)} if "json" in action else {})) as response:
                if 300 <= response.status_code < 400:
                    raise Denied("HTTP redirect refused")
                result = {"status": response.status_code}
                if action.get("outputs"):
                    data = bytearray()
                    for chunk in response.iter_bytes(chunk_size=16384):
                        data.extend(chunk)
                        if len(data) > LIMIT or time.monotonic() - start > timeout:
                            raise Denied("HTTP response exceeds size or time limit")
                    body = json.loads(data)
                    result["data"] = {key: select(body, path) for key, path in action["outputs"].items()}
                return result

    def command(self, action, secrets):
        # A command is administrator-trusted code. Agent never supplies argv/cwd/env.
        env = {k: v for k, v in os.environ.items()
               if k.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG"}}
        env.update(render(action.get("env", {}), secrets))
        env["NO_COLOR"] = "1"
        output = action.get("output", "none") == "text"
        with subprocess.Popen(action["argv"], cwd=action["cwd"], env=env, shell=False,
                              stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                              stderr=subprocess.STDOUT if output else subprocess.DEVNULL) as proc:
            data = bytearray()
            too_large = threading.Event()
            descendants = set()
            try:
                root = psutil.Process(proc.pid)
            except psutil.NoSuchProcess:
                root = None
            def cleanup():
                for child in descendants:
                    try:
                        child.kill()
                    except psutil.Error:
                        pass
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
            def drain():
                while True:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    if len(data) + len(chunk) > LIMIT:
                        too_large.set()
                        break
                    data.extend(chunk)
            reader = threading.Thread(target=drain, daemon=True) if output else None
            if reader:
                reader.start()
            deadline = time.monotonic() + action.get("timeout", 60)
            try:
                while proc.poll() is None:
                    try:
                        if root:
                            descendants.update(root.children(recursive=True))
                    except psutil.Error:
                        pass
                    if too_large.is_set():
                        raise Denied("Command output exceeded limits")
                    if time.monotonic() >= deadline:
                        raise Denied("Command timed out")
                    time.sleep(0.03)
                code = proc.returncode
            finally:
                cleanup()
            if reader:
                reader.join(timeout=2)
                if reader.is_alive() or too_large.is_set():
                    raise Denied("Command output exceeded limits or was left open")
            return {"exit_code": code, **({"output": data.decode("utf-8", errors="replace")} if output else {})}

    def browser(self, action, secrets):
        from playwright.sync_api import sync_playwright
        allowed = {origin(url) for url in action["origins"]}
        deadline = time.monotonic() + action.get("timeout", 60)
        def remaining():
            ms = int((deadline - time.monotonic()) * 1000)
            if ms <= 0:
                raise Denied("Browser action timed out")
            return ms
        def guard(route):
            try:
                ok = origin(route.request.url) in allowed
            except (Denied, ValueError):
                ok = False
            route.continue_() if ok else route.abort()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=action.get("headless", True),
                                        channel=action.get("channel"), chromium_sandbox=True,
                                        timeout=remaining())
            try:
                context = browser.new_context(accept_downloads=False, service_workers="block")
                context.route("**/*", guard)
                context.route_web_socket("**/*", lambda ws: ws.close())
                page = context.new_page()
                data = {}
                for step in action["steps"]:
                    op = step["op"]
                    if op == "goto":
                        page.goto(step["url"], wait_until="domcontentloaded", timeout=remaining())
                        continue
                    if origin(page.url) not in allowed:
                        raise Denied("Browser left approved origins")
                    element = page.locator(step["selector"])
                    if op == "fill":
                        element.fill(render(step["value"], secrets), timeout=remaining())
                    elif op == "click":
                        element.click(timeout=remaining())
                    elif op == "wait":
                        element.wait_for(state="visible", timeout=remaining())
                    elif op == "text":
                        value = element.inner_text(timeout=remaining())
                        if len(value.encode()) > LIMIT:
                            raise Denied("Browser output exceeds limit")
                        data[step["name"]] = value
                return {"completed": True, **({"data": data} if data else {})}
            finally:
                browser.close()
