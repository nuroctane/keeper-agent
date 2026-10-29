"""Isolated Keeper login/broker process. Only typed protocol messages reach the UI."""
from __future__ import annotations

import argparse
import builtins
import contextlib
import getpass
import json
import logging
import os
from pathlib import Path
import sys
import threading
import uuid

from .security import Denied, read_json


class BrowserLoginUi:
    def __init__(self, emit, receive):
        self.emit = emit
        self.receive = receive

    def ask(self, kind, options):
        challenge = uuid.uuid4().hex
        self.emit({"state": "challenge", "challenge": {"id": challenge, "kind": kind, "options": options}})
        answer = self.receive()
        if not isinstance(answer, dict) or answer.get("id") != challenge:
            raise Denied("Login response expired. Start login again.")
        if answer.get("action") == "cancel":
            raise Denied("Login cancelled")
        if not isinstance(answer.get("value", ""), str) or len(answer.get("value", "")) > 4096:
            raise Denied("Invalid login response")
        self.emit({"state": "connecting"})
        return answer

    def on_password(self, step):
        answer = self.ask("password", [{"id": "password", "label": "Master password", "secret": True}])
        if answer.get("action") != "password":
            raise Denied("Choose password authentication")
        try:
            step.verify_password(answer["value"])
        except Exception:
            raise Denied("Keeper did not accept the password. Start login again.") from None
        finally:
            answer.clear()

    def on_device_approval(self, step):
        from keepercommander.auth.login_steps import DeviceApprovalChannel as Channel
        options = [{"id": "email", "label": "Send approval email"},
                   {"id": "push", "label": "Send Keeper push"},
                   {"id": "twofactor", "label": "Send MFA approval"},
                   {"id": "email-code", "label": "Submit email code", "secret": True},
                   {"id": "mfa-code", "label": "Submit MFA code", "secret": True},
                   {"id": "resume", "label": "I approved this device"}]
        answer = self.ask("device", options)
        action = answer.get("action")
        if action in {"email", "push", "twofactor"}:
            step.send_push({"email": Channel.Email, "push": Channel.KeeperPush, "twofactor": Channel.TwoFactor}[action])
        elif action in {"email-code", "mfa-code"}:
            step.send_code(Channel.Email if action == "email-code" else Channel.TwoFactor, answer.get("value", ""))
        elif action == "resume":
            step.resume()
        else:
            raise Denied("Invalid device approval method")
        answer.clear()

    def on_two_factor(self, step):
        from keepercommander.auth.login_steps import TwoFactorChannel as Channel, TwoFactorPushAction as Push, TwoFactorDuration
        channels = list(step.get_channels())
        methods = {}
        options = []
        for index, channel in enumerate(channels):
            if channel.channel_type in {Channel.SecurityKey, Channel.Other}:
                continue  # Keeper's RP-bound WebAuthn cannot run on this app's origin.
            key = str(index)
            methods[key] = (channel, None)
            options.append({"id": key, "label": channel.channel_type.name + " code", "secret": True})
            push = {Channel.TextMessage: Push.TextMessage, Channel.DuoSecurity: Push.DuoPush,
                    Channel.KeeperDNA: Push.KeeperDna}.get(channel.channel_type)
            if push:
                methods[key + "-push"] = (channel, push)
                options.append({"id": key + "-push", "label": "Send " + channel.channel_type.name + " request"})
        if not options:
            raise Denied("This account requires a hardware-key-only flow. Use the private terminal or enable a Keeper-supported code method.")
        answer = self.ask("mfa", options + [{"id": "resume", "label": "I approved the push"}])
        action = answer.get("action")
        step.duration = TwoFactorDuration.EveryLogin
        if action == "resume":
            step.resume()
        elif action in methods:
            channel, push = methods[action]
            if push:
                step.send_push(channel.channel_uid, push)
            else:
                step.send_code(channel.channel_uid, answer.get("value", ""))
        else:
            raise Denied("Invalid MFA method")
        answer.clear()

    def on_sso_redirect(self, step):
        raise Denied("Enterprise SSO is not supported by the Personal web login. Use the private terminal for this account.")

    def on_sso_data_key(self, step):
        raise Denied("SSO data-key approval requires the private terminal.")


def watch_parent(stream, stop):
    """The web server holds this process's stdin open. End of input means it has
    exited, however abruptly, so stop serving and log out of Keeper instead of
    leaving an owner-level session running with nobody in control."""
    try:
        while stream.readline(65537):
            pass
    except (OSError, ValueError):
        pass
    stop.set()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path)
    parser.add_argument("--install-browser", action="store_true")
    args = parser.parse_args(argv)
    output = sys.stdout

    def emit(value):
        output.write(json.dumps(value) + "\n")
        output.flush()

    def receive():
        line = sys.stdin.readline(65537)
        if not line or len(line) > 65536:
            raise Denied("Login cancelled")
        return json.loads(line)

    def unsupported_prompt(*args, **kwargs):
        raise Denied("This Keeper account needs an additional terminal-only step. Use private terminal login.")

    logging.disable(logging.CRITICAL)
    builtins.input = unsupported_prompt
    getpass.getpass = unsupported_prompt
    with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            if args.install_browser:
                import subprocess
                from playwright._impl._driver import compute_driver_executable, get_driver_env
                node, cli = compute_driver_executable()
                result = subprocess.run([str(node), str(cli), "install", "chromium"],
                                        env=get_driver_env(), stdout=sink, stderr=sink, timeout=600)
                if result.returncode:
                    raise Denied("Browser download failed. Check the broker host's network and disk space.")
                emit({"state": "completed"})
                return 0
            from .provider import KeeperProvider
            from .policy import validate
            from .server import serve
            provider = KeeperProvider(args.state / "keeper.json", BrowserLoginUi(emit, receive))
            stop = threading.Event()

            def connected():
                emit({"state": "connected"})
                # Login challenges are over, so stdin is now only a lifeline.
                threading.Thread(target=watch_parent, args=(sys.stdin, stop), daemon=True).start()

            try:
                serve(args.state, validate(read_json(args.state / "policy.json")), provider,
                      ready=connected, stop=stop)
            finally:
                provider.close()
        except Denied as error:
            emit({"state": "failed", "error": str(error)})
            return 1
        except Exception:
            emit({"state": "failed", "error": "Keeper connection failed. Check your account, approval method, and network, then try again."})
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
