from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .policy import NAME, validate
from .security import Denied, read_json, token_hash, write_private


def protect_directory(path):
    if os.name == "nt":
        system = Path(os.environ["SystemRoot"]) / "System32"
        identity = subprocess.run([str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                                  check=True, capture_output=True, text=True).stdout
        import re
        sid = re.search(r"S-1-[0-9-]+", identity)
        if not sid:
            raise Denied("Could not resolve the current Windows account SID")
        access = "(OI)(CI)F" if path.is_dir() else "F"
        subprocess.run([str(system / "icacls.exe"), str(path), "/inheritance:r", "/grant:r",
                        f"*{sid[0]}:{access}", f"*S-1-5-18:{access}"],
                       check=True, capture_output=True)
    else:
        path.chmod(0o700 if path.is_dir() else 0o600)


def certificate(state):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Keeper Agent local")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(key, hashes.SHA256()))
    for name, data in [("server.key", key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                       ("server.crt", cert.public_bytes(serialization.Encoding.PEM))]:
        fd = os.open(state / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)


def initialize(state, email, port):
    if state.exists():
        raise Denied("State directory already exists; choose a new empty location")
    state.mkdir(parents=True, mode=0o700)
    protect_directory(state)
    write_private(state / "keeper.json", {"user": email, "server": "keepersecurity.com", "certificate_check": True})
    write_private(state / "policy.json", {"version": 1, "actions": {}})
    write_private(state / "clients.json", {})
    write_private(state / "server.json", {"port": port})
    certificate(state)
    print("Initialized private state with no permitted actions. Configure policy.json before issuing a client.")


def replace_private(path, value):
    tmp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        write_private(tmp, value)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def add_client(state, name, actions, out):
    if not out.resolve().is_relative_to(state.resolve()):
        raise Denied("Generate the client inside private broker state, then transfer it to the agent account")
    if not NAME.fullmatch(name):
        raise Denied("Invalid client name")
    policy = validate(read_json(state / "policy.json"))
    if not actions or set(actions) - policy["actions"].keys():
        raise Denied("Every granted action must exist in policy.json")
    clients = read_json(state / "clients.json")
    if name in clients:
        raise Denied("Client already exists; revoke it first")
    token = secrets.token_urlsafe(48)
    config = read_json(state / "server.json")
    write_private(out, {"url": f"https://127.0.0.1:{config['port']}/v1", "token": token,
                        "certificate": (state / "server.crt").read_text()})
    protect_directory(out)
    clients[name] = {"sha256": token_hash(token), "actions": sorted(set(actions))}
    replace_private(state / "clients.json", clients)
    print("Client written. Transfer only that file to the agent account; keep all broker state private.")


def call_client(path, body):
    # Metadata-only desktop requests do not need to load the HTTP stack.
    import httpx
    config = read_json(path)
    url = urlsplit(config["url"])
    if url.scheme != "https" or url.hostname != "127.0.0.1" or url.path != "/v1" or url.username or url.query or url.fragment:
        raise Denied("Client endpoint must be the local HTTPS broker")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=config["certificate"])
    with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=330) as client:
        response = client.post(config["url"], headers={"Authorization": f"Bearer {config['token']}"}, json=body)
        value = response.json()
        if response.status_code != 200:
            raise Denied(value.get("error", "Broker rejected request"))
        return value


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] == "web":
        from .web import main as web_main
        return web_main(arguments[1:])
    parser = argparse.ArgumentParser(description="Use approved actions backed by a Keeper Personal vault")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("web", help="Serve the authenticated browser administrator (web --help)")
    for name in ("init", "serve", "client-add", "client-revoke", "doctor", "audit-verify"):
        command = sub.add_parser(name)
        command.add_argument("--state", type=Path, required=True, help="Private directory owned by the broker account")
        if name == "init":
            command.add_argument("--email", required=True)
            command.add_argument("--port", type=int, default=19463)
        elif name == "client-add":
            command.add_argument("--name", required=True)
            command.add_argument("--allow", action="append", required=True)
            command.add_argument("--out", type=Path, required=True)
        elif name == "client-revoke":
            command.add_argument("--name", required=True)
    command = sub.add_parser("validate")
    command.add_argument("--policy", type=Path, required=True)
    for name in ("list", "run"):
        command = sub.add_parser(name)
        command.add_argument("--client", type=Path, required=True)
        if name == "run":
            command.add_argument("action")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            if not 1024 <= args.port <= 65535:
                raise Denied("Port must be between 1024 and 65535")
            initialize(args.state.resolve(), args.email, args.port)
        elif args.command == "validate":
            policy = validate(read_json(args.policy))
            print(f"Valid policy: {len(policy['actions'])} actions")
        elif args.command == "client-add":
            add_client(args.state.resolve(), args.name, args.allow, args.out.resolve())
        elif args.command == "client-revoke":
            path = args.state / "clients.json"
            clients = read_json(path)
            if args.name not in clients:
                raise Denied("Unknown client")
            del clients[args.name]
            replace_private(path, clients)
            print("Client revoked for subsequent requests. Any already-running action may finish.")
        elif args.command == "doctor":
            policy = validate(read_json(args.state / "policy.json"))
            print(json.dumps({"policy_valid": True, "actions": len(policy["actions"]),
                              "isolation": "Requires separate OS account and protected code, policy, scripts and state",
                              "keeper_connected": "Not checked; serve performs interactive login"}, indent=2))
        elif args.command == "audit-verify":
            from .audit import verify
            count, problem = verify(args.state.resolve())
            print(json.dumps({"entries": count, "intact": problem is None, "problem": problem}, indent=2))
            return 0 if problem is None else 1
        elif args.command == "serve":
            from .provider import KeeperProvider
            from .server import serve
            state = args.state.resolve()
            policy = validate(read_json(state / "policy.json"))
            print("Administrator console: complete Keeper login here. Never paste credentials into agent chat.", flush=True)
            provider = KeeperProvider(state / "keeper.json")
            serve(state, policy, provider)
        else:
            body = {"operation": "list"} if args.command == "list" else {"operation": "run", "action": args.action}
            print(json.dumps(call_client(args.client, body), indent=2))
        return 0
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130
    except Denied as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # Deliberately do not stringify upstream exceptions; they may carry secrets.
        print("Operation failed. Check paths, installed dependencies, policy, and Keeper authentication.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
