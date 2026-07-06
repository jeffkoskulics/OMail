"""
The `omail` terminal entry point.

Boots the node: local web portal on 127.0.0.1, Tor Hidden Service in
front of it, live status on the terminal, and an ASCII QR code of the
generated .onion address for secure Tor Browser access.
"""
import argparse
import asyncio
import datetime
import os
import signal
import sys
from pathlib import Path

from aiohttp import web

from omail import __version__
from omail.db import Database
from omail.host import HostNode
from omail.key_pair import KeyPair
from omail.onion_service import OnionService
from omail.qr import render_ascii
from omail.server import create_app

BANNER = r"""
   ____  __  __       _ _
  / __ \|  \/  | __ _(_) |
 | |  | | |\/| |/ _` | | |    decentralized - private - sovereign
 | |__| | |  | | (_| | | |    v{version}
  \____/|_|  |_|\__,_|_|_|
"""


def status(message: str) -> None:
    """Real-time system status line."""
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"  [{stamp}] {message}", flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omail",
        description="OMail node: Tor-routed, passkey-bound, Triple Ratchet messaging.",
    )
    parser.add_argument("--data-dir", default="data", help="node data directory")
    parser.add_argument("--host-name", default=None,
                        help="human-readable host name shown in portal titles")
    parser.add_argument("--port", type=int, default=8000,
                        help="local portal port (default 8000)")
    parser.add_argument("--hs-port", type=int, default=80,
                        help="virtual port exposed on the onion service")
    parser.add_argument("--control-port", type=int, default=9051,
                        help="Tor control port")
    parser.add_argument("--tor-password", default=os.environ.get("TOR_PASSWORD"),
                        help="Tor control port password (default: $TOR_PASSWORD; "
                             "not needed when torrc uses CookieAuthentication 1)")
    parser.add_argument("--no-tor", action="store_true",
                        help="development mode: skip the Tor Hidden Service")
    parser.add_argument("--version", action="version",
                        version=f"omail {__version__}")
    return parser


def _tor_error_hints(exc: Exception, control_port: int) -> list:
    """Turn a stem/Tor failure into actionable remediation steps."""
    from stem import SocketError
    from stem.connection import (
        AuthenticationFailure,
        IncorrectPassword,
        MissingPassword,
        UnreadableCookieFile,
    )

    if isinstance(exc, MissingPassword):
        return [
            "tor control port requires a password and none was provided.",
            "Either pass it:      omail --tor-password <pw>   (or export TOR_PASSWORD)",
            "Or switch to cookie auth in your torrc (recommended):",
            "    ControlPort 9051",
            "    CookieAuthentication 1",
            "    # remove any HashedControlPassword line",
            "then restart tor (brew services restart tor) and rerun omail.",
        ]
    if isinstance(exc, IncorrectPassword):
        return [
            "the Tor control password was rejected.",
            "Check --tor-password / $TOR_PASSWORD against the HashedControlPassword",
            "in your torrc, or regenerate it with: tor --hash-password <new-pw>",
        ]
    if isinstance(exc, UnreadableCookieFile):
        return [
            "Tor's auth cookie exists but cannot be read.",
            "Run omail as the same user that runs tor (brew services runs it as you),",
            "or switch the control port to password auth (HashedControlPassword).",
        ]
    if isinstance(exc, AuthenticationFailure):
        return [
            "could not authenticate to the Tor control port.",
            "Check your torrc auth settings: CookieAuthentication 1 (recommended)",
            "or HashedControlPassword + --tor-password.",
        ]
    if isinstance(exc, SocketError):
        return [
            f"nothing is listening on the Tor control port ({control_port}).",
            "Is tor running? Enable the control port in your torrc:",
            "    ControlPort 9051",
            "    CookieAuthentication 1",
            "then restart tor, or start one ad hoc: tor --controlport 9051",
        ]
    return [
        "unexpected Tor error — check that tor is running and the control",
        f"port ({control_port}) matches your torrc's ControlPort.",
    ]


def _start_onion(host_kp: KeyPair, args) -> OnionService:
    service = OnionService(
        host_kp,
        target_port=args.port,
        hidden_service_port=args.hs_port,
        control_port=args.control_port,
        password=args.tor_password,
    )
    service.start()
    return service


def _sovereign_onion_services(db: Database, args) -> list:
    """Re-provisions hidden services for tenants promoted to sovereign."""
    services = []
    for user in db.list_users():
        if not user["sovereign"]:
            continue
        pem = db.get_config(f"sovereign_onion_key:{user['id']}")
        if not pem:
            continue
        from cryptography.hazmat.primitives import serialization as ser
        kp = KeyPair()
        kp.private_key = ser.load_pem_private_key(pem.encode(), password=None)
        kp.public_key = kp.private_key.public_key()
        service = OnionService(
            kp,
            target_port=args.port,
            hidden_service_port=args.hs_port,
            control_port=args.control_port,
            password=args.tor_password,
        )
        service.start()
        services.append((user["handle"], service))
    return services


async def serve(args) -> int:
    print(BANNER.format(version=__version__))

    data_dir = Path(args.data_dir)
    db = Database(data_dir / "omail.db")
    host = HostNode(db, host_name=args.host_name)
    status(f"node data directory : {data_dir.resolve()}")
    status(f"host name           : {host.host_name}")
    status(f"node mode           : {db.get_config('mode', 'tenant')}")

    # 1. Local asynchronous web server (loopback only — never the clearnet)
    app = create_app(
        db,
        host,
        announce=status,
        tor_options={
            "control_port": args.control_port,
            "password": args.tor_password,
            "local_port": args.port,
        },
        start_tor_on_migration=not args.no_tor,
    )
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", args.port)
    await site.start()
    status(f"local portal        : http://127.0.0.1:{args.port} (loopback only)")

    # 2. Tor Hidden Service in front of it
    onion_url = f"http://{host.onion}"
    local_url = f"http://127.0.0.1:{args.port}"
    services = []
    tor_live = False
    if args.no_tor:
        status("tor hidden service  : SKIPPED (--no-tor); portal is local-only")
    else:
        status(f"tor control port    : {args.control_port} — publishing descriptor…")
        loop = asyncio.get_running_loop()
        try:
            service = await loop.run_in_executor(None, _start_onion,
                                                 host.key_pair(), args)
            services.append(("host", service))
            tor_live = True
            status(f"tor hidden service  : LIVE at {host.onion}")
            sovereign = await loop.run_in_executor(
                None, _sovereign_onion_services, db, args
            )
            for handle, svc in sovereign:
                services.append((handle, svc))
                status(f"sovereign service   : {svc.service_id}.onion ({handle})")
        except Exception as exc:
            status(f"tor hidden service  : FAILED ({exc})")
            for hint in _tor_error_hints(exc, args.control_port):
                status(f"  {hint}")
            status("continuing local-only; fix Tor and restart to go dark")

    status(f"host UPA            : {host.upa}")
    print()
    if tor_live:
        print(f"  Access the {host.host_name} OMail portal in Tor Browser:")
        print(f"\n      {onion_url}\n")
        print("  Bookmark it — there is no clearnet fallback. Scan to open:\n")
        print(render_ascii(onion_url))
    else:
        print(f"  The {host.host_name} OMail portal is LOCAL-ONLY right now:")
        print(f"\n      {local_url}\n")
        print("  The onion address below is reserved for this node but is NOT")
        print("  reachable in Tor Browser until Tor publishes it (fix Tor per the")
        print("  hints above, then restart omail):\n")
        print(f"      {onion_url}")

    # 3. Serve until interrupted
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # e.g. Windows event loops
            pass
    if tor_live:
        status("node is up — waiting for Tor circuits (Ctrl+C to stop)")
    else:
        status("node is up — LOCAL-ONLY, not reachable over Tor (Ctrl+C to stop)")
    try:
        await stop.wait()
    finally:
        status("shutting down…")
        for _, service in services:
            try:
                service.stop()
            except Exception:
                pass
        await runner.cleanup()
        db.close()
        status("goodbye")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(serve(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
