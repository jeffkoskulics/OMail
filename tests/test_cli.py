import asyncio

import pytest

from omail.cli import build_parser, serve, status
from omail.qr import render_ascii


def test_render_ascii_produces_qr_blocks():
    art = render_ascii("http://example.onion")
    assert len(art.splitlines()) > 10
    assert any(ch in art for ch in "█▀▄")


def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.port == 8000
    assert args.control_port == 9051
    assert args.hs_port == 80
    assert args.no_tor is False
    assert args.data_dir == "data"


def test_parser_overrides():
    args = build_parser().parse_args(
        ["--no-tor", "--port", "9000", "--host-name", "Harbor",
         "--tor-password", "s3cret"]
    )
    assert args.no_tor is True
    assert args.port == 9000
    assert args.host_name == "Harbor"
    assert args.tor_password == "s3cret"


def test_serve_boots_and_shuts_down(tmp_path, capsys, aiohttp_unused_port):
    """Full node boot in --no-tor mode: portal comes up, status renders,
    local-only warning is shown (no QR for an unpublished onion), clean
    shutdown."""
    port = aiohttp_unused_port()
    args = build_parser().parse_args(
        ["--no-tor", "--data-dir", str(tmp_path), "--port", str(port),
         "--host-name", "Boot Test"]
    )

    async def run():
        task = asyncio.create_task(serve(args))
        await asyncio.sleep(0.3)
        # Portal must be answering on loopback
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        head = await reader.read(64)
        writer.close()
        assert b"200 OK" in head
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    out = capsys.readouterr().out
    assert "host name           : Boot Test" in out
    assert "SKIPPED (--no-tor)" in out
    assert "LOCAL-ONLY" in out
    assert f"http://127.0.0.1:{port}" in out
    # The unpublished onion address is disclosed but clearly marked dead,
    # and never rendered as a bookmarkable QR code.
    assert "NOT" in out
    assert ".onion" in out
    assert "█" not in out.split(".onion")[-1]
    assert "Bookmark it" not in out


def test_tor_error_hints_cover_auth_failures():
    from stem import SocketError
    from stem.connection import IncorrectPassword, MissingPassword

    from omail.cli import _tor_error_hints

    hints = "\n".join(_tor_error_hints(MissingPassword("no passphrase provided"), 9051))
    assert "CookieAuthentication 1" in hints
    assert "--tor-password" in hints

    hints = "\n".join(_tor_error_hints(IncorrectPassword("bad"), 9051))
    assert "tor --hash-password" in hints

    hints = "\n".join(_tor_error_hints(SocketError("connection refused"), 9151))
    assert "9151" in hints
    assert "ControlPort" in hints

    hints = "\n".join(_tor_error_hints(RuntimeError("weird"), 9051))
    assert "9051" in hints


def test_status_prints_timestamped(capsys):
    status("hello world")
    out = capsys.readouterr().out
    assert "hello world" in out
    assert out.strip().startswith("[")
