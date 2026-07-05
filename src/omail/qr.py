"""
Terminal QR rendering for .onion portal URLs.
"""
import io

import qrcode


def render_ascii(data: str, invert: bool = True) -> str:
    """Renders `data` as a compact ASCII QR code suitable for terminals."""
    qr = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(data)
    qr.make(fit=True)
    out = io.StringIO()
    qr.print_ascii(out=out, invert=invert)
    return out.getvalue()
