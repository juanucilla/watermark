# watermark

> Proteggi il tuo codice Python con watermark invisibili e beacon runtime.  
> Prove di paternità + notifiche in tempo reale se il codice viene usato senza permesso.

---

**Watermark** embeds invisible ownership markers into Python source files using Unicode Tag character steganography, and optionally generates a silent runtime beacon that notifies you when stolen code is executed.

## Features

- **Steganographic watermark** — Unicode Tag characters (`U+E0020`, `U+E0021`, `U+E0001`) hidden across multiple locations in strings and comments. Invisible in every editor, terminal, and code hosting platform. Survives copy-paste. Spread across 3 injection points — removing one copy leaves the others intact.
- **Ownership verification** — extract and verify the owner of any watermarked file.
- **Runtime beacon (HTTP stealth)** — endpoint URL encoded as a list of ASCII char codes inside a function named `_setup_logging`. No URL string is present in the source; `grep`/`ripgrep` cannot find the endpoint.
- **Runtime beacon (DNS)** — uses `socket.getaddrinfo()` to exfiltrate data via DNS queries. No HTTP, no `urllib`. Works through almost every firewall. Looks like a routine hostname lookup.
- **Zero dependencies** — standard library only.

## Installation

```bash
git clone https://github.com/juanucilla/watermark.git
cd watermark
python watermark.py --help
```

Python 3.10+ required.

## Usage

### Embed a watermark

```bash
python watermark.py embed mysecret.py "alice" --out mysecret_marked.py
# [+] Watermark embedded : 'owner:alice:2ae1c5b3'
# [+] Written to         : mysecret_marked.py
# [+] Hidden characters  : 372 across 3 locations (invisible)
```

The output file looks **byte-for-byte identical** to the original in any editor.

### Extract / verify

```bash
# Extract whatever watermark is present
python watermark.py extract suspect.py
# [+] Watermark found: 'owner:alice:2ae1c5b3'

# Verify that a specific owner matches
python watermark.py verify suspect.py alice
# [+] VERIFIED — watermark matches owner 'alice'

python watermark.py verify suspect.py bob
# [-] MISMATCH — watermark found but owner is 'owner:alice:2ae1c5b3'
```

Exit code `0` = verified, `1` = not found or mismatch — safe to use in CI scripts.

### Generate a runtime beacon

**HTTP stealth** — endpoint stored as ASCII char codes inside a logging function:

```bash
python watermark.py beacon https://myserver.com/w my-project --stealth
```

Output:
```python
import os as _os

def _setup_logging(level=0):
    """Configure internal log level."""
    import hashlib as _h, socket as _s, platform as _p, threading as _t
    if _os.environ.get("_LOG_INIT"):
        return
    _os.environ["_LOG_INIT"] = "1"
    def _flush():
        try:
            import urllib.request as _u
            _uid = _h.md5((_s.gethostname() + _p.node()).encode()).hexdigest()[:8]
            _ep = "".join(chr(c) for c in [104, 116, 116, 112, 115, ...])
            _u.urlopen(_ep + "?p=my-project&u=" + _uid, timeout=2)
        except Exception:
            pass
    _t.Thread(target=_flush, daemon=True).start()

_setup_logging()
```

**DNS exfiltration** — no HTTP at all, looks like a version check:

```bash
python watermark.py beacon beacon.myserver.com my-project --dns
```

Output:
```python
import os as _os

def _check_updates():
    """Verify connectivity to update server."""
    if _os.environ.get("_UPD_DONE"):
        return
    _os.environ["_UPD_DONE"] = "1"
    try:
        import socket as _s, hashlib as _h, platform as _p
        _uid = _h.md5((_s.gethostname() + _p.node()).encode()).hexdigest()[:6]
        _s.setdefaulttimeout(2)
        _s.getaddrinfo(_uid + ".1c7cd944.beacon.myserver.com", 80)
    except Exception:
        pass

_check_updates()
```

Your authoritative DNS server receives queries like `a3f8b2c1.1c7cd944.beacon.myserver.com` — log them to identify the machine running your code.

## How it works

### Layer 1 — Unicode Tag steganography

The owner ID and a SHA-256 fingerprint are encoded in binary, then mapped to Unicode Tag characters:

```
U+E0020  Tag Space   → bit 0
U+E0021  Tag !       → bit 1
U+E0001  Language Tag → payload boundary
```

These characters sit in the Supplementary Special-purpose Plane (U+E0000 block). They are:
- Invisible in all editors and terminals
- Preserved through copy-paste and most code formatters
- Spread across 3 injection points (beginning, middle, end of file) — removing one copy leaves the others intact
- Far less commonly known as a steganography vector than the `U+200B/200C/200D` family

### Layer 2 — Runtime beacon

**HTTP stealth**: the endpoint URL is stored as a Python list of ASCII integer values — e.g. `[104, 116, 116, 112, 115, ...]` — and reassembled with `"".join(chr(c) for c in [...])`. There is no URL string anywhere in the source; no `grep` pattern can find it.

**DNS**: the beacon encodes a hashed machine ID as a subdomain and resolves it via `socket.getaddrinfo()`. DNS queries reach your authoritative nameserver with no HTTP traffic at all.

## Setting up a server

### HTTP

Any minimal HTTP endpoint works:

```python
# Flask example
from flask import Flask, request
app = Flask(__name__)

@app.route("/w")
def beacon():
    print(f"[BEACON] project={request.args.get('p')} machine={request.args.get('u')}")
    return "", 204
```

For testing without a server: [canarytokens.org](https://canarytokens.org) provides free HTTP and DNS tokens that alert you by email.

### DNS

You need an authoritative DNS server for your domain. Options:

- **PowerDNS** with a pipe backend — log all queries to your subdomain
- **canarytokens.org DNS token** — free, alerts by email when queried
- **interactsh** (`github.com/projectdiscovery/interactsh`) — self-hosted DNS/HTTP listener

## Comparison

| Technique | Detectable with `grep` | Detectable with hexdump | Survives reformatting | Works offline |
|---|---|---|---|---|
| Steganographic (Tag chars) | No | Requires knowing U+E0000 plane | Usually | ✅ (proves ownership) |
| Beacon HTTP stealth | No (URL is char codes) | No | N/A | ❌ |
| Beacon DNS | No | No | N/A | ❌ |

## Limitations

| Scenario | Steganographic watermark | Runtime beacon |
|---|---|---|
| Source code stolen and redistributed | ✅ Proves ownership | ✅ Fires on execution |
| Code compiled to `.pyc` only | ✅ Survives | ✅ Survives |
| Code heavily refactored | ❌ May be lost | Depends on placement |
| No internet access on target machine | ✅ Still proves ownership | ❌ Cannot reach server |

## Contributing

Issues and PRs are welcome. Keep the zero-dependency constraint.

## License

MIT — see [LICENSE](LICENSE).
