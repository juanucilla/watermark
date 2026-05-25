# watermark

> Proteggi il tuo codice Python con watermark invisibili e beacon runtime.  
> Prove di paternità + notifiche in tempo reale se il codice viene usato senza permesso.

---

**Watermark** embeds invisible ownership markers into Python source files using zero-width Unicode steganography, and optionally generates a silent runtime beacon that notifies you when stolen code is executed.

## Features

- **Steganographic watermark** — zero-width Unicode characters (`U+200B`, `U+200C`, `U+200D`) hidden inside strings and comments. Invisible in every editor, terminal, and code hosting platform. Survives copy-paste.
- **Ownership verification** — extract and verify the owner of any watermarked file.
- **Runtime beacon** — a daemon thread that silently contacts your server when the watermarked code runs, sending a hashed machine ID.
- **Stealth beacon** — endpoint URL split into base64 fragments and disguised as a profiling decorator. `grep`/`ripgrep` cannot find the URL in plain text.
- **Zero dependencies** — standard library only.

## Installation

No package needed. Just copy `watermark.py` into your project or anywhere on your `PATH`.

```bash
git clone https://github.com/<your-username>/watermark.git
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
# [+] Hidden characters  : 186 (invisible)
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

```bash
# Standard (URL in plain text)
python watermark.py beacon https://myserver.com/w my-project

# Stealth (URL split into base64 fragments, wrapped in a decorator)
python watermark.py beacon https://myserver.com/w my-project --stealth
```

Paste the output into your module's `__init__.py` or entry point, then decorate any public function:

```python
# paste beacon snippet here …

@_perf_track          # ← this is the hidden trigger
def my_main_function():
    ...
```

When the decorated function is called for the first time, your server receives:

```
GET https://myserver.com/w?p=my-project&u=<md5_of_hostname>
```

The request runs in a daemon thread and silences all exceptions — it never affects the host application.

### Inspect URL fragments (utility)

```bash
python watermark.py encode https://myserver.com/w
# Fragments:
#   _F[0] = b'aHR0cHM6Ly9'
#   _F[1] = b'0dW9zZXJ2ZX'
#   _F[2] = b'IuY29tL3c='
```

## How it works

### Layer 1 — Zero-width steganography

The owner ID and a SHA-256 fingerprint of the filename are encoded as a binary string, then mapped to zero-width characters:

```
bit 0 → U+200B (Zero Width Space)
bit 1 → U+200C (Zero Width Non-Joiner)
boundary → U+200D (Zero Width Joiner)
```

The payload is injected immediately after the first string literal or comment found in the file. It is completely invisible when viewing the file, and most automated formatters (Black, isort) preserve it because it sits inside a string or comment.

### Layer 2 — Runtime beacon

The stealth beacon splits the endpoint URL into N base64 fragments stored as separate byte literals. They are reassembled in memory at call time. Neither `grep` nor IDE search can find the URL by scanning the source.

The beacon fires at most once per process (guarded by a module-level flag), uses a 2-second timeout, and catches all exceptions.

## Setting up a server

Any minimal HTTP endpoint works. Examples:

- **Testing:** [webhook.site](https://webhook.site) — free, instant, no setup.
- **Production:** a single serverless function (Vercel, AWS Lambda, Cloudflare Worker) that logs `?p=` and `?u=` to a database.

Minimal Python server (Flask):

```python
from flask import Flask, request
app = Flask(__name__)

@app.route("/w")
def beacon():
    project = request.args.get("p")
    uid = request.args.get("u")
    print(f"[BEACON] project={project} machine={uid}")
    return "", 204
```

## Limitations

| Scenario | Steganographic watermark | Runtime beacon |
|---|---|---|
| Source code stolen and redistributed | ✅ Proves ownership | ✅ Fires on execution |
| Code compiled to `.pyc` only | ✅ Survives (`.pyc` embeds string data) | ✅ Survives |
| Code heavily refactored / rewritten | ❌ May be lost | Depends on placement |
| Attacker strips all comments and strings | ❌ Lost | Depends on placement |
| No internet access on target machine | ✅ Still proves ownership | ❌ Beacon cannot reach server |

## Contributing

Issues and PRs are welcome. Keep the zero-dependency constraint.

## License

MIT — see [LICENSE](LICENSE).
