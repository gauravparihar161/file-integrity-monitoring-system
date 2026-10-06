# File Integrity Monitor

A Python command-line file integrity monitor for Linux and other Python 3.10+ systems. It builds a trusted SHA-256 baseline, periodically compares current file content and selected metadata, and reports created, modified, deleted, and metadata-changed files. Scan failures are logged. Deletions are suppressed when a scan is incomplete, avoiding false deletion alerts caused by permission or I/O errors.

## Features

- Chunked SHA-256 hashing for bounded memory use.
- Versioned JSON baseline written atomically with owner-only permissions on POSIX.
- Recursive directory scanning, glob exclusions, and explicit symlink policy (`skip` or `follow`). Follow mode tracks visited directory inodes to avoid symlink loops.
- Detection of created, deleted, modified, and permission/ownership/symlink metadata changes.
- Periodic monitoring, one-shot scans, JSON Lines audit events, and console alerts.
- Reports unreadable files and files that change while being hashed. An incomplete scan never replaces the baseline.
- Explicit `--update-baseline` option to accept changes after a clean scan.

## Install

From this directory on Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
mkdir -p demo-data
cp fim.example.json fim.json
```

On Windows, activate with `.venv\\Scripts\\Activate.ps1`. The application is designed for Linux monitoring and records POSIX ownership where available, but the Python implementation can also run on Windows.

## Run

Paths in the configuration are resolved relative to the config file. Keep `.fim/` outside every monitored path. The sample config monitors `demo-data` and stores its baseline and event log in `.fim/`.

```bash
fim baseline --config fim.json
fim scan --config fim.json
fim monitor --config fim.json
fim monitor --config fim.json --interval 5
fim scan --config fim.json --update-baseline
```

Exit codes for `scan`: `0` means no change, `1` means changes were found, and `2` means a configuration, baseline, or scan error occurred. Monitoring continues after a scan error and logs the error.

## Configuration

| Key | Purpose |
| --- | --- |
| `watch` | Non-empty list of existing files or directories to monitor. |
| `exclude` | Glob patterns matched against paths; useful for volatile files. |
| `baseline` | JSON baseline path. Keep it outside watched directories. |
| `log` | Append-only JSON Lines event log path. Keep it outside watched directories. |
| `interval_seconds` | Default delay between scans; can be overridden with `--interval`. |
| `hash_chunk_size` | Read size in bytes, at least 4096. |
| `symlinks` | `skip` (default) or `follow`. |

## Event example

```json
{"event":"modified","path":"/srv/example/config.ini","previous":{"sha256":"..."},"current":{"sha256":"..."},"timestamp":"2026-10-07T10:05:00Z"}
```

Events are appended to `.fim/events.jsonl`. Keep that log in a location with appropriate access controls; this starter project does not send email or remote alerts.

## Architecture and data flow

1. The CLI loads and validates configuration and ensures state files are outside monitored roots.
2. The scanner walks each configured path, applies exclusions and symlink policy, and hashes regular files in chunks.
3. A baseline command stores the complete inventory. A scan loads it and compares the current inventory.
4. The detector reports created, modified, deleted, and metadata changes. If any scan errors occur, it suppresses deletion conclusions because the inventory may be incomplete.
5. The reporter prints alerts and appends timestamped JSONL records. Monitor repeats this flow until interrupted.

## Security boundaries

- The baseline is the trust anchor. POSIX mode `0600` and atomic replacement help protect it from other local users and partial writes, but do not protect it from an attacker with the same account or root access.
- For a stronger deployment, place the baseline/log on a separately controlled host or read-only/append-only storage, or authenticate baselines with a separately protected key. Do not store an HMAC key beside the baseline and call that tamper-proof.
- SHA-256 detects content changes; it does not identify the actor, prove when a change occurred, or detect changes to metadata unless those fields are separately compared.
- A local monitor can be stopped or tampered with by a sufficiently privileged attacker. Production deployments should run under a constrained service account and forward events off-host.
- `follow` mode intentionally includes symlink targets. Use `skip` unless following links is required.

## Interview walkthrough

Demonstrate this sequence in a disposable directory:

1. Create a file and make the baseline.
2. Modify it, create another file, and delete one; run a one-shot scan and show the three event classes.
3. Change permissions with `chmod`; show `metadata_changed`.
4. Temporarily make a file unreadable and explain why the scan reports an error and suppresses deletion alerts.
5. Explain that protecting the baseline matters as much as selecting a cryptographic hash.

The main tradeoff is polling: it is portable and straightforward but costs repeated directory walks and hashing. A Linux `inotify` watcher could reduce latency and I/O, while periodic full scans remain useful to catch missed events.

