# zmsf-linux-audit
# ZMSF Linux Audit Toolkit
<img width="1024" height="339" alt="image" src="https://github.com/user-attachments/assets/5136febb-9071-49b1-b1af-c5ec7f376703" />

**A non-invasive, open-source-ready Linux host security baseline collector.** This toolkit complements [ZMSF — Zero Meaning Security Framework](https://github.com/JoaquinHernandez/ZMSF) and the [OWASP ASVS](https://asvs.owasp.org/). **It is not a certification, penetration test, vulnerability scanner, or proof of compliance.**

> Assume Compromise. Protect Meaning.

## What it does

- Inventories Linux OS, kernel, architecture, and installed Nginx, Apache, Python, Node, npm, OpenSSL, SSH, database, and other available executable versions.
- Checks cached package-update metadata (APT on Debian/Ubuntu; DNF cache on RHEL-derived systems). Outputs *available updates*, not a claim that the host is completely patched.
- Reviews limited SSH daemon configuration, listening TCP sockets, host firewall status, ASLR, SELinux/AppArmor status, and Nginx configuration syntax when tools and permissions permit.
- Optionally performs **heuristic static triage** of Python/JavaScript/TypeScript/HTML application source for possible injection, XSS, unsafe execution, and embedded-key indicators **without printing source lines or key values**.
- Tracks important **not-verified** controls such as external KMS/HSM, encrypted data theft exercises, authN/authZ and IDOR testing, dependency CVE analysis, and active security testing.
- Generates private `summary.txt` and (when Python 3 is available) `report.json`.
- Supports an optional daily systemd timer and an inventory-based SSH collection runner for **only authorized servers**.

**Does not:** scan every server on the Internet, exploit systems, run remote Nmap/ZAP, discover hosts, install packages, run `apt update`/`upgrade`, restart services, access database records, print API-key values, or send telemetry.

## Quick start — on a Linux server

Requires Bash and standard command-line tools. Python 3 is optional, but recommended for JSON and source triage.

```bash
chmod +x zmsf-linux-audit.sh
./zmsf-linux-audit.sh --help
sudo ./zmsf-linux-audit.sh
```

Optional code check on a directory you own:

```bash
sudo ./zmsf-linux-audit.sh --app-dir /path/to/your/app
```

No output files (great for short-lived SSH sessions):

```bash
bash ./zmsf-linux-audit.sh --stdout-only
```

Report paths default to `/var/lib/zmsf-audit/` for root and `~/.local/state/zmsf-audit/` for non-root. Reports may include software versions, hostnames, and private listening addresses; **keep reports private**. Do not commit the reports to a public GitHub repository.

## Optional daily audit via systemd

```bash
sudo AUDIT_TZ=America/Chicago AUDIT_HOUR=06 ./install-systemd.sh
sudo systemctl list-timers --all zmsf-linux-audit.timer
sudo systemctl start zmsf-linux-audit.service
sudo journalctl -u zmsf-linux-audit.service -n 50 --no-pager
```

Defaults: **06:00 UTC** if timezone/hour are not specified. The installer refuses to overwrite existing installed units. The timer service is configured to write reports only under `/var/lib/zmsf-audit`. It does **not** alter other services.

**If you already installed a GlucoFocus-specific security audit timer, leave that intact unless you have a validated transition plan. Running both produces duplicate audits.**

## Auditing a fleet you own (SSH, no scanning)

For authenticated hosts already in `~/.ssh/known_hosts`:

```bash
cp examples/hosts.example.txt hosts.txt
# Edit hosts.txt to contain only machines you administer: user@server.example.com
chmod 600 hosts.txt
./audit-authorized-hosts.sh hosts.txt
```

The collector sends the self-contained script over an **authenticated SSH connection** and writes per-host reports locally. SSH uses `BatchMode=yes`, `StrictHostKeyChecking=yes`, and disables forwarding. No inventory discovery, password attempts, or probing outside the specified list. Privileges depend on the configured remote SSH account. Use SSH config for custom ports.

## How to interpret findings

| Marker | Meaning |
|---|---|
| `APT_AVAILABLE_UPDATES_CACHED=N` | N potentially upgradable packages based on cached local repository metadata; not a live CVE scan. |
| `APT_METADATA_FRESHNESS=STALE` | Consider a separately approved package-index refresh; this tool never refreshes metadata. |
| `APP_REVIEW_SIGNALS=N` | Heuristic code-review signals, **not proven vulnerabilities**. |
| `ZMSF_EXTERNAL_KMS_HSM=NOT_VERIFIED` | External key separation requires architecture and runtime verification. |
| `OWASP_AUTHENTICATED_IDOR_CSRF_XSS=NOT_TESTED` | Authenticated application testing is still required. |
| `SECURITY_CERTIFICATION=NOT_CLAIMED` | A green run must not be presented as an independent security assessment. |

## Coverage and limitations

- Works best on Linux. Tested in a Debian-like sandbox; other Linux distributions receive best-effort inventories. Package-update checks outside APT/DNF intentionally report **review required** rather than silently guessing.
- Does not determine whether software versions are vulnerable. Distro maintainers may backport security fixes; compare vendor advisories and use dedicated SCA/CVE scanners.
- This does not verify the host supports MFA, is intrusion-free, or that sensitive health data is encrypted. For ZMSF, assess envelope encryption, independent KMS/HSM trust boundary, identity-gated decryption, key rotation, and stolen-backup readability with authorized test data.
- Active OWASP testing (IDOR, injection payloads, CSRF, upload abuse, XSS, SSRF, session hijacking) must be run in authorized isolated staging with synthetic accounts, not on a patient production system.
- File-name-based flags are suggestions only. Source code is never executed during source triage.
- Audit collection requires enough privileges for some host checks. Unprivileged results are explicitly marked limited.
- Existing OS auto-updaters may still install software. This tool does **not** disable them.

## Security model

- No secret values or application source lines in the report.
- Report directories are created `0700`; reports are `0600`.
- Refuses symlinked output directory and symlinked application root. It does not follow symlinked source files.
- No external connections from the local collector. Optional SSH runner connects only to enumerated authorized hosts.
- Installer does not overwrite existing installed files.

## GitHub publishing

Create your new repository (for example `zmsf-linux-audit`), then upload the **source files only**. Review `.gitignore`. Never include any real host reports, server inventories, `.env`, credentials, SSH keys, or medical/customer data. Add your preferred copyright/license before accepting contributions.

## References

- ZMSF: https://github.com/JoaquinHernandez/ZMSF
- OWASP ASVS: https://asvs.owasp.org/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST CSF: https://www.nist.gov/cyberframework
- Ubuntu automatic updates: https://documentation.ubuntu.com/security/security-updates/

## Roadmap (not yet implemented)

Semgrep / Bandit, pip-audit and OSV dependency analysis, image-upload and cross-account authorization tests, reporting dashboards, verified vendor-advisory correlation, signed audit artifacts, and ZMSF key-isolation evidence collection.
