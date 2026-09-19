# fwre — Linux firmware RE / vulnerability framework

A lightweight, dependency-free (stdlib-only) framework for reverse-engineering
and security-auditing Linux-based firmware images — IP cameras, routers and
other embedded devices whose `.bin` flash dumps carry a bootloader, one or more
`uImage` kernels and a SquashFS/JFFS2/UBI root filesystem.

**Extraction is delegated to 7-Zip.** Everything else — the value — is the
analysis layer that runs over the extracted root filesystem.

## Requirements

- Python 3.9+
- `7z` on `PATH` (e.g. `scoop install 7zip`, or 7-Zip on Windows)
- **Optional** extractors for filesystems 7z can't read (`pip install -r requirements.txt`):
  - `jefferson` — JFFS2 images
  - `ubi_reader` — UBI / UBIFS images

The core is pure stdlib; the optional tools are only used as an extraction
fallback. The CVE-corpus feature downloads a zip on demand.

## Quick start

```bash
# extract + analyze a single image, print findings
python -m fwre run firmware/wyze_cam3-t31x-gc2053-rtl8189ftv-virgin.bin

# write a full markdown report
python -m fwre run firmware/anker_c200-t31x-sc500ai-stock.bin -o anker.md

# run over every .bin in a directory + cross-image SUMMARY.md
python -m fwre batch ../firmware --out fwre_out

# analyze an already-extracted rootfs
python -m fwre analyze fwre_out/wyze_cam3.../

# just recover default/weak credentials
python -m fwre creds path/to/rootfs --wordlist mypasswords.txt

# per-binary hardening report (checksec)
python -m fwre checksec rootfs/usr/sbin/httpd rootfs/bin/busybox

# parse a serial boot log (or auto-find a sibling *.bootlog.txt)
python -m fwre bootlog firmware/hugolog_e5-...-atbm6012bx.bootlog.txt

# analyze the boot chain (U-Boot / uImage / env) on the raw image
python -m fwre uboot firmware/wyze_cam3-t31x-gc2053-rtl8189ftv-virgin.bin

# emit a CycloneDX SBOM (standalone, or add --sbom out.json to run/analyze)
python -m fwre sbom path/to/rootfs -o firmware.sbom.json
```

`batch` additionally writes a **cross-image correlation** section into
`SUMMARY.md` — shared `/etc/shadow` hashes, shared TLS certs/keys and reused
recovered passwords across every image scanned (crack once, own the fleet).

## How extraction works

`fwre extract` runs `7z x` on the raw image. 7z locates and unpacks the first
archive it recognises regardless of its offset in the flash. When that first
archive turns out to be the compressed kernel rather than the rootfs (common in
multi-partition dumps), fwre **locates filesystem magics** (SquashFS, UBI,
cramfs, JFFS2, ext) and dispatches each candidate to the right extractor until a
Linux rootfs appears:

- SquashFS / cramfs / ext / gzip -> carved `[offset:EOF]` slice handed to **7z**
- JFFS2 -> **jefferson** (carved slice)
- UBI / UBIFS -> **ubireader_extract_files** (auto-detects wrapped UBI geometry,
  falls back to trying common LEB sizes for a bare UBIFS)

No parsing/validation of the images themselves — the external tools do the
decompression. If an image needs a tool that isn't installed, fwre reports which
one to `pip install`.

## Build a standalone binary

```bash
build_nuitka.bat     # Windows -> dist\fwre.exe
./build_nuitka.sh    # Linux   -> dist/fwre
```

Both compile the pure-Python `fwre` package with Nuitka into one self-contained
executable. The external tools (7z, jefferson, ubi_reader) are invoked via
subprocess and are **not** bundled — keep them on PATH on the target machine.

## Analyzers

| module | what it finds |
|---|---|
| `defaults.py` | **default/weak credentials** — cracks `/etc/shadow` md5crypt/sha256crypt/sha512crypt hashes against a curated IoT-default wordlist (pure-python crypt, works on Windows), matches known vendor default hashes, and scrapes configs/`.htpasswd`/URLs for hardcoded logins |
| `analyze.py` (credentials) | passwd/shadow parsing, empty passwords, UID-0 aliases, weak DES/md5 hashes, hashcat mode hints |
| `analyze.py` (secrets) | private keys, TLS certs, API tokens (AWS/GCP/GitHub/JWT), Wi-Fi PSKs, hardcoded secret assignments |
| `elf.py` + `analyze.py` | **checksec**: arch/endian/bits, static/stripped, NX, PIE, RELRO, stack canary, FORTIFY, RPATH; dangerous libc imports; setuid & network-daemon flagging |
| `services.py` | **service misconfigs**: sshd/dropbear, telnet/inetd, FTP (vsftpd/proftpd/bftpd), nginx, lighttpd, apache, boa/goahead, wpa_supplicant/hostapd, unbound/dnsmasq, samba, mosquitto (MQTT), NTP, SNMP; plus web-app **RCE / XSS / SQLi / LFI** sinks in CGI/Lua/PHP/shell |
| `analyze.py` (attack surface) | init scripts (`inittab`, `init.d/rcS`), started daemons, direct-shell telnetd, gdbserver/debug shells |
| `cvedb.py` | component fingerprinting (busybox, dropbear, openssl, kernel, U-Boot, mbedTLS, sqlite, expat, curl, …) + curated high-impact CVE rules (always available, offline) |
| `cvestore.py` | full **cvelistV5 corpus** — download once, SQLite index, version-range matching |
| `analyze.py` (network IOCs) | URLs, IPs, MACs, cloud/MQTT/OTA endpoints — **cleartext-OTA (HIGH)** and **P2P/cloud control** endpoints classified distinctly (phone-home infra) |
| `analyze.py` (secrets, cont.) | now also scans **inside ELFs/`.so`** via string extraction (keys compiled into cloud/app daemons), adds AWS-secret/Alibaba/Slack/Telegram/Tuya patterns + an **entropy gate** |
| `analyze.py` (binaries, cont.) | **static-binary** dangerous-func detection (string scan), **RWX segment** + **UPX/packed** flags, `.comment`/toolchain, global hardening rollup |
| `bootlog.py` | parses serial **`*.bootlog.txt`**: U-Boot/kernel/gcc versions, `mtdparts`, `bootargs` (init=/console=/root=), boot-time creds → feeds CVE matching |
| `uboot.py` | boot-chain analysis on the **raw image**: U-Boot banner, **uImage** headers, U-Boot **env** (bootargs/bootcmd), init=/bin/sh + no-verified-boot flags |
| `cloud.py` | **cloud / P2P SDK** fingerprinting (ThroughTek/TUTK-Kalay, Tuya, ajcloud/Gwell, XMeye, iLnkP2P, …) with curated CVEs — the real remote surface on cameras |
| `certs.py` | pure-stdlib **X.509** parse: weak sig (MD5/SHA1), short RSA, self-signed, expiry, SHA-256 fingerprint; recognises TLS-library **test vectors** and softens them |
| `fsaudit.py` | filesystem **permission** audit: SUID/SGID, world-writable files/dirs, writable init scripts, loose key perms (auto-skips when Windows extraction drops modes) |
| `busybox.py` | **BusyBox applet** enumeration + dangerous-applet flagging (telnetd/nc/tftp/wget/crond), symlink-exposure aware |
| `correlate.py` | **cross-image (fleet)** correlation in `batch`: shared `/etc/shadow` hashes, shared certs/keys, reused cracked passwords across the corpus |
| `services.py` (cont.) | adds TR-069/CWMP, UPnP/miniupnpd, OpenVPN/stunnel/IPsec keys, RTSP/ONVIF auth, and **compiled-CGI** (C `httpd`) command-injection detection |
| `sbom.py` | **CycloneDX 1.5** SBOM export (`--sbom`, or `fwre sbom`) from the fingerprinted component/CVE set |

## CVE corpus

The curated rules in `cvedb.py` work out of the box. For exhaustive coverage,
download and index the official CVE Project list (`cvelistV5`):

```bash
# download (~500 MB zip, done once) + build the SQLite index
python -m fwre cvedb refresh

# show what's cached
python -m fwre cvedb status

# rebuild from an already-downloaded zip
python -m fwre cvedb build

# ad-hoc query
python -m fwre cvedb query --product busybox --pver 1.33.1 --verbose
```

The zip is streamed member-by-member with Python's `zipfile` (no multi-GB
extraction). The index is cached under `~/.fwre/cache` (override with
`$FWRE_CACHE`) and reused automatically by `run`/`analyze`/`batch` — when
present, corpus matches are added on top of the curated rules. To refresh, run
`fwre cvedb refresh` again.

## Output

- Console: severity-sorted finding list + a recovered-credentials table.
- `-o report.md`: full Markdown report (findings, creds, components/CVEs, a
  checksec table, network IOCs).
- `--json`: machine-readable output for tooling / diffing across firmware.

## Severity model

`CRITICAL` (unauth root: empty/cracked passwords, direct-shell telnetd,
embedded private keys) → `HIGH` → `MEDIUM` → `LOW` → `INFO`. See
`finding.py`.

## Layout

```
fwre/
  __main__.py    python -m fwre
  cli.py         argparse front-end (extract/analyze/run/batch/creds/cvedb/checksec/strings/bootlog/uboot/sbom)
  extract.py     7z driver + magic-locate carve fallback
  elf.py         pure-python ELF parser + checksec (+ .comment, RWX, packed, static dangerous-func scan)
  analyze.py     rootfs orchestrator + credential/secret/binary/attack-surface/IOC analyzers
  services.py    per-service misconfig + web-app sink analyzers (+ TR-069/UPnP/VPN/RTSP/compiled-CGI)
  defaults.py    default/weak credential recovery (+ sudoers / cred-backup files)
  cryptcrack.py  pure-python md5/sha256/sha512 crypt (verified vs test vectors)
  cvedb.py       fingerprints + curated CVE rules
  cvestore.py    cvelistV5 downloader + SQLite index
  bootlog.py     serial boot-log (*.bootlog.txt) parser
  uboot.py       raw-image U-Boot / uImage / env analyzer
  cloud.py       cloud / P2P SDK fingerprinting + CVEs
  certs.py       stdlib X.509 certificate / private-key analyzer
  fsaudit.py     filesystem permission / SUID audit
  busybox.py     BusyBox applet enumeration
  correlate.py   cross-image (fleet) correlation for batch
  sbom.py        CycloneDX SBOM export
  cache.py       cache-dir helper
  finding.py     Finding / Severity model
  report.py      markdown + json renderers
  strings_util.py in-process strings(1)
```

## Notes & caveats

- CVE matches (curated and corpus) are **leads to confirm**, not proof — version
  fingerprints and range logic are heuristic.
- Extraction errors like "Sub items Errors" from 7z on Windows are just device
  nodes it can't create; the rootfs still extracts fine.
- Intended for authorized firmware research on images you own or are permitted
  to analyze.
```
