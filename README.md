# fwre — Linux firmware RE / vulnerability framework

A lightweight framework for reverse-engineering and security-auditing
Linux-based firmware images — IP cameras, routers and other embedded devices
whose `.bin` flash dumps carry a bootloader, one or more `uImage` kernels and a
SquashFS/JFFS2/UBI root filesystem.

The **analysis layer** — where the value is — is pure Python stdlib. Extraction
uses a **built-in, pure-Python SquashFS reader** for the common case (and, being
in-process, it preserves Unix permissions even on Windows), and shells out to
7-Zip / jefferson / ubi_reader for the other filesystem types.

## Requirements

- Python 3.9+
- Extraction backends (`pip install -r requirements.txt` for the Python ones):
  - `dissect.squashfs` — **SquashFS** via the built-in perm-preserving reader
    (the common case for these devices)
  - `7z` on `PATH` — cramfs / ext / gzip and nested archives, plus SquashFS
    fallback (e.g. `scoop install 7zip`, or 7-Zip on Windows)
  - `jefferson` — JFFS2 images
  - `ubi_reader` — UBI / UBIFS images

The analysis core is pure stdlib; the backends above are only used to unpack the
image. The CVE-corpus feature downloads a zip on demand.

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

# rank the unusual / vendor binaries worth opening in a disassembler first
python -m fwre interesting path/to/rootfs

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

A raw flash dump usually holds a bootloader and one or more uImage kernels ahead
of the rootfs, so fwre **locates every filesystem magic** in the image (SquashFS,
UBI, cramfs, JFFS2, ext) and dispatches each candidate to the right extractor
until a Linux rootfs appears:

- **SquashFS** (the common case) -> the **built-in pure-Python reader**
  (`dissect.squashfs`), which records real st_mode/uid/gid/symlinks in a sidecar
  manifest so the permission and SUID audit stays accurate even on Windows.
  Falls back to a carved `[offset:EOF]` slice handed to **7z** if the reader
  can't parse it (or isn't installed)
- **cramfs / ext / gzip** -> carved slice handed to **7z**
- **JFFS2** -> **jefferson** (carved slice)
- **UBI / UBIFS** -> **ubireader_extract_files** (auto-detects wrapped UBI
  geometry, falls back to trying common LEB sizes for a bare UBIFS)

Nested archives found after the first pass are recursed into with 7z. If an image
needs a backend that isn't installed, fwre reports which one to install.

## Build a standalone binary

```bash
build_nuitka.bat     # Windows -> dist\fwre.exe
./build_nuitka.sh    # Linux   -> dist/fwre
```

Both compile the pure-Python `fwre` package with Nuitka into one self-contained
executable. The subprocess backends (7z, jefferson, ubi_reader) are **not**
bundled — keep them on PATH on the target machine. The built-in SquashFS reader
needs `dissect.squashfs` importable at build time to be compiled in.

CI does the same on every push: `.github/workflows/build.yml` builds both
platforms (independently — one failing leg still ships the other), uploads each
binary as a workflow artifact, and on a `v*` tag attaches them to the matching
GitHub release (`fwre-linux-x86_64`, `fwre-windows-x86_64.exe`). A manual run
(`workflow_dispatch`) can target an existing tag.

## Analyzers

fwre runs every analyzer over the extracted rootfs (and, for the boot chain, the
raw image), then merges their output into one severity-ranked finding list. Each
is a self-contained module; here is what each one actually does.

### Credentials & secrets

**`defaults.py` — default / weak credential recovery.** The single
highest-value output. It goes after credentials three ways: it cracks the
`/etc/shadow` (+`passwd`) hashes against a small, high-signal wordlist of
passwords that genuinely ship on IoT/camera BSPs (Ingenic, SigmaStar, Hisilicon,
Xiongmai, Anyka, …) using the in-process crypt below; it matches hashes against a
table of publicly documented vendor default hashes; and it scrapes service
configs and provisioning files for hardcoded logins (web-UI admin pairs, MQTT /
ONVIF / RTSP URLs). Anything recovered in plaintext is collected into its own
table up top.

**`cryptcrack.py` — pure-Python `crypt(3)`.** md5crypt (`$1$`), sha256crypt
(`$5$`) and sha512crypt (`$6$`) implemented to match the glibc reference, so the
hash cracking above works on Windows and on Python 3.13+ (which removed the
stdlib `crypt` module). descrypt/bcrypt/yescrypt are left for hashcat/john.
Verified against canonical test vectors.

**`analyze.py` (credentials).** Parses `/etc/passwd` + `/etc/shadow` and flags
empty passwords (CRITICAL — login with no credentials), non-root accounts with
UID 0, and weak hash schemes (DES crypt, md5crypt), printing the matching hashcat
mode for each.

**`analyze.py` (secrets).** Scans text files *and the insides of ELFs/`.so`* (via
string extraction, for keys baked into cloud/app daemons) for private keys, TLS
certs, cloud/API tokens (AWS access **and** secret keys, GCP, GitHub, JWT,
Alibaba, Slack, Telegram, Tuya), Wi-Fi PSKs and hardcoded `SECRET=…`
assignments. Generic high-entropy candidates pass an entropy gate to cut noise,
and every hit is reported with its exact location.

**`certs.py` — X.509 / private-key analyzer.** A from-scratch stdlib ASN.1/DER
parser (no third-party crypto) that finds every PEM/DER certificate and key in
the rootfs and reads just enough to flag what matters for firmware: weak
signature algorithms (MD5/SHA1), short RSA keys, self-signed device certs, and
expired / not-yet-valid windows. Each cert is fingerprinted (SHA-256 of the DER)
for the cross-image pass, and known TLS-library test vectors are recognised and
softened so they don't drown out real device certs.

### Binaries

**`elf.py` + `analyze.py` — checksec.** A dependency-free ELF parser that reports
arch / endian / bits, static-vs-dynamic, stripped state and the exploit
mitigations (NX, PIE, RELRO, stack canary, FORTIFY, RPATH/RUNPATH) for every
binary, plus its imported symbols so dangerous libc calls are visible. It flags
setuid binaries and network daemons; for statically-linked or stripped blobs
(most BusyBox images) it falls back to a bounded string scan for dangerous-func
names. It also surfaces RWX segments, UPX / other packing, and the `.comment`
toolchain banner.

**`interesting.py` — what to open first.** Most ELFs in an image are boring
(BusyBox, libc, well-known FOSS daemons); the bugs and backdoors live in the
vendor code. This ranks every binary by how much it stands out *from the rest of
this image* — outliers in architecture, toolchain, size and strip-state measured
against the image's own population — combined with absolute tells: proprietary
SDK libraries, packing, RWX, odd filesystem locations, suspicious name tokens,
and heavy dangerous-import use. It points, it doesn't judge: leads for manual RE,
not vulnerabilities. Reuses the checksec parse, no re-parsing.

**`netcalls.py` — network API usage per binary.** Answers *which* binary reaches
the network and *where in it*. It finds BSD socket / resolver / TLS / curl / MQTT
calls and resolves each to the GOT slot address it's called through (`.got` /
`.got.plt`, including the MIPS GOT layout that has no named PLT relocation) so you
can jump straight to the call site in a disassembler. Only *imported*
(SHN_UNDEF) symbols count, so libc's own exported definitions don't create noise.
It flags the classic command-injection shape — a listening socket combined with
`system()`/`exec*()` — and refines the `network_facing` flag on the checksec
table from real imports instead of a filename guess.

**`busybox.py` — applet surface.** These images are usually one static BusyBox
multi-call binary, and the set of applets compiled in defines the real attack
surface. It recovers the applet list from BusyBox's own string table and
cross-checks the `bin/ sbin/ usr/bin/ usr/sbin` symlink farm that actually exposes
them on `$PATH`, flagging the dangerous ones (`telnetd`, `nc`, `tftp`/`tftpd`,
`httpd`, `crond`, `inetd`).

### Services & web attack surface

**`services.py` (service misconfigs).** Parses the config files of the services
that dominate embedded-Linux attack surface — sshd/dropbear, telnet/inetd, FTP
(vsftpd/proftpd/bftpd/pure-ftpd), nginx, lighttpd, apache, boa/goahead,
wpa_supplicant/hostapd, dnsmasq/unbound, samba, mosquitto (MQTT), NTP, SNMP — and
flags insecure settings (permit-root-login, anonymous FTP upload, and so on). It
also covers TR-069/CWMP, UPnP/miniupnpd, OpenVPN/stunnel/IPsec key material,
RTSP/ONVIF auth, and command injection in compiled C `httpd`/CGI binaries.

**`services.py` (web-app sinks).** A lightweight taint tracker for CGI / PHP /
Lua / JS web code: it marks variables assigned (transitively) from request data,
then flags RCE / XSS / SQLi / LFI only when a sink's *own argument* is tainted,
and downgrades when a sanitizer (`escapeshellarg`, `htmlspecialchars`,
parameterised queries, encoding, …) neutralises it — so it is far quieter than
grepping for `system(`. On top of that it catches common PHP/CGI mistakes
(`eval` / `unserialize` / `extract` on request data, `preg_replace /e`, SSRF,
XXE, header/CRLF injection, weak token RNG, `md5` magic-hash auth,
`allow_url_include`, webshell markers) and web-root hygiene issues (`.git`/`.svn`
in the docroot, `.bak`/`config.php` served).

**`analyze.py` (attack surface).** Reads the init path (`inittab`, `init.d/rcS`)
to see which daemons actually start at boot, and flags a `telnetd` wired straight
to a shell, gdbserver / debug shells, and similar drop-to-root surface.

### Network indicators

**`analyze.py` (network IOCs).** Pulls URLs, IPs, MACs and cloud/MQTT/OTA
endpoints out of both text files and binary strings, classifying cleartext-HTTP
OTA/update fetches (HIGH — MITM-to-implant) and P2P/cloud control endpoints
(phone-home infrastructure) distinctly from ordinary URLs. Every hit carries
where it was found: `file:line` in text, `file@0xvaddr (file+0xoffset)` in a
binary.

**`cloud.py` — cloud / P2P SDK fingerprinting.** The real remote surface on a
camera isn't sshd, it's the proprietary video/cloud stack baked into the main
app binary. This fingerprints ThroughTek Kalay/TUTK, Tuya, Gwell/ajcloud (Meari),
Xiongmai XMeye, iLnkP2P/CS2, Anyka and generic MQTT by marker strings across the
binaries, attaches the known high-impact CVEs for each stack (e.g. TUTK
CVE-2021-28372), and records their endpoints as IOCs.

### Components, CVEs & SBOM

**`cvedb.py` — offline fingerprints + curated CVEs.** A small, hand-maintained
knowledge base rather than an NVD mirror: regexes recover component versions from
string banners (busybox, dropbear, openssl, libcurl, wpa_supplicant, hostapd,
lighttpd, dnsmasq, the kernel, …) and a curated rule table flags versions with
well-known, high-impact issues. Always available, fully offline. Treat matches as
leads to confirm, not proof.

**`cvestore.py` — full CVE corpus.** For exhaustive coverage it downloads the
CVEProject cvelistV5 zip once, stream-parses every record straight out of the zip
(no multi-GB extraction to disk) into a compact SQLite index keyed by product,
and does version-range matching on top of the curated rules. Cached and reused
automatically; driven by `fwre cvedb` (see below).

**`sbom.py` — CycloneDX export.** Emits the fingerprinted component/CVE set as a
CycloneDX 1.5 JSON document with purl/CPE identifiers, so results feed standard
supply-chain tooling and diff cleanly across firmware revisions. Standalone
(`fwre sbom`) or `--sbom out.json` alongside `run`/`analyze`.

### Boot chain

**`uboot.py` — raw-image boot chain.** Works directly on the `.bin`, since the
extractor discards everything but the rootfs. It locates U-Boot version banners,
parses legacy uImage headers (magic `0x27051956`: name / load addr / OS / arch /
compression), and carves the U-Boot environment (`bootargs`/`bootcmd`) to flag an
`init=/bin/sh` drop-to-shell or a boot chain with no image verification.
Offset-agnostic struct/string scanning, no external tools.

**`bootlog.py` — serial boot logs.** A serial-console capture (`*.bootlog.txt`,
auto-found next to the image) is gold and usually ignored: it reveals the U-Boot
/ kernel / gcc versions, the MTD partition map, the kernel command line, and
sometimes credentials printed at boot. It parses those out, raises findings for
the risky bits, and feeds the version strings to the CVE fingerprinter so
kernel/U-Boot CVEs land even without a rootfs.

### Filesystem & cross-image

**`fsaudit.py` — permission audit.** Filesystem-wide hygiene on top of checksec:
world-writable files and directories, the full SUID/SGID inventory (scripts as
well as ELFs), writable boot/init scripts (persistence), and
loosely-permissioned key material. Because a 7z extraction on Windows drops Unix
modes, it detects that case and emits an INFO note instead of silently reporting
nothing — which is exactly why the built-in SquashFS reader (which preserves
modes) is preferred.

**`correlate.py` — cross-image (fleet) correlation.** Run in `batch`, a corpus is
worth more than the sum of its scans: the same ODM ships the same secrets across
a whole product line. This cross-links the per-image results to surface *shared*
material — identical `/etc/shadow` hashes, identical embedded certs/keys, reused
recovered passwords, a shared BusyBox build or cloud SDK — so one crack or one
stolen key maps to its full blast radius. Rendered into the batch `SUMMARY.md`.

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

- Console: a colour-coded, severity-sorted finding list (secrets are printed
  with their value and exact location — `path:line` for text, `path @ 0xOFFSET`
  for a key embedded in a binary) + a recovered-credentials table. A `fwRE`
  banner prints at startup. Disable with `--nocolors` / `--nologo` (or
  `NO_COLOR=1`); colour is auto-off when stdout isn't a terminal.
- Every URL/IOC and every network API call is reported **with its exact site**:
  `etc/init.d/rcS:42` for text, `usr/bin/ipc@0x8a55ec (file+0x4a55ec)` for a
  string inside a binary, `usr/bin/ipc@0xa4d098 (GOT)` for a call. The compact
  console list shows the first site; `-v`/`--details` prints the full evidence
  line (all sites) under each finding, and the `-o` report / `--json` output
  always carries them all.

### Interactive post-analysis phases

After the findings print, two optional phases run (console mode only, never with
`--json`):

- **Secret dump** — for each located secret it asks `y/N` whether to dump the
  full material (the whole PEM block for a key at its binary offset) to
  `fwre_secrets/<image>/`. `--dumpsecrets` dumps all without prompting;
  `--skipdumpsecrets` prints a note and skips.
- **Hash crack-assist** — prints each `/etc/shadow` hash and, for **fast** types
  (descrypt/md5crypt), offers to generate a hashcat command and **run** or
  **save** it; **slow** types (sha256/512crypt, bcrypt, yescrypt) only get a
  saved wordlist-based command. Saved scripts are OS-native — `.bat` on Windows,
  `.sh` on Linux. `--crack` saves all non-interactively; `--skipcrack` skips.
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
  cli.py         argparse front-end (extract/analyze/run/batch/creds/cvedb/checksec/interesting/strings/bootlog/uboot/sbom)
  extract.py     built-in squashfs + magic-locate dispatch, 7z/jefferson/ubi_reader backends
  squashfs.py    perm-preserving SquashFS extractor (dissect.squashfs)
  term.py        colour output + figlet banner (--nocolors / --nologo)
  elf.py         pure-python ELF parser + checksec (+ .comment, RWX, packed, static dangerous-func scan)
  interesting.py ranks the unusual / vendor / outlier binaries worth manual RE
  netcalls.py    socket/TLS/HTTP API usage per binary, with GOT addresses
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
  finding.py     Finding / Severity model + Site (file:line / address of evidence)
  report.py      markdown + json renderers
  strings_util.py in-process strings(1) (+ offset-aware extraction)
```

## Notes & caveats

- CVE matches (curated and corpus) are **leads to confirm**, not proof — version
  fingerprints and range logic are heuristic.
- Extraction errors like "Sub items Errors" from 7z on Windows are just device
  nodes it can't create; the rootfs still extracts fine.
- Intended for authorized firmware research on images you own or are permitted
  to analyze.
```
