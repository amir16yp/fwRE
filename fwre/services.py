"""Service-configuration misconfiguration analyzers.

Parses the config files of the network services that dominate embedded-Linux
attack surface and flags insecure settings. Each `check_*` returns Findings.

Covered: sshd/dropbear, telnet, ftp (vsftpd/proftpd/bftpd/pure-ftpd),
nginx, lighttpd, apache/httpd, boa/goahead, wpa_supplicant/hostapd,
unbound/dnsmasq, samba, mosquitto (MQTT), NTP, and generic web-app RCE/XSS
sinks in CGI/Lua/PHP/shell scripts.
"""
from __future__ import annotations

import os
import re

from .finding import Finding, Severity
from . import pem as pemmod


_MAX = 2 * 1024 * 1024


def _read(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(_MAX).decode("latin1", "replace")
    except OSError:
        return ""


def _rel(rootfs: str, p: str) -> str:
    return os.path.relpath(p, rootfs).replace("\\", "/")


def _find_files(rootfs: str, *rel_globs: str) -> list[str]:
    import glob
    out, seen = [], set()
    for g in rel_globs:
        for p in glob.glob(os.path.join(rootfs, g.replace("/", os.sep)),
                           recursive=True):
            # overlapping globs ("etc/openvpn/**/*" and "**/*.ovpn") would
            # otherwise report the same file twice
            if p not in seen and os.path.isfile(p):
                seen.add(p)
                out.append(p)
    return out


def _uncommented(text: str):
    """Yield (lineno, stripped_line) for non-comment, non-blank lines."""
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        yield i, s


# ---------------------------------------------------------------------------
# SSH: OpenSSH sshd_config
# ---------------------------------------------------------------------------

def check_sshd(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/ssh/sshd_config", "etc/sshd_config"):
        rel = _rel(rootfs, p)
        opts = {}
        for _, line in _uncommented(_read(p)):
            m = re.match(r"(\w+)\s+(.+)", line)
            if m:
                opts.setdefault(m.group(1).lower(), m.group(2).strip())
        def v(k): return opts.get(k.lower(), "").lower()
        if v("permitrootlogin") in ("yes", "prohibit-password", ""):
            sev = Severity.HIGH if v("permitrootlogin") == "yes" else Severity.MEDIUM
            f.append(Finding(sev, "svc-ssh",
                             f"PermitRootLogin {opts.get('PermitRootLogin','(default)')}",
                             "root can log in over SSH", rel))
        if v("permitemptypasswords") == "yes":
            f.append(Finding(Severity.CRITICAL, "svc-ssh",
                             "PermitEmptyPasswords yes",
                             "SSH accepts accounts with empty passwords", rel))
        if v("passwordauthentication") == "yes":
            f.append(Finding(Severity.LOW, "svc-ssh",
                             "PasswordAuthentication yes",
                             "password auth enabled (brute-forceable)", rel))
        if v("protocol") == "1":
            f.append(Finding(Severity.HIGH, "svc-ssh", "SSH Protocol 1 enabled",
                             "SSHv1 is cryptographically broken", rel))
        if "yes" in v("x11forwarding"):
            f.append(Finding(Severity.LOW, "svc-ssh", "X11Forwarding yes",
                             "may widen attack surface", rel))
        if v("usedns") == "no":
            pass
        if v("gatewayports") == "yes":
            f.append(Finding(Severity.MEDIUM, "svc-ssh", "GatewayPorts yes",
                             "remote hosts can bind forwarded ports", rel))
    return f


def check_dropbear(rootfs: str) -> list[Finding]:
    """Dropbear is configured via its init args, not a config file."""
    f = []
    for p in _find_files(rootfs, "etc/init.d/*", "etc/*.sh", "etc/rc.local",
                         "etc/inittab"):
        text = _read(p)
        if "dropbear" not in text:
            continue
        rel = _rel(rootfs, p)
        # -B  : disable banner / -s disable password; look for allow-blank-pw
        for _, line in _uncommented(text):
            if "dropbear" not in line:
                continue
            if re.search(r"dropbear[^\n]*\s-B\b", line):
                f.append(Finding(Severity.HIGH, "svc-ssh",
                                 "dropbear started with -B (allow blank passwords)",
                                 line.strip()[:120], rel))
            if re.search(r"dropbear[^\n]*\s-r\s+/tmp", line):
                f.append(Finding(Severity.MEDIUM, "svc-ssh",
                                 "dropbear host key stored under /tmp (regenerated, MITM-able)",
                                 line.strip()[:120], rel))
    # world-accessible authorized_keys / host keys
    for p in _find_files(rootfs, "**/authorized_keys", "etc/dropbear/*",
                         "root/.ssh/*"):
        rel = _rel(rootfs, p)
        base = os.path.basename(p)
        if base == "authorized_keys" and os.path.getsize(p) > 0:
            f.append(Finding(Severity.MEDIUM, "svc-ssh",
                             f"pre-provisioned authorized_keys: {rel}",
                             "hardcoded SSH access key baked into firmware", rel))
        if "key" in base and _read(p).strip():
            if base.endswith(("_key", ".key")) or "host" in base:
                f.append(Finding(Severity.HIGH, "svc-ssh",
                                 f"shared SSH host/private key in firmware: {rel}",
                                 "identical key across all devices - MITM/impersonation",
                                 rel))
    return f


# ---------------------------------------------------------------------------
# telnet / inetd
# ---------------------------------------------------------------------------

def check_telnet_inetd(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/inetd.conf", "etc/xinetd.conf",
                         "etc/xinetd.d/*"):
        rel = _rel(rootfs, p)
        text = _read(p)
        for _, line in _uncommented(text):
            low = line.lower()
            if "telnet" in low:
                f.append(Finding(Severity.HIGH, "svc-telnet",
                                 "telnet enabled via inetd/xinetd",
                                 line[:120], rel))
            if re.search(r"\b(shell|exec|login|rsh|rlogin)\b", low) and "stream" in low:
                f.append(Finding(Severity.HIGH, "svc-telnet",
                                 "legacy r-service (rsh/rexec/rlogin) enabled",
                                 line[:120], rel))
            if "-l /bin/sh" in low or "-l/bin/sh" in low:
                f.append(Finding(Severity.CRITICAL, "svc-telnet",
                                 "telnetd bound directly to a shell (unauth root)",
                                 line[:120], rel))
    # telnetd started with autologin / no login program
    for p in _find_files(rootfs, "etc/init.d/*", "etc/rc.local", "etc/inittab",
                         "etc/*.sh"):
        text = _read(p)
        if "telnetd" not in text:
            continue
        rel = _rel(rootfs, p)
        for _, line in _uncommented(text):
            if "telnetd" in line and re.search(r"-l\s+/bin/(?:sh|ash)", line):
                f.append(Finding(Severity.CRITICAL, "svc-telnet",
                                 "telnetd -l /bin/sh - direct root shell, no auth",
                                 line[:120], rel))
    return f


# ---------------------------------------------------------------------------
# FTP: vsftpd / proftpd / bftpd / pure-ftpd
# ---------------------------------------------------------------------------

def check_ftp(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/vsftpd.conf", "etc/vsftpd/vsftpd.conf"):
        rel = _rel(rootfs, p)
        opts = dict((k.lower(), v) for k, v in
                    (re.match(r"(\w+)\s*=\s*(.*)", ln).groups()
                     for _, ln in _uncommented(_read(p))
                     if re.match(r"(\w+)\s*=\s*(.*)", ln)))
        if opts.get("anonymous_enable", "").upper() == "YES":
            f.append(Finding(Severity.HIGH, "svc-ftp",
                             "vsftpd anonymous access enabled", path=rel))
        if opts.get("anon_upload_enable", "").upper() == "YES":
            f.append(Finding(Severity.CRITICAL, "svc-ftp",
                             "vsftpd anonymous upload enabled (drop webshell)",
                             path=rel))
        if opts.get("chroot_local_user", "").upper() != "YES":
            f.append(Finding(Severity.MEDIUM, "svc-ftp",
                             "vsftpd users not chrooted (filesystem traversal)",
                             path=rel))
        if opts.get("ssl_enable", "").upper() != "YES":
            f.append(Finding(Severity.LOW, "svc-ftp",
                             "vsftpd runs without TLS (cleartext creds)", path=rel))
    for p in _find_files(rootfs, "etc/proftpd.conf", "etc/proftpd/*.conf"):
        rel = _rel(rootfs, p)
        text = _read(p).lower()
        if "<anonymous" in text:
            f.append(Finding(Severity.HIGH, "svc-ftp",
                             "proftpd anonymous block present", path=rel))
        if "requirevalidshell off" in text:
            f.append(Finding(Severity.MEDIUM, "svc-ftp",
                             "proftpd RequireValidShell off", path=rel))
    for p in _find_files(rootfs, "etc/bftpd.conf"):
        rel = _rel(rootfs, p)
        text = _read(p).lower()
        if "anonymous_enable" in text and "yes" in text:
            f.append(Finding(Severity.HIGH, "svc-ftp",
                             "bftpd anonymous access enabled", path=rel))
    return f


# ---------------------------------------------------------------------------
# Web servers: nginx / lighttpd / apache / boa / goahead
# ---------------------------------------------------------------------------

def check_nginx(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/nginx/**/*.conf", "etc/nginx/nginx.conf",
                         "usr/local/nginx/conf/*.conf"):
        rel = _rel(rootfs, p)
        text = _read(p)
        low = text.lower()
        if "autoindex on" in low:
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "nginx autoindex on (directory listing)", path=rel))
        if "server_tokens on" in low or "server_tokens" not in low:
            f.append(Finding(Severity.LOW, "svc-web",
                             "nginx server_tokens not disabled (version leak)",
                             path=rel))
        # classic alias traversal / off-by-slash
        if re.search(r"location\s+/\w+\s*\{[^}]*\balias\b", low, re.S):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "nginx location+alias - check off-by-slash path traversal",
                             path=rel))
        # SSRF-prone proxy_pass with variable
        if re.search(r"proxy_pass\s+https?://\$", low):
            f.append(Finding(Severity.HIGH, "svc-web",
                             "nginx proxy_pass to a variable (SSRF / request smuggling)",
                             path=rel))
        # fastcgi passing raw SCRIPT_FILENAME → PHP RCE (cgi.fix_pathinfo)
        if "fastcgi_pass" in low and "fastcgi_split_path_info" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "nginx fastcgi without split_path_info (PHP path-info RCE class)",
                             path=rel))
        if re.search(r"add_header\s+.*['\"]?\*", low) and "access-control-allow-origin" in low:
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "nginx CORS Access-Control-Allow-Origin: *", path=rel))
        if "ssl_protocols" in low and re.search(r"ssl_protocols[^;]*(sslv3|tlsv1(\.0)?)\b", low):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "nginx enables obsolete TLS/SSL protocol", path=rel))
    return f


def check_lighttpd(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/lighttpd/**/*.conf", "etc/lighttpd.conf",
                         "etc/lighttpd/lighttpd.conf"):
        rel = _rel(rootfs, p)
        text = _read(p)
        low = text.lower()
        if "dir-listing.activate" in low and '"enable"' in low:
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "lighttpd dir-listing enabled", path=rel))
        if "mod_cgi" in low or "cgi.assign" in low:
            f.append(Finding(Severity.LOW, "svc-web",
                             "lighttpd mod_cgi enabled - audit CGI handlers for RCE",
                             path=rel))
        if re.search(r'server\.username\s*=\s*"root"', low):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "lighttpd configured to run as root (server.username root)",
                             path=rel))
        if "ssl.pemfile" in low and "ssl.engine" in low:
            pass
        if re.search(r'setenv\.add-response-header.*access-control-allow-origin.*\*', low):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "lighttpd CORS wildcard", path=rel))
    return f


def check_apache(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/apache2/**/*.conf", "etc/httpd/**/*.conf",
                         "etc/apache2/apache2.conf", "etc/httpd/httpd.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if re.search(r"options[^\n]*\bindexes\b", low):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "apache Options Indexes (directory listing)", path=rel))
        if re.search(r"options[^\n]*\bincludes\b", low) and "includesnoexec" not in low:
            f.append(Finding(Severity.HIGH, "svc-web",
                             "apache SSI +Includes enabled (SSI injection → RCE)",
                             path=rel))
        if "allowoverride all" in low:
            f.append(Finding(Severity.LOW, "svc-web",
                             "apache AllowOverride All (.htaccess-driven config)",
                             path=rel))
        if re.search(r"<limitexcept\b", low) is None and "require all granted" in low:
            f.append(Finding(Severity.LOW, "svc-web",
                             "apache 'Require all granted' - verify scope", path=rel))
        if "traceenable on" in low or "traceenable" not in low:
            f.append(Finding(Severity.LOW, "svc-web",
                             "apache TraceEnable not disabled (XST)", path=rel))
        if re.search(r'header set access-control-allow-origin\s+"?\*', low):
            f.append(Finding(Severity.MEDIUM, "svc-web",
                             "apache CORS wildcard", path=rel))
    return f


def check_boa_goahead(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/boa/*", "etc/boa.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        f.append(Finding(Severity.MEDIUM, "svc-web",
                         "boa web server present (EOL, CVE-2017-9833 traversal class)",
                         path=rel))
        if "user root" in low or "group root" in low:
            f.append(Finding(Severity.HIGH, "svc-web",
                             "boa running as root", path=rel))
    if _find_files(rootfs, "**/goahead", "usr/sbin/goahead", "bin/goahead"):
        f.append(Finding(Severity.MEDIUM, "svc-web",
                         "GoAhead web server present - audit CGI (CVE-2017-17562 RCE)",
                         path="goahead"))
    return f


# ---------------------------------------------------------------------------
# Wi-Fi: wpa_supplicant / hostapd
# ---------------------------------------------------------------------------

def check_wifi(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/wpa_supplicant.conf",
                         "etc/wpa_supplicant/*.conf", "**/wpa_supplicant*.conf"):
        rel = _rel(rootfs, p)
        text = _read(p)
        for m in re.finditer(r'psk\s*=\s*"?([^"\n]+)"?', text):
            f.append(Finding(Severity.HIGH, "svc-wifi",
                             "plaintext Wi-Fi PSK in wpa_supplicant.conf",
                             m.group(1)[:40], rel))
        if re.search(r'key_mgmt\s*=\s*NONE', text):
            f.append(Finding(Severity.MEDIUM, "svc-wifi",
                             "wpa_supplicant key_mgmt=NONE (open network)", path=rel))
        if "ctrl_interface" in text and "GROUP" not in text:
            f.append(Finding(Severity.LOW, "svc-wifi",
                             "wpa_supplicant ctrl_interface without GROUP restriction",
                             path=rel))
        if re.search(r'update_config\s*=\s*1', text):
            f.append(Finding(Severity.LOW, "svc-wifi",
                             "wpa_supplicant update_config=1 (runtime cred writes)",
                             path=rel))
    for p in _find_files(rootfs, "etc/hostapd*.conf", "etc/hostapd/*.conf"):
        rel = _rel(rootfs, p)
        text = _read(p)
        for m in re.finditer(r'wpa_passphrase\s*=\s*(.+)', text):
            f.append(Finding(Severity.HIGH, "svc-wifi",
                             "hardcoded AP passphrase in hostapd.conf",
                             m.group(1).strip()[:40], rel))
        if re.search(r'wpa\s*=\s*0', text) or re.search(r'auth_algs\s*=\s*0', text):
            f.append(Finding(Severity.MEDIUM, "svc-wifi",
                             "hostapd open/unencrypted AP configuration", path=rel))
        if re.search(r'wps_state\s*=\s*[12]', text):
            f.append(Finding(Severity.MEDIUM, "svc-wifi",
                             "hostapd WPS enabled (PIN brute-force / Pixie-Dust)",
                             path=rel))
    return f


# ---------------------------------------------------------------------------
# DNS: unbound / dnsmasq
# ---------------------------------------------------------------------------

def check_dns(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/unbound/unbound.conf", "etc/unbound.conf",
                         "etc/unbound/**/*.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if re.search(r'access-control:\s*0\.0\.0\.0/0\s+allow', low):
            f.append(Finding(Severity.HIGH, "svc-dns",
                             "unbound open resolver (access-control allows 0.0.0.0/0) - DDoS amp",
                             path=rel))
        if "interface: 0.0.0.0" in low and "access-control" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-dns",
                             "unbound listening on all interfaces w/o access-control",
                             path=rel))
        if "control-enable: yes" in low and "control-interface: 127" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-dns",
                             "unbound-control exposed beyond localhost", path=rel))
    for p in _find_files(rootfs, "etc/dnsmasq.conf", "etc/dnsmasq.d/*"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "no-dhcp-interface" not in low and re.search(r'^\s*interface=', low, re.M) is None \
                and "bind-interfaces" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-dns",
                             "dnsmasq not bound to a specific interface (possible open resolver)",
                             path=rel))
        if "dhcp-boot" in low or "enable-tftp" in low:
            f.append(Finding(Severity.LOW, "svc-dns",
                             "dnsmasq TFTP/PXE enabled - extra attack surface", path=rel))
    return f


# ---------------------------------------------------------------------------
# Samba / mosquitto (MQTT) / NTP / SNMP
# ---------------------------------------------------------------------------

def check_misc_services(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/samba/smb.conf", "etc/smb.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "guest ok = yes" in low or "map to guest" in low:
            f.append(Finding(Severity.HIGH, "svc-smb",
                             "samba guest access enabled", path=rel))
        if "security = share" in low:
            f.append(Finding(Severity.HIGH, "svc-smb",
                             "samba share-level security (legacy, unauth)", path=rel))
        if "min protocol" not in low or "smb1" in low or "nt1" in low:
            f.append(Finding(Severity.MEDIUM, "svc-smb",
                             "samba SMB1/NT1 not disabled (EternalBlue-era protocol)",
                             path=rel))
    for p in _find_files(rootfs, "etc/mosquitto/mosquitto.conf",
                         "etc/mosquitto.conf", "etc/mosquitto/conf.d/*"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "allow_anonymous true" in low or ("allow_anonymous" not in low):
            f.append(Finding(Severity.HIGH, "svc-mqtt",
                             "mosquitto allows anonymous MQTT clients", path=rel))
        if "password_file" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-mqtt",
                             "mosquitto without password_file (no auth)", path=rel))
    for p in _find_files(rootfs, "etc/snmp/snmpd.conf", "etc/snmpd.conf"):
        rel = _rel(rootfs, p)
        text = _read(p)
        for m in re.finditer(r'(?im)^\s*(?:rocommunity|rwcommunity)\s+(\S+)', text):
            comm = m.group(1)
            sev = Severity.CRITICAL if comm.lower() in ("public", "private") else Severity.HIGH
            f.append(Finding(sev, "svc-snmp",
                             f"SNMP community string '{comm}' configured",
                             "SNMP v1/v2c community leaks device info / config", rel))
    for p in _find_files(rootfs, "etc/ntp.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "restrict" not in low:
            f.append(Finding(Severity.MEDIUM, "svc-ntp",
                             "ntpd without restrict lines (monlist/amplification risk)",
                             path=rel))
    return f


# ---------------------------------------------------------------------------
# Web-app source: CGI / Lua / PHP / shell - RCE & XSS sinks
# ---------------------------------------------------------------------------

# command-execution sinks fed by request data
_RCE_SINKS = [
    (re.compile(r'\bsystem\s*\('), "system()"),
    (re.compile(r'\bpopen\s*\('), "popen()"),
    (re.compile(r'\bexec[lv][ep]?\s*\('), "exec()"),
    (re.compile(r'\b(?:os\.system|os\.popen|subprocess\.(?:call|Popen|run|check_output))\s*\('),
     "python exec"),
    (re.compile(r'\bos\.execute\s*\('), "lua os.execute"),
    (re.compile(r'\bio\.popen\s*\('), "lua io.popen"),
    (re.compile(r'\b(?:loadstring|load)\s*\('), "lua loadstring"),
    (re.compile(r'\beval\s*\('), "eval()"),
    (re.compile(r'\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s*\('), "php cmd exec"),
    (re.compile(r'\bassert\s*\('), "php assert() (RCE)"),
    (re.compile(r'\bcreate_function\s*\('), "php create_function() (RCE)"),
    (re.compile(r'\bchild_process\.(?:exec|execSync|spawn)\s*\('), "node child_process"),
    (re.compile(r'\bnew\s+Function\s*\('), "js new Function()"),
    (re.compile(r'`[^`]*\$'), "backtick w/ variable"),
    (re.compile(r'\bopen\s*\([^)]*\|'), "perl 2-arg open() pipe"),
]
# request-data sources (taint origins), broadened across languages
_REQ_SOURCES = re.compile(
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|'
    r'\bQUERY_STRING\b|\bHTTP_[A-Z_]+\b|\bCONTENT_LENGTH\b|\bREQUEST_METHOD\b|'
    r'\bgetenv\s*\(|\$_SERVER\[|php://input|\$ENV\{|\bargv\b|'
    r'\breq\.(?:query|body|params|cookies|headers)\b|\bparams\[|'
    r'\bngx\.var\b|\bgetvalue\s*\(|\bFORM\[|\bhaserl',
    re.I)
_SOURCE_TOKEN = re.compile(
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\bgetenv\s*\(|\$_SERVER\[|'
    r'php://input|\bQUERY_STRING\b|\bHTTP_[A-Z_]+\b|\$ENV\{|\breq\.(?:query|body|params)\b|'
    r'\bngx\.var\b', re.I)
# validation/encoding that neutralises tainted data (presence -> downgrade)
_SANITIZERS = re.compile(
    r'\b(?:escapeshellarg|escapeshellcmd|htmlspecialchars|htmlentities|intval|'
    r'floatval|ctype_[a-z]+|is_numeric|preg_match|filter_var|filter_input|'
    r'basename|realpath|addslashes|mysqli?_real_escape_string|pg_escape_\w+|'
    r'urlencode|rawurlencode|json_encode|quotemeta|str_replace|sprintf\s*\(\s*["\']%d)',
    re.I)
# XSS output sinks
_XSS_SINKS = [
    (re.compile(r'\becho\b[^;]*'), "php echo"),
    (re.compile(r'\bprint(?:f)?\s*\([^)]*'), "php print"),
    (re.compile(r'document\.write\s*\([^)]*'), "js document.write"),
    (re.compile(r'\.innerHTML\s*=\s*[^;]*'), "js innerHTML"),
    (re.compile(r'\bdangerouslySetInnerHTML\b[^;]*'), "react dangerouslySetInnerHTML"),
    (re.compile(r'\$\([^)]*\)\.html\s*\([^)]*'), "jquery .html()"),
]
# SQL query builders
_SQL_SINKS = re.compile(
    r'\b(?:mysqli?_query|mysqli_?->?query|pg_query|sqlite_query|->query|->exec|'
    r'db\.query|execute)\s*\(', re.I)
_SQL_TEXT = re.compile(r'(?i)\b(?:select|insert|update|delete|union)\b')
# file operations (LFI / traversal)
_FILE_SINKS = re.compile(
    r'\b(?:fopen|file_get_contents|readfile|include|include_once|require|'
    r'require_once|show_source|highlight_file|fpassthru|sendfile|open|io\.open)\s*\(')

_SCRIPT_EXT = {".cgi", ".sh", ".lua", ".php", ".php3", ".php5", ".phtml",
               ".pl", ".py", ".js", ".asp", ".aspx", ".jsp", ".htm", ".html"}
_WEBROOT_HINTS = ("cgi-bin", "www", "webroot", "htdocs", "web", "html", "wsgi",
                  "goahead", "lighttpd", "nginx", "webs", "mongoose", "boa")


def _matching_paren(text: str, open_idx: int, limit: int = 400) -> str:
    """Return the argument text inside the call whose '(' is at open_idx."""
    depth = 0
    end = min(len(text), open_idx + limit)
    for i in range(open_idx, end):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
    return text[open_idx + 1:end]


def _taint_vars(text: str) -> set[str]:
    """Lightweight taint: variables assigned (transitively) from a request
    source. Handles `$c = $_GET['x']` and `$d = $c . '/x'` chains."""
    tainted: set[str] = set()
    assigns = re.findall(r'(\$[A-Za-z_]\w*)\s*=\s*([^;\n]{0,200})', text)
    for _ in range(3):  # fixpoint over a few passes for chained assignments
        changed = False
        for var, rhs in assigns:
            if var in tainted:
                continue
            if _SOURCE_TOKEN.search(rhs) or any(t in rhs for t in tainted):
                tainted.add(var)
                changed = True
        if not changed:
            break
    return tainted


def _arg_tainted(arg: str, tainted: set[str]) -> bool:
    if _SOURCE_TOKEN.search(arg):
        return True
    return any(re.search(re.escape(t) + r'\b', arg) for t in tainted)


def check_webapp_sinks(rootfs: str) -> list[Finding]:
    f = []
    seen = set()
    for dirpath, _, files in os.walk(rootfs):
        low_dir = dirpath.lower()
        in_webish = any(h in low_dir for h in _WEBROOT_HINTS)
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _SCRIPT_EXT and not (in_webish and ext == ""):
                continue
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > _MAX:
                    continue
            except OSError:
                continue
            text = _read(p)
            rel = _rel(rootfs, p)
            has_source = bool(_REQ_SOURCES.search(text))
            tainted = _taint_vars(text) if has_source else set()

            def emit(sev, cat, key, title, detail):
                k = (rel, key)
                if k in seen:
                    return
                seen.add(k)
                f.append(Finding(sev, cat, title, f"{detail}  @ {rel}", rel))

            # --- RCE: only flag a sink whose OWN ARGUMENT is tainted ---------
            for pat, label in _RCE_SINKS:
                for m in pat.finditer(text):
                    op = text.find("(", m.start())
                    if label.startswith(("backtick", "perl")):
                        arg = m.group(0)
                    elif op < 0:
                        continue
                    else:
                        arg = _matching_paren(text, op)
                    if _arg_tainted(arg, tainted):
                        if _SANITIZERS.search(arg):
                            emit(Severity.MEDIUM, "webapp-rce", f"rce-s:{label}",
                                 f"{label} on request data (a sanitiser is present - verify it covers this path)",
                                 arg.strip()[:100])
                        else:
                            emit(Severity.HIGH, "webapp-rce", f"rce:{label}",
                                 f"{label} executes request-controlled data (command/code injection)",
                                 arg.strip()[:100])
                    elif in_webish and label in ("eval()", "php assert() (RCE)",
                                                 "lua loadstring", "js new Function()"):
                        emit(Severity.LOW, "webapp-rce", f"rce-w:{label}",
                             f"dynamic-eval sink {label} in web script", "review for tainted input")

            # --- XSS: output sink whose argument is tainted -----------------
            for pat, label in _XSS_SINKS:
                for m in pat.finditer(text):
                    seg = m.group(0)
                    if _arg_tainted(seg, tainted):
                        if re.search(r'htmlspecialchars|htmlentities|json_encode|urlencode', seg, re.I):
                            continue  # encoded output
                        emit(Severity.MEDIUM, "webapp-xss", f"xss:{label}",
                             f"reflected XSS: {label} emits request data unencoded",
                             seg.strip()[:100])
                        break
            # PHP_SELF / SCRIPT_NAME reflected without encoding
            if re.search(r'\becho\b[^;]*\$_SERVER\[[\'"]?(?:PHP_SELF|REQUEST_URI|SCRIPT_NAME)', text):
                emit(Severity.MEDIUM, "webapp-xss", "xss:php_self",
                     "PHP_SELF/REQUEST_URI echoed unencoded (reflected XSS)", "")

            # --- SQLi: query call + SQL keyword + tainted arg ---------------
            for m in _SQL_SINKS.finditer(text):
                op = text.find("(", m.start())
                if op < 0:
                    continue
                arg = _matching_paren(text, op)
                # a query sink is SQL by definition, so a request-tainted arg
                # (direct concat OR a tainted var built earlier) is enough
                if _arg_tainted(arg, tainted):
                    if re.search(r'real_escape|pg_escape|\bbindParam\b|\bbindValue\b|\?\s*[,)]', arg, re.I):
                        continue  # parameterised / escaped
                    emit(Severity.HIGH, "webapp-sqli", "sqli",
                         "request data reaches a SQL query sink (SQL injection)",
                         arg.strip()[:100])
                    break
            else:
                # string-built query even without a recognised sink call
                if has_source and re.search(
                        r'(?i)["\'](?:[^"\']*)(?:select|insert|update|delete)\b[^"\']*["\']?\s*\.\s*\$',
                        text) and _arg_tainted(text, tainted):
                    emit(Severity.MEDIUM, "webapp-sqli", "sqli2",
                         "SQL string concatenated with a variable (possible SQLi)", "")

            # --- LFI / path traversal ---------------------------------------
            for m in _FILE_SINKS.finditer(text):
                op = text.find("(", m.start())
                if op < 0:
                    continue
                arg = _matching_paren(text, op)
                if _arg_tainted(arg, tainted):
                    if re.search(r'\bbasename\s*\(|\brealpath\s*\(', arg):
                        sev = Severity.LOW
                        note = "path is basename/realpath-normalised - verify traversal is blocked"
                    else:
                        sev = Severity.HIGH if re.search(r'include|require', m.group(0)) \
                            else Severity.MEDIUM
                        note = "request-controlled file path (path traversal / LFI / RFI)"
                    emit(sev, "webapp-lfi", "lfi", note, arg.strip()[:100])
                    break
    return f


# ---------------------------------------------------------------------------
# TR-069 / CWMP remote management
# ---------------------------------------------------------------------------

def check_tr069(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/**/*.conf", "etc/tr069/*", "**/cwmp*.conf",
                         "**/tr069*.conf", "**/*acs*.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "cwmp" not in low and "tr069" not in low and "acs" not in low \
                and "connectionrequest" not in low:
            continue
        f.append(Finding(Severity.MEDIUM, "svc-tr069",
                         "TR-069/CWMP remote-management config present",
                         "carrier/ODM can push config & firmware - CVE-2014-9222 "
                         "'Misfortune Cookie' class if RomPager-based", rel))
        for m in re.finditer(r'(?im)(?:acs|connectionrequest)?(?:username|password)\s*[:=]\s*(\S+)', low):
            if m.group(1) not in ("", '""', "''"):
                f.append(Finding(Severity.HIGH, "svc-tr069",
                                 "hardcoded TR-069 ACS credential", m.group(0)[:80], rel))
                break
    return f


# ---------------------------------------------------------------------------
# UPnP / miniupnpd - port mapping / IGD
# ---------------------------------------------------------------------------

def check_upnp(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/miniupnpd*.conf", "etc/miniupnpd/*.conf",
                         "etc/upnpd.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        f.append(Finding(Severity.MEDIUM, "svc-upnp",
                         "miniupnpd/UPnP IGD present - automatic firewall pinholing",
                         "malware/LAN peers can self-expose ports to the WAN", rel))
        if "secure_mode=no" in low or ("secure_mode" not in low):
            f.append(Finding(Severity.MEDIUM, "svc-upnp",
                             "miniupnpd secure_mode not enabled (map arbitrary hosts)",
                             path=rel))
    if _find_files(rootfs, "**/wsdd", "**/wscd", "usr/sbin/*upnp*", "bin/*upnp*"):
        f.append(Finding(Severity.LOW, "svc-upnp",
                         "UPnP/WS-Discovery daemon present", path="upnp"))
    return f


# ---------------------------------------------------------------------------
# VPN / TLS tunnels - embedded keys
# ---------------------------------------------------------------------------

def check_vpn_tls(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/openvpn/**/*", "etc/openvpn/*.conf",
                         "**/*.ovpn"):
        rel = _rel(rootfs, p)
        text = _read(p)
        # a whole PEM block - not just the BEGIN banner, which also shows up
        # in commented-out sample configs and in the inline <key> template
        if pemmod.has_key(text):
            f.append(Finding(Severity.HIGH, "svc-vpn",
                             "OpenVPN config with an embedded private key", path=rel))
        if re.search(r'(?im)^\s*auth-user-pass\s+\S+', text):
            f.append(Finding(Severity.MEDIUM, "svc-vpn",
                             "OpenVPN auth-user-pass points at a stored cred file",
                             path=rel))
    for p in _find_files(rootfs, "etc/stunnel/*.conf", "etc/stunnel.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "cert" in low or "key" in low:
            f.append(Finding(Severity.MEDIUM, "svc-vpn",
                             "stunnel TLS tunnel config present (check embedded key)",
                             path=rel))
    for p in _find_files(rootfs, "etc/ipsec.secrets", "etc/ipsec.conf"):
        rel = _rel(rootfs, p)
        if _read(p).strip():
            f.append(Finding(Severity.HIGH, "svc-vpn",
                             "IPsec secrets/config present (PSK or key material)",
                             path=rel))
    return f


# ---------------------------------------------------------------------------
# RTSP / ONVIF - camera media plane
# ---------------------------------------------------------------------------

def check_rtsp_onvif(rootfs: str) -> list[Finding]:
    f = []
    for p in _find_files(rootfs, "etc/**/*.conf", "etc/**/*.cfg", "**/rtsp*.conf",
                         "**/onvif*.conf", "**/*media*.conf"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if "rtsp" in low:
            if re.search(r'(?:auth|authentication|need_auth)\s*[:=]\s*(?:0|off|false|no|none)', low):
                f.append(Finding(Severity.HIGH, "svc-rtsp",
                                 "RTSP authentication disabled - open video stream",
                                 path=rel))
            if re.search(r'rtsp://[^:@\s]+:[^@\s]+@', low):
                f.append(Finding(Severity.HIGH, "svc-rtsp",
                                 "hardcoded RTSP credentials in config", path=rel))
        if "onvif" in low and re.search(r'(?:auth|ws-security|wsse)\s*[:=]\s*(?:0|off|false|no)', low):
            f.append(Finding(Severity.HIGH, "svc-onvif",
                             "ONVIF WS-Security/auth disabled", path=rel))
    return f


# ---------------------------------------------------------------------------
# Compiled CGI (C) - request-data → command sinks in the httpd binary itself
# ---------------------------------------------------------------------------

def check_cgi_binaries(rootfs: str) -> list[Finding]:
    from . import elf as elfmod
    from .strings_util import strings_file
    f = []
    import glob
    cands: set[str] = set()
    for g in ("www/**/*", "**/cgi-bin/*", "**/webs*", "usr/sbin/httpd",
              "bin/httpd", "usr/sbin/goahead", "**/*.cgi"):
        for p in glob.glob(os.path.join(rootfs, g.replace("/", os.sep)),
                           recursive=True):
            if os.path.isfile(p):
                cands.add(p)
    for p in sorted(cands):
        if not elfmod.is_elf(p):
            continue
        try:
            if os.path.getsize(p) > 32 * 1024 * 1024:
                continue
        except OSError:
            continue
        rel = _rel(rootfs, p)
        blob = "\n".join(strings_file(p, min_len=5, max_read=32 * 1024 * 1024))
        low = blob.lower()
        has_src = ("query_string" in low or "content_length" in low
                   or "request_method" in low)
        has_sink = bool(re.search(r'\b(system|popen|execve?|exec[lv][ep]?)\b', low))
        if has_src and has_sink:
            f.append(Finding(Severity.HIGH, "webapp-rce",
                             f"compiled CGI '{os.path.basename(rel)}' mixes CGI env "
                             f"with a shell-exec sink",
                             "trace QUERY_STRING/CONTENT_* into system()/exec - "
                             "classic camera httpd command injection", rel))
    return f


# ---------------------------------------------------------------------------
# Common PHP / CGI mistakes (dangerous constructs + webshell/backdoor markers)
# ---------------------------------------------------------------------------

# (compiled regex, severity, label). Each is a well-known footgun in embedded
# web UIs; matches are leads to confirm, not proof.
_PHP_RULES = [
    (re.compile(r'\bpreg_replace\s*\(\s*[\'"][^\'"]*/[a-zA-Z]*e[a-zA-Z]*[\'"]'),
     Severity.HIGH, "preg_replace /e modifier (code execution)"),
    (re.compile(r'\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'),
     Severity.HIGH, "unserialize() of request data (PHP object injection)"),
    (re.compile(r'\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)'),
     Severity.HIGH, "extract() of request data (variable overwrite)"),
    (re.compile(r'\b(?:include|include_once|require|require_once)\s*'
                r'(?:\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)'),
     Severity.HIGH, "include/require of request data (LFI/RFI)"),
    (re.compile(r'\beval\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|'
                r'gzinflate|str_rot13)'),
     Severity.CRITICAL, "eval() of request/obfuscated data (RCE / webshell)"),
    (re.compile(r'\b(?:assert|create_function)\s*\(\s*\$_(?:GET|POST|REQUEST)'),
     Severity.CRITICAL, "assert()/create_function() on request data (RCE)"),
    (re.compile(r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\('
                r'[^;)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)'),
     Severity.CRITICAL, "shell exec of request data (command injection)"),
    (re.compile(r'\bcall_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST)'),
     Severity.HIGH, "call_user_func() with request-controlled name"),
    (re.compile(r'\bmove_uploaded_file\s*\('),
     Severity.MEDIUM, "file upload handler (move_uploaded_file) - check type/path"),
    (re.compile(r'\b(?:file_get_contents|fopen|readfile|file)\s*\(\s*'
                r'\$_(?:GET|POST|REQUEST|COOKIE)'),
     Severity.HIGH, "file read on request-controlled path (LFI/SSRF)"),
    (re.compile(r'\bheader\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*\$_'),
     Severity.MEDIUM, "header('Location:') from request data (open redirect)"),
    (re.compile(r'==\s*\bmd5\s*\(|\bmd5\s*\([^)]*\)\s*=='),
     Severity.MEDIUM, "loose == comparison on md5() (PHP magic-hash auth bypass)"),
    (re.compile(r'\$\$[a-zA-Z_]'),
     Severity.LOW, "variable variables ($$x) - audit for injection"),
    (re.compile(r'\bphpinfo\s*\(\s*\)'),
     Severity.LOW, "phpinfo() present (information disclosure)"),
    (re.compile(r'@\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\('),
     Severity.CRITICAL, "@$_REQUEST[...]() dynamic call (classic PHP webshell)"),
    # --- info disclosure ---------------------------------------------------
    (re.compile(r'\b(?:var_dump|print_r|var_export)\s*\(\s*\$_(?:GET|POST|REQUEST|SERVER)'),
     Severity.LOW, "var_dump/print_r of request/server data (info disclosure)"),
    (re.compile(r'\becho\b[^;]*\$_SERVER\[[\'"]?PHP_SELF'),
     Severity.MEDIUM, "PHP_SELF echoed (reflected XSS)"),
    # --- SSRF / RFI --------------------------------------------------------
    (re.compile(r'\b(?:curl_setopt[^;]*CURLOPT_URL|fsockopen|stream_socket_client|'
                r'file_get_contents)\s*\([^;]*\$_(?:GET|POST|REQUEST)'),
     Severity.HIGH, "outbound request to request-controlled URL (SSRF)"),
    # --- XXE ---------------------------------------------------------------
    (re.compile(r'\blibxml_disable_entity_loader\s*\(\s*false\s*\)'),
     Severity.HIGH, "libxml_disable_entity_loader(false) - XXE enabled"),
    (re.compile(r'\b(?:simplexml_load_string|simplexml_load_file|DOMDocument'
                r'[^;]*->load)[^;]*(?:LIBXML_NOENT|\$_(?:GET|POST|REQUEST))'),
     Severity.HIGH, "XML parse of request data with entities (XXE)"),
    # --- HTTP header / CRLF injection --------------------------------------
    (re.compile(r'\bheader\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)'),
     Severity.MEDIUM, "header() built from request data (HTTP response splitting)"),
    (re.compile(r'\bsetcookie\s*\([^)]*\$_(?:GET|POST|REQUEST)'),
     Severity.LOW, "setcookie() value from request data"),
    # --- weak crypto / RNG for security tokens -----------------------------
    (re.compile(r'\b(?:session_id|token|csrf|nonce|salt|password)\b[^;\n]{0,40}'
                r'\b(?:mt_rand|rand|uniqid|microtime)\s*\(', re.I),
     Severity.MEDIUM, "predictable RNG (rand/uniqid) used for a security token"),
    (re.compile(r'\b(?:password|passwd|pwd)\b[^;\n]{0,20}\b(?:md5|sha1)\s*\(', re.I),
     Severity.MEDIUM, "password hashed with md5/sha1 (fast, unsalted - crackable)"),
    (re.compile(r'\bmcrypt_\w+\s*\('),
     Severity.LOW, "mcrypt used (removed/insecure crypto API)"),
    # --- request-var pollution / auth --------------------------------------
    (re.compile(r'\bparse_str\s*\(\s*\$_SERVER\[[\'"]?QUERY_STRING[\'"]?\]\s*\)'),
     Severity.HIGH, "parse_str() without result array (register_globals-style overwrite)"),
    (re.compile(r'\bimport_request_variables\s*\('),
     Severity.HIGH, "import_request_variables() (request->global overwrite)"),
    (re.compile(r'\bstrcmp\s*\([^)]*\$_(?:GET|POST|REQUEST)[^)]*\)\s*==\s*0'),
     Severity.MEDIUM, "strcmp()==0 auth check on request data (array-bypass to NULL)"),
    (re.compile(r'\bmail\s*\([^;]*,[^;]*,[^;]*,[^;]*,\s*\$_(?:GET|POST|REQUEST)'),
     Severity.MEDIUM, "mail() 5th arg from request data (params/sendmail injection)"),
    # --- CORS wildcard in code --------------------------------------------
    (re.compile(r'header\s*\(\s*[\'"]Access-Control-Allow-Origin:\s*\*'),
     Severity.MEDIUM, "CORS Access-Control-Allow-Origin: * set in code"),
]

# Lua (haserl / lua-CGI / openresty) request->sink mistakes
_LUA_RULES = [
    (re.compile(r'\bos\.execute\s*\([^)]*(?:ngx\.var|FORM\[|getvalue|arg\[|\bENV\b)'),
     Severity.CRITICAL, "lua os.execute() with request data (command injection)"),
    (re.compile(r'\bio\.popen\s*\([^)]*(?:ngx\.var|FORM\[|getvalue|arg\[)'),
     Severity.HIGH, "lua io.popen() with request data"),
    (re.compile(r'\b(?:loadstring|load)\s*\([^)]*(?:ngx\.var|FORM\[|getvalue)'),
     Severity.CRITICAL, "lua loadstring/load() of request data (code injection)"),
    (re.compile(r'\bngx\.location\.capture\s*\([^)]*ngx\.var'),
     Severity.MEDIUM, "ngx.location.capture() to request-controlled URI (SSRF)"),
]

# client-side (served .js/.html) DOM XSS
_JS_RULES = [
    (re.compile(r'\.innerHTML\s*=\s*[^;]*(?:location|document\.URL|\.search|\.hash|params)'),
     Severity.MEDIUM, "innerHTML assigned from location/URL (DOM XSS)"),
    (re.compile(r'document\.write\s*\([^)]*(?:location|document\.URL|\.search|\.hash)'),
     Severity.MEDIUM, "document.write() of location/URL (DOM XSS)"),
    (re.compile(r'\beval\s*\([^)]*(?:location|\.search|\.hash|params)'),
     Severity.HIGH, "eval() of URL-derived data (DOM XSS -> code exec)"),
    (re.compile(r'\bnew\s+Function\s*\([^)]*(?:location|\.search|\.hash)'),
     Severity.HIGH, "new Function() from URL data"),
]

_CGI_RULES = [
    (re.compile(r'\beval\s+["\']?\$(?:QUERY_STRING|HTTP_|CONTENT)'),
     Severity.CRITICAL, "shell eval of CGI request var (command injection)"),
    (re.compile(r'`[^`]*\$(?:QUERY_STRING|HTTP_[A-Z_]+|CONTENT_LENGTH)'),
     Severity.HIGH, "backtick command using CGI request var"),
    (re.compile(r'\b(?:system|exec|`)[^;\n]*\$ENV\{(?:QUERY_STRING|HTTP_)'),
     Severity.HIGH, "perl CGI exec of %ENV request var"),
    (re.compile(r'\becho\s+\$(?:QUERY_STRING|HTTP_[A-Z_]+)\b'),
     Severity.MEDIUM, "echo of CGI request var (reflected XSS)"),
    (re.compile(r'\bopen\s*\([^)]*\$(?:ENV\{|q\b)[^)]*\|'),
     Severity.HIGH, "perl 2-arg open() pipe with tainted data (command injection)"),
]

_PHP_EXT = {".php", ".php3", ".php4", ".php5", ".phtml", ".inc"}
_CGI_EXT = {".cgi", ".sh", ".pl"}
_LUA_EXT = {".lua"}
_JS_EXT = {".js", ".htm", ".html"}


def check_php_cgi_mistakes(rootfs: str) -> list[Finding]:
    f = []
    seen = set()
    for dirpath, _, files in os.walk(rootfs):
        low_dir = dirpath.lower()
        in_webish = any(h in low_dir for h in _WEBROOT_HINTS)
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            is_php = ext in _PHP_EXT
            is_cgi = ext in _CGI_EXT
            is_lua = ext in _LUA_EXT
            is_js = ext in _JS_EXT
            # only scan .js/.html when they live in a web dir (avoid vendored libs noise)
            if is_js and not in_webish:
                continue
            if not (is_php or is_cgi or is_lua or is_js):
                continue
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > _MAX:
                    continue
            except OSError:
                continue
            text = _read(p)
            rel = _rel(rootfs, p)
            rules = []
            if is_php:
                rules = _PHP_RULES + _CGI_RULES  # php may shell out via backticks
            elif is_cgi:
                rules = _CGI_RULES
            elif is_lua:
                rules = _LUA_RULES
            elif is_js:
                rules = _JS_RULES
            for pat, sev, label in rules:
                m = pat.search(text)
                if not m:
                    continue
                key = (rel, label)
                if key in seen:
                    continue
                seen.add(key)
                snip = m.group(0)[:100]
                cat = ("webapp-php" if is_php else "webapp-lua" if is_lua
                       else "webapp-xss" if is_js else "webapp-cgi")
                f.append(Finding(sev, cat, f"{label}", f"{snip}  @ {rel}", rel))
    # php.ini dangerous directives
    for p in _find_files(rootfs, "**/php.ini", "etc/php*/php.ini", "**/php*.ini"):
        rel = _rel(rootfs, p)
        low = _read(p).lower()
        if re.search(r'allow_url_include\s*=\s*on', low):
            f.append(Finding(Severity.HIGH, "webapp-php",
                             "php.ini allow_url_include=On (remote file include)",
                             path=rel))
        if re.search(r'allow_url_fopen\s*=\s*on', low):
            f.append(Finding(Severity.LOW, "webapp-php",
                             "php.ini allow_url_fopen=On (SSRF surface)", path=rel))
        if re.search(r'display_errors\s*=\s*on', low):
            f.append(Finding(Severity.LOW, "webapp-php",
                             "php.ini display_errors=On (info disclosure)", path=rel))
        if re.search(r'register_globals\s*=\s*on', low):
            f.append(Finding(Severity.HIGH, "webapp-php",
                             "php.ini register_globals=On (legacy, dangerous)",
                             path=rel))
    return f


# ---------------------------------------------------------------------------
# Web-root hygiene: files that shouldn't be served
# ---------------------------------------------------------------------------

_BACKUP_RE = re.compile(r'\.(?:bak|old|orig|save|swp|swo|tmp|inc|~)$|~$|'
                        r'\.(?:php|asp|cgi|lua)\.(?:bak|old|txt|dist|sample)$', re.I)
_VCS_DIRS = (".git", ".svn", ".hg", "cvs")
_EXPOSED_NAMES = ("config.php", "configuration.php", "wp-config.php",
                  "settings.php", "database.php", "db.php", ".env",
                  "phpinfo.php", "info.php", "test.php", "adminer.php",
                  "id_rsa", "id_dsa", ".htpasswd", ".git-credentials")


def check_webroot_hygiene(rootfs: str) -> list[Finding]:
    f = []
    for dirpath, dirnames, files in os.walk(rootfs):
        low_dir = dirpath.lower().replace("\\", "/")
        if not any(h in low_dir for h in _WEBROOT_HINTS):
            continue
        rel_dir = _rel(rootfs, dirpath)
        # VCS metadata served from the docroot leaks full source/history
        for vcs in _VCS_DIRS:
            if vcs in [d.lower() for d in dirnames]:
                f.append(Finding(Severity.HIGH, "webroot",
                                 f"{vcs} directory inside web root: {rel_dir}/{vcs}",
                                 "source/history/credentials downloadable over HTTP",
                                 f"{rel_dir}/{vcs}"))
        for name in files:
            rel = _rel(rootfs, os.path.join(dirpath, name))
            low = name.lower()
            if _BACKUP_RE.search(low):
                f.append(Finding(Severity.MEDIUM, "webroot",
                                 f"editor/backup file served from web root: {rel}",
                                 "may expose source or credentials verbatim", rel))
            if low in _EXPOSED_NAMES:
                sev = Severity.HIGH if low in (
                    "config.php", "wp-config.php", ".env", "database.php",
                    "db.php", "id_rsa", "id_dsa", ".htpasswd") else Severity.MEDIUM
                f.append(Finding(sev, "webroot",
                                 f"sensitive file in web root: {rel}",
                                 "downloadable / info-disclosure if not access-controlled",
                                 rel))
    return f


# ---------------------------------------------------------------------------
# aggregate
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_sshd, check_dropbear, check_telnet_inetd, check_ftp,
    check_nginx, check_lighttpd, check_apache, check_boa_goahead,
    check_wifi, check_dns, check_misc_services, check_webapp_sinks,
    check_tr069, check_upnp, check_vpn_tls, check_rtsp_onvif,
    check_cgi_binaries, check_php_cgi_mistakes, check_webroot_hygiene,
]


def analyze_services(rootfs: str) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            findings += check(rootfs)
        except Exception as e:  # keep one bad config from killing the scan
            findings.append(Finding(Severity.INFO, "svc-error",
                                    f"{check.__name__} failed: {e}"))
    return findings
