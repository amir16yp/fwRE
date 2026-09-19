"""fwre - a lightweight reverse-engineering / vulnerability framework for
Linux-based firmware images (IP cameras, routers, embedded devices).

Extraction is delegated entirely to 7-Zip (7z.exe). Everything else in this
package operates on the extracted root filesystem and focuses on the parts of
firmware RE that actually matter for finding bugs and attack surface:

  * checksec-style ELF hardening audit (pure-python ELF parser, no deps)
  * dangerous libc import detection
  * credential extraction (passwd/shadow, hashes ready for john/hashcat)
  * secret / key / certificate hunting
  * attack-surface mapping (init scripts, network daemons, debug shells)
  * component version fingerprinting + offline CVE heuristics
  * network IOC extraction (URLs, IPs, cloud/MQTT endpoints)

Stdlib only. Requires 7z on PATH for extraction.
"""

__version__ = "0.1.0"

from .finding import Finding, Severity  # noqa: F401
