"""Cloud / P2P SDK fingerprinting for consumer IP cameras.

The real remote attack surface of these devices is not sshd - it is the
proprietary cloud / peer-to-peer video stack baked into the main application
binary: ThroughTek Kalay/TUTK, Tuya, Gwell/ajcloud, Xiongmai XMeye, Hisilicon
P2P, Anyka cloud, etc. Several of these have public, high-impact CVEs and all of
them are phone-home infrastructure worth surfacing.

We fingerprint by scanning binary/string evidence across the rootfs, attach
known CVEs for the identified stack, and record the associated endpoints as
IOCs. Version extraction is best-effort (these SDKs rarely embed clean banners).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .finding import Finding, Severity
from . import elf as elfmod
from .strings_util import strings_file


@dataclass
class CloudSDK:
    name: str
    vendor: str
    evidence: str
    source: str
    version: str = ""


# each SDK: display name, vendor, list of case-insensitive marker substrings,
# a severity for "present", a note, and any curated CVE leads.
_SDKS = [
    ("ThroughTek Kalay / TUTK", "ThroughTek",
     ("tutk", "iotcapi", "iotc_", "avapi", "p2pcam", "kalay", "throughtek",
      "PPCS_", "IOTC_Connect", "st_avserv"),
     Severity.HIGH,
     "ThroughTek P2P stack - CVE-2021-28372 (unauth remote AV access) / "
     "CVE-2021-32934 (missing AV stream auth). Confirm SDK version.",
     ["CVE-2021-28372", "CVE-2021-32934"]),
    ("Tuya IoT SDK", "Tuya",
     ("tuya", "tuyalink", "tuyaos", "tuya_iot", "ty_cJSON", "mqtt.tuyaus",
      "smartlife"),
     Severity.MEDIUM,
     "Tuya cloud SDK - cloud-account-bound device; audit local activation & "
     "MQTT credential handling.",
     []),
    ("Gwell / ajcloud (Meari)", "ajcloud",
     ("ajcloud", "gwell", "meari", "ppstrun", "ppcs", "iotcplatform"),
     Severity.MEDIUM,
     "Gwell/ajcloud P2P cloud (Meari OEM platform) - phone-home + P2P relay.",
     []),
    ("Xiongmai XMeye", "Xiongmai",
     ("xmeye", "xiongmai", "dvrip", "cloud.xm030", "np2p.net"),
     Severity.HIGH,
     "Xiongmai XMeye/Sofia stack - historically riddled with unauth RCE / "
     "backdoor (Mirai lineage). Treat as high risk.",
     []),
    ("Hisilicon / generic P2P (iLnkP2P)", "iLnkP2P",
     ("ilnkp2p", "cs2 network", "cs2network", "vstarcam", "p2pwificam",
      "ppppapi", "eye4"),
     Severity.HIGH,
     "CS2/PPPP 'iLnkP2P' stack - CVE-2019-11219 (enumerable device IDs) / "
     "CVE-2019-11220 (MITM of P2P traffic).",
     ["CVE-2019-11219", "CVE-2019-11220"]),
    ("Anyka cloud", "Anyka",
     ("anyka", "ak_cloud", "akcloud", "anycloud"),
     Severity.LOW,
     "Anyka SoC cloud helper.", []),
    ("MQTT phone-home", "generic",
     ("mosquitto", "mqtt_connect", "MQTTClient", "emqx", "aliyuncs", "iot-as-mqtt"),
     Severity.LOW,
     "MQTT client present - device maintains a persistent cloud control channel.",
     []),
]


def _iter_scan_targets(rootfs: str):
    """Yield (relpath, string_blob) for binaries/libs and app config likely to
    carry SDK markers. Bounded to keep the scan quick."""
    interesting_dirs = ("bin", "sbin", "usr", "opt", "app", "system",
                        "thirdlib", "lib", "customer", "backup")
    for dirpath, _, files in os.walk(rootfs):
        rel_dir = os.path.relpath(dirpath, rootfs).replace("\\", "/").lower()
        top = rel_dir.split("/", 1)[0]
        if rel_dir != "." and top not in interesting_dirs:
            continue
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size > 32 * 1024 * 1024:
                continue
            rel = os.path.relpath(p, rootfs).replace("\\", "/")
            if elfmod.is_elf(p) or name.lower().endswith((".so", ".bin", ".ko")) \
                    or ".so." in name.lower():
                yield rel, "\n".join(strings_file(p, min_len=5,
                                                  max_read=32 * 1024 * 1024))


def analyze(rootfs: str) -> tuple[list[Finding], list[CloudSDK]]:
    findings: list[Finding] = []
    detected: dict[str, CloudSDK] = {}

    for rel, blob in _iter_scan_targets(rootfs):
        low = blob.lower()
        for name, vendor, markers, sev, note, cves in _SDKS:
            if name in detected:
                continue
            for mk in markers:
                if mk.lower() in low:
                    sdk = CloudSDK(name=name, vendor=vendor, evidence=mk,
                                   source=rel)
                    detected[name] = sdk
                    findings.append(Finding(
                        sev, "cloud-sdk",
                        f"{name} cloud/P2P SDK present",
                        f"{note}  (marker '{mk}')", rel))
                    for cve in cves:
                        findings.append(Finding(
                            sev, "cve",
                            f"{vendor} P2P stack: {cve}",
                            "curated lead - confirm SDK version against advisory",
                            rel, data={"cve": cve, "cloud": True}))
                    break
    return findings, list(detected.values())
