"""Platform fingerprint, logged at startup and stored with every artifact and report (IBM Z evidence)."""
from __future__ import annotations

import os
import platform
import socket
import sys


def _mem_gib() -> float | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / 1024 / 1024, 2)
    except OSError:
        pass
    return None


def _cpu_features() -> dict:
    """On IBM Z, /proc/cpuinfo lists the machine type and facilities ('nnpa' = on-chip AI accelerator)."""
    info = {}
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            text = f.read()
        for line in text.splitlines():
            if line.startswith("features") and "features" not in info:
                feats = line.split(":", 1)[1].split()
                info["features_has_nnpa"] = "nnpa" in feats
            if line.startswith("processor 0:") and "machine =" in line:
                info["machine_type"] = line.split("machine =")[1].strip()
    except OSError:
        pass
    return info


def fingerprint() -> dict:
    from importlib import metadata

    libs = {}
    for name, dist in (("numpy", "numpy"), ("pandas", "pandas"), ("sklearn", "scikit-learn"),
                       ("torch", "torch"), ("flask", "flask")):
        try:
            libs[name] = metadata.version(dist)
        except metadata.PackageNotFoundError:
            libs[name] = None
    return {
        "arch": platform.machine(),
        "byteorder": sys.byteorder,
        "system": platform.system(),
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "mem_gib": _mem_gib(),
        **_cpu_features(),
        "libs": libs,
    }


def one_line(fp: dict | None = None) -> str:
    fp = fp or fingerprint()
    return (f"platform={fp['arch']} byteorder={fp['byteorder']} cpus={fp['cpus']} mem_gib={fp['mem_gib']} "
            f"python={fp['python']} sklearn={fp['libs'].get('sklearn')} torch={fp['libs'].get('torch')}")
