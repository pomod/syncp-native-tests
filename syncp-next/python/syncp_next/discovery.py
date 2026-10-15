"""Read-only hardware observations. Missing probes remain unknown, not zero."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import csv
import ctypes
import io
import os
import platform
import shutil
import subprocess


@dataclass(frozen=True)
class Observation:
    value: Any
    source: str
    confidence: str
    limitation: str | None = None


def _probe(argv: list[str]) -> str | None:
    """A five-second diagnostic probe limit is not a model task deadline."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def parse_linux_memory(text: str) -> dict[str, int | None]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1].isdigit() and parts[2] == "kB":
            values[parts[0].rstrip(":")] = int(parts[1]) * 1024
    return {"total_bytes": values.get("MemTotal"), "available_bytes": values.get("MemAvailable")}


def parse_nvidia_csv(text: str) -> list[dict[str, Any]]:
    """Use actual per-device free VRAM, not total VRAM or a workstation preset."""
    devices = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) != 5:
            continue
        name, total, free, driver, uuid = (part.strip() for part in row)
        try:
            total_bytes, available_bytes = int(total) * 1024**2, int(free) * 1024**2
            if total_bytes < 0 or not 0 <= available_bytes <= total_bytes:
                continue
        except ValueError:
            total_bytes = available_bytes = None
        devices.append({"vendor": "NVIDIA", "model": name, "total_vram_bytes": total_bytes,
                        "available_vram_bytes": available_bytes, "driver": driver, "id": uuid,
                        "source": "nvidia-smi", "inference_backend_qualified": False})
    return devices


def _memory(system: str, probe: Callable[[list[str]], str | None]) -> Observation:
    if system == "Linux":
        try:
            data = parse_linux_memory(Path("/proc/meminfo").read_text())
            return Observation(data, "/proc/meminfo", "high")
        except OSError:
            pass
    elif system == "Windows" and os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong) for name in ("total_phys", "avail_phys", "total_page",
                "avail_page", "total_virtual", "avail_virtual", "avail_extended")]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return Observation({"total_bytes": status.total_phys, "available_bytes": status.avail_phys},
                               "GlobalMemoryStatusEx", "high")
    elif system == "Darwin":
        total = probe(["/usr/sbin/sysctl", "-n", "hw.memsize"])
        if total and total.isdigit():
            return Observation({"total_bytes": int(total), "available_bytes": None}, "sysctl hw.memsize",
                               "partial", "Usable memory and unified GPU memory are not yet qualified")
    return Observation({"total_bytes": None, "available_bytes": None}, "unavailable", "unknown")


def discover(disk_path: Path, *, probe: Callable[[list[str]], str | None] = _probe) -> dict[str, Any]:
    """No writes, provider reads, network probes, model loading or service changes."""
    system = platform.system()
    try:
        disk = shutil.disk_usage(disk_path)
        disk_observation = Observation({"total_bytes": disk.total, "available_bytes": disk.free},
                                       "filesystem at selected destination", "high")
    except OSError:
        disk_observation = Observation(None, "unavailable", "unknown", "Destination is inaccessible")
    nvidia = shutil.which("nvidia-smi")
    gpu_text = probe([nvidia, "--query-gpu=name,memory.total,memory.free,driver_version,uuid",
                      "--format=csv,noheader,nounits"]) if nvidia else None
    gpu = Observation(parse_nvidia_csv(gpu_text), "nvidia-smi", "high",
                      "Driver discovery does not qualify an inference backend") if gpu_text else Observation(
        None, "unavailable", "unknown", "No qualified GPU observation; this does not prove absence of a GPU")
    cpu_features = None
    cpu_source = "unavailable"
    if system == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith(("flags", "Features")) and ":" in line:
                    cpu_features = sorted(set(line.split(":", 1)[1].split()))
                    cpu_source = "/proc/cpuinfo"
                    break
        except OSError:
            pass
    return {"api_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
            "os": {"system": system, "release": platform.release(), "architecture": platform.machine()},
            "cpu": {"logical_processors": os.cpu_count(), "model": platform.processor() or None,
                    "features": asdict(Observation(cpu_features, cpu_source, "high" if cpu_features else "unknown"))},
            "memory": asdict(_memory(system, probe)), "gpu": asdict(gpu), "disk": asdict(disk_observation),
            "network": asdict(Observation(None, "not probed", "unknown", "Network checks require explicit intent")),
            "qualification": {"Windows": "UNTESTED", "Darwin": "UNTESTED", "Linux": "READ_ONLY_PROBE"}.get(system, "UNTESTED")}
