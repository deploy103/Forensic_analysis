"""Tool-installation planner: proposes install commands, never executes them.

Auto-installing packages changes system state in a way that is not cleanly
reversible and can fail loudly (missing sudo, restricted competition
sandbox, unexpected package name on that distro), so this module is
deliberately plan-only. :func:`plan_install` returns ranked candidate argv
commands plus a short rationale; nothing in this codebase invokes them
automatically. An operator who wants to act on a plan can run the returned
argv by hand (ideally through ``bin/log-command`` so the install itself is
part of the case's reproducible audit trail).
"""

from __future__ import annotations

import dataclasses

# Curated tool -> [(package_manager, package_name), ...] map for the tools
# this project already depends on (config/toolset.txt) plus common CTF
# forensics tools whose package name differs from the executable name.
# Anything not listed here still gets a generic best-guess ``apt`` candidate
# using the tool's own name as the package name.
_KNOWN_PACKAGES: dict[str, list[tuple[str, str]]] = {
    "exiftool": [("apt", "libimage-exiftool-perl")],
    "binwalk": [("apt", "binwalk"), ("pip", "binwalk")],
    "foremost": [("apt", "foremost")],
    "bulk_extractor": [("apt", "bulk-extractor")],
    "fls": [("apt", "sleuthkit")],
    "mmls": [("apt", "sleuthkit")],
    "testdisk": [("apt", "testdisk")],
    "tshark": [("apt", "tshark")],
    "tcpdump": [("apt", "tcpdump")],
    "yara": [("apt", "yara"), ("pip", "yara-python")],
    "ffmpeg": [("apt", "ffmpeg")],
    "magick": [("apt", "imagemagick")],
    "sqlite3": [("apt", "sqlite3")],
    "7z": [("apt", "p7zip-full")],
    "vol.py": [("pip", "volatility3")],
    "zsteg": [("gem", "zsteg")],
    "stegseek": [("apt", "stegseek")],
    "olevba": [("pip", "oletools")],
}

_MANAGER_ARGV = {
    "apt": lambda pkg: ["sudo", "apt-get", "install", "-y", pkg],
    "pip": lambda pkg: ["pip", "install", pkg],
    "pipx": lambda pkg: ["pipx", "install", pkg],
    "gem": lambda pkg: ["gem", "install", pkg],
    "cargo": lambda pkg: ["cargo", "install", pkg],
    "go": lambda pkg: ["go", "install", pkg],
}


@dataclasses.dataclass
class InstallCandidate:
    manager: str
    package: str
    argv: list[str]
    rationale: str


def plan_install(tool_name: str) -> list[InstallCandidate]:
    candidates = []
    for manager, package in _KNOWN_PACKAGES.get(tool_name, [("apt", tool_name)]):
        builder = _MANAGER_ARGV.get(manager)
        if builder is None:
            continue
        candidates.append(InstallCandidate(
            manager=manager, package=package, argv=builder(package),
            rationale=f"{tool_name!r} is commonly packaged as {package!r} via {manager}",
        ))
    return candidates


def plan_installs(tool_names: list[str]) -> dict[str, list[InstallCandidate]]:
    return {name: plan_install(name) for name in tool_names}
