from __future__ import annotations

from usaf.collectors.packages.apt import get_package_for_file as _get_dpkg_package
from usaf.collectors.packages.flatpak import get_flatpak_package_for_file
from usaf.collectors.packages.snap import get_snap_package_for_file


def resolve_package(filepath: str) -> str | None:
    pkg = _get_dpkg_package(filepath)
    if pkg is not None:
        return pkg
    pkg = get_flatpak_package_for_file(filepath)
    if pkg is not None:
        return pkg
    pkg = get_snap_package_for_file(filepath)
    if pkg is not None:
        return pkg
    return None
