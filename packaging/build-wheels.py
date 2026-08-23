#!/usr/bin/env python3
"""Builds PyPI wheels from binaries the release workflow already built.

    python packaging/build-wheels.py --version 0.1.1 --binaries artifacts --out dist

The PyPI project is `ralonlock` — `ralon` was not available there — but the
command it installs is `ralon`, the same as everywhere else.

Ralon is not a Python library; a wheel is just the delivery mechanism that
`pip install ralonlock` and `uv tool install ralonlock` understand. Each wheel
carries one binary in its `.data/scripts/` directory, which pip installs onto
PATH and marks executable. There is nothing to import.

Building the wheels here rather than with maturin means the artifact users
install is byte-identical to the one attached to the GitHub release, instead of
a second compile of the same source.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The PyPI project name differs from the crate and the npm package; the binary
# it installs does not.
PROJECT = "ralonlock"
SUMMARY = (
    "Filesystem policy for AI coding agents: kernel-enforced write protection "
    "driven by an agent.lock file"
)
# Scripts must be executable once installed; zip entries carry the mode in the
# top 16 bits of external_attr.
EXECUTABLE = (0o100755 << 16)


def urlsafe_digest(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def metadata(version: str, description: str) -> str:
    return (
        "Metadata-Version: 2.1\n"
        "Name: " + PROJECT + "\n"
        f"Version: {version}\n"
        f"Summary: {SUMMARY}\n"
        "Author: Ralon contributors\n"
        "License: Apache-2.0\n"
        "Project-URL: Homepage, https://github.com/stoneware-dev/Ralon\n"
        "Project-URL: Source, https://github.com/stoneware-dev/Ralon\n"
        "Keywords: ai,agent,sandbox,landlock,security\n"
        "Classifier: Development Status :: 4 - Beta\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Operating System :: POSIX :: Linux\n"
        "Classifier: Operating System :: MacOS\n"
        "Classifier: Operating System :: Microsoft :: Windows\n"
        "Classifier: Topic :: Security\n"
        "Requires-Python: >=3.8\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
        f"{description}"
    )


def wheel_metadata(tags: list[str]) -> str:
    lines = [
        "Wheel-Version: 1.0",
        "Generator: ralon packaging/build-wheels.py",
        "Root-Is-Purelib: false",
    ]
    lines += [f"Tag: py3-none-{tag}" for tag in tags]
    return "\n".join(lines) + "\n"


def build(version: str, target: str, spec: dict, binaries: Path, out: Path) -> Path:
    executable = "ralon.exe" if spec["os"] == "win32" else "ralon"
    source = binaries / target / executable
    if not source.is_file():
        raise SystemExit(f"no binary for {target} at {source}")

    tags = spec["wheel"]
    # A wheel may declare several platform tags at once, dot-separated. The
    # Linux binaries are static, so one file legitimately satisfies both the
    # glibc and the musl tag.
    platform_tag = ".".join(tags)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{PROJECT}-{version}-py3-none-{platform_tag}.whl"

    dist_info = f"{PROJECT}-{version}.dist-info"
    data_scripts = f"{PROJECT}-{version}.data/scripts"
    readme = (ROOT / "npm" / "README.md").read_text(encoding="utf-8")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as wheel:

        def write(name: str, data: bytes, mode: int = 0) -> None:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode:
                info.external_attr = mode
            wheel.writestr(info, data)
            records.append((name, urlsafe_digest(data), len(data)))

        write(f"{data_scripts}/{executable}", source.read_bytes(), EXECUTABLE)
        write(f"{dist_info}/METADATA", metadata(version, readme).encode())
        write(f"{dist_info}/WHEEL", wheel_metadata(tags).encode())
        write(f"{dist_info}/licenses/LICENSE", license_text.encode())

        record = io.StringIO()
        writer = csv.writer(record, lineterminator="\n")
        for name, digest, size in records:
            writer.writerow([name, digest, size])
        # RECORD cannot contain its own hash.
        writer.writerow([f"{dist_info}/RECORD", "", ""])
        wheel.writestr(f"{dist_info}/RECORD", record.getvalue())

    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--binaries", default="artifacts", type=Path)
    parser.add_argument("--out", default="dist", type=Path)
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="skip targets whose binary is absent instead of failing",
    )
    arguments = parser.parse_args()

    version = arguments.version.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+([0-9A-Za-z.+-]*)", version):
        raise SystemExit(f"--version {version} is not a version PyPI will accept")

    targets = json.loads((ROOT / "packaging" / "targets.json").read_text())
    built = 0
    for target, spec in targets.items():
        try:
            path = build(version, target, spec, arguments.binaries, arguments.out)
        except SystemExit:
            if not arguments.allow_missing:
                raise
            print(f"skipping {target}: no binary")
            continue
        built += 1
        print(f"built {path.name}")

    if built == 0:
        raise SystemExit("no binaries were found, so there is nothing to publish")


if __name__ == "__main__":
    main()
