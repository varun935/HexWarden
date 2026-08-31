"""Packaging configuration for HexWarden.

Defines how the HexWarden firmware analysis toolkit is packaged and installed,
including its console-script entry point so that `pip install .` provides
a `hexwarden` command on the PATH.

Inputs:
    None (invoked by pip/setuptools during package build/installation).

Outputs:
    None (side effect: registers the installable "hexwarden" package and CLI).
"""

from pathlib import Path

from setuptools import find_packages, setup

_ROOT = Path(__file__).resolve().parent
_LONG_DESCRIPTION = (_ROOT / "README.md").read_text(encoding="utf-8")

setup(
    name="hexwarden",
    version="0.1.0",
    description="HexWarden: an open firmware trojan/malware detection toolkit for embedded devices.",
    long_description=_LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(exclude=("tests", "tests.*")),
    py_modules=["main", "config"],
    install_requires=[
        "matplotlib==3.11.1",
        "numpy==1.26.4",
        "yara-python==4.5.1",
        "pyelftools==0.31",
        "scapy==2.5.0",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "hexwarden=main:main",
        ],
    },
)
