"""Hash firmware bytes for attestation and update verification."""

import hashlib
from pathlib import Path
from typing import Union


def sha256_file(path: Union[str, Path]) -> str:
    """Return the lowercase SHA-256 digest of the file's actual bytes."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as firmware:
        for chunk in iter(lambda: firmware.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()