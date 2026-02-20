"""
ATUM Audit Agent - Cryptographic hashing module.
Provides deterministic, streaming hash computation for files of any size.
"""

import hashlib
from pathlib import Path

# Buffer size for streaming hash: 128KB balances memory vs syscall overhead
_BUFFER_SIZE = 131072


def compute_hash(
    filepath: Path,
    algorithm: str = "sha256",
    max_size: int | None = None,
) -> str | None:
    """
    Compute cryptographic hash of a file using streaming reads.
    Returns hex digest string or None if file is unreadable/too large.

    Thread-safe: no shared state.
    """
    try:
        stat = filepath.stat()
        if max_size and stat.st_size > max_size:
            return None

        if algorithm == "blake2b":
            h = hashlib.blake2b(digest_size=32)
        elif algorithm == "sha512":
            h = hashlib.sha512()
        else:
            h = hashlib.sha256()

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(_BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()

    except (OSError, PermissionError, FileNotFoundError):
        return None


def compute_dual_hash(
    filepath: Path,
    max_size: int | None = None,
) -> tuple[str, str] | None:
    """
    Compute both SHA-256 and BLAKE2b in a single file read.
    Returns (sha256_hex, blake2b_hex) or None.
    """
    try:
        stat = filepath.stat()
        if max_size and stat.st_size > max_size:
            return None

        h_sha = hashlib.sha256()
        h_blake = hashlib.blake2b(digest_size=32)

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(_BUFFER_SIZE)
                if not chunk:
                    break
                h_sha.update(chunk)
                h_blake.update(chunk)

        return (h_sha.hexdigest(), h_blake.hexdigest())

    except (OSError, PermissionError, FileNotFoundError):
        return None


def verify_hash(filepath: Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify file integrity against a known hash.
    Returns True if match, False otherwise (including on read error).
    """
    current = compute_hash(filepath, algorithm)
    if current is None:
        return False
    return current == expected_hash
