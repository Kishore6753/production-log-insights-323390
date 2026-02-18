from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


# Files we consider as "logs" inside a zip. (Lowercased match.)
_ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".json", ".ndjson"}

# Environment variable controlling how much total uncompressed data we will accept from a zip.
# This protects against "zip bombs" while allowing operators to tune the limit.
_ZIP_MAX_TOTAL_UNCOMPRESSED_ENV = "ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES"


@dataclass(frozen=True)
class ExtractedZipTextFile:
    """A single extracted (text-like) file from a zip archive."""

    path: str
    content_bytes: bytes


def _is_allowed_log_member(filename: str) -> bool:
    """Return True if a zip member filename should be treated as a log file."""
    name = filename.lower().strip()

    # Ignore directories and OS metadata.
    if not name or name.endswith("/"):
        return False
    # Avoid zip entries that can be used for weird paths; ZipFile will give us member names.
    if "__macosx/" in name or name.endswith(".ds_store"):
        return False

    for ext in _ALLOWED_LOG_EXTENSIONS:
        if name.endswith(ext):
            return True
    return False


def _safe_member_path(name: str) -> str:
    """
    Normalize member name for display only.

    Note: ZipFile prevents direct filesystem traversal because we never write to disk,
    but we still normalize to avoid confusing UI/reporting.
    """
    out = name.replace("\\", "/")
    while out.startswith("/"):
        out = out[1:]
    # Collapse any '..' purely for display.
    parts = [p for p in out.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) if parts else name


def _format_bytes(num_bytes: int) -> str:
    """Human-readable bytes for error messaging."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KiB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MiB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GiB"


# PUBLIC_INTERFACE
def get_zip_max_total_uncompressed_bytes(default: int = 50 * 1024 * 1024) -> int:
    """
    Read the max total uncompressed bytes allowed when extracting zip archives.

    This is a safety control to mitigate zip-bomb style uploads, but can be configured
    via env var for legitimate larger archives.

    Env var:
        ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES: integer bytes (e.g. 52428800 for 50MiB)

    Args:
        default: Value to use when env var is unset or invalid.

    Returns:
        Configured maximum total uncompressed bytes (always a positive integer).
    """
    raw = os.getenv(_ZIP_MAX_TOTAL_UNCOMPRESSED_ENV)
    if raw is None or raw.strip() == "":
        return default

    try:
        val = int(raw.strip())
        if val <= 0:
            return default
        return val
    except Exception:
        return default


# PUBLIC_INTERFACE
def extract_log_files_from_zip_bytes(
    zip_bytes: bytes, max_total_uncompressed: Optional[int] = None
) -> Tuple[List[ExtractedZipTextFile], List[str]]:
    """
    Extract log-like files from a zip archive.

    Args:
        zip_bytes: Raw uploaded zip file bytes.
        max_total_uncompressed: Safety limit across extracted files, to avoid zip bombs.
            If None, will be loaded from ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES env var (default 10MiB).

    Returns:
        (files, warnings)
        - files: list of extracted files (in-memory bytes)
        - warnings: non-fatal messages (e.g., skipped files, size limits)

    Raises:
        ValueError: if the zip is invalid/corrupt or exceeds safety constraints.
    """
    warnings: List[str] = []
    extracted: List[ExtractedZipTextFile] = []

    limit = (
        int(max_total_uncompressed)
        if max_total_uncompressed is not None
        else get_zip_max_total_uncompressed_bytes()
    )

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            infos = zf.infolist()
            if not infos:
                raise ValueError("Zip archive is empty.")

            total_uncompressed = 0
            allowed_infos = [i for i in infos if _is_allowed_log_member(i.filename)]

            if not allowed_infos:
                warnings.append(
                    "Zip archive contained no supported log files. "
                    "Supported extensions: .log .txt .json .ndjson"
                )
                return [], warnings

            for info in allowed_infos:
                # Basic bomb guard: sum declared uncompressed sizes.
                total_uncompressed += int(info.file_size or 0)
                if total_uncompressed > limit:
                    raise ValueError(
                        "Zip archive rejected: total uncompressed size "
                        f"{_format_bytes(total_uncompressed)} exceeds safety limit "
                        f"{_format_bytes(limit)} ({limit} bytes). "
                        f"To increase, set env var {_ZIP_MAX_TOTAL_UNCOMPRESSED_ENV}."
                    )

                try:
                    data = zf.read(info)
                except Exception:
                    warnings.append(f"Failed to read zip member: {info.filename}")
                    continue

                extracted.append(
                    ExtractedZipTextFile(
                        path=_safe_member_path(info.filename),
                        content_bytes=data,
                    )
                )

    except zipfile.BadZipFile as e:
        raise ValueError("Invalid zip file.") from e

    # Keep ordering deterministic for reproducibility.
    extracted = sorted(extracted, key=lambda f: f.path.lower())
    return extracted, warnings


# PUBLIC_INTERFACE
def combine_extracted_text_files(files: Iterable[ExtractedZipTextFile]) -> bytes:
    """
    Combine extracted log files into a single bytes payload for existing parser.

    We insert a small header separator between files so analysts can see provenance
    in redacted evidence quotes without changing the response structure.
    """
    out = bytearray()
    first = True
    for f in files:
        if not first:
            out.extend(b"\n")
        first = False
        header = f"\n----- BEGIN FILE: {f.path} -----\n"
        out.extend(header.encode("utf-8", errors="ignore"))
        out.extend(f.content_bytes)
        out.extend(b"\n")
        footer = f"----- END FILE: {f.path} -----\n"
        out.extend(footer.encode("utf-8", errors="ignore"))
    return bytes(out)
