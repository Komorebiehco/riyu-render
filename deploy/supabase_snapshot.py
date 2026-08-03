"""Persist RIYU data with bounded, atomic Supabase Storage snapshots."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO


ROOT_DIR = Path(os.environ.get("RIYU_ROOT", "/app")).resolve()
DATA_DIR = Path(os.environ.get("DATA_DIR", str(ROOT_DIR / "data"))).resolve()
STATE_FILE = DATA_DIR / ".supabase_snapshot_state.json"
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "riyu-persistence")
PREFIX = os.environ.get("SUPABASE_SNAPSHOT_PREFIX", "riyu-v1").strip("/")
POINTER_OBJECT = f"{PREFIX}/latest.json"
BUDGET_OBJECT = f"{PREFIX}/upload-budget.json"
LEGACY_MANIFEST_OBJECT = "snapshot/manifest.json"
PART_SIZE = 16 * 1024 * 1024
IO_CHUNK_SIZE = 256 * 1024
MONTHLY_UPLOAD_BUDGET_BYTES = int(
    os.environ.get("SNAPSHOT_MONTHLY_UPLOAD_BUDGET_BYTES", "2000000000")
)
VALID_SLOTS = {"a", "b"}
EXCLUDED_ROOT_DIRS = {"logs", "temp"}
EXCLUDED_DIR_NAMES = {"__pycache__", ".pytest_cache", ".ruff_cache"}


def object_url(object_path: str, authenticated: bool) -> str:
    """Return a Supabase Storage object URL.

    Args:
        object_path: Path inside the configured bucket.
        authenticated: Whether to use the authenticated download endpoint.

    Returns:
        Fully qualified Storage API URL.
    """
    encoded_bucket = urllib.parse.quote(BUCKET, safe="")
    encoded_path = urllib.parse.quote(object_path, safe="/")
    route = "object/authenticated" if authenticated else "object"
    return f"{SUPABASE_URL}/storage/v1/{route}/{encoded_bucket}/{encoded_path}"


def is_missing_error(exc: urllib.error.HTTPError, error_body: bytes) -> bool:
    """Return whether a Storage error represents a missing object.

    Args:
        exc: HTTP error raised by urllib.
        error_body: Response body read from the error.

    Returns:
        True when Supabase reports that the requested object is absent.
    """
    if exc.code not in {400, 404}:
        return False
    try:
        payload = json.loads(error_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    text = " ".join(
        str(payload.get(field, ""))
        for field in ("statusCode", "error", "message")
    ).lower()
    return "404" in text or "not found" in text or "not_found" in text


def request_object(
    method: str,
    object_path: str,
    body: bytes | None = None,
    content_type: str = "application/json",
) -> bytes | None:
    """Read or upload a small Storage object.

    Args:
        method: HTTP method.
        object_path: Path inside the configured bucket.
        body: Optional payload.
        content_type: Payload MIME type.

    Returns:
        Response bytes, or None when a requested object does not exist.

    Raises:
        urllib.error.HTTPError: If Storage returns an unexpected error.
    """
    headers = {
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "apikey": SUPABASE_KEY,
        "Content-Type": content_type,
    }
    if method != "GET":
        headers["x-upsert"] = "true"
    req = urllib.request.Request(
        object_url(object_path, authenticated=method == "GET"),
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        error_body = exc.read()
        if method == "GET" and is_missing_error(exc, error_body):
            return None
        raise


def download_object(
    object_path: str,
    destination: BinaryIO,
    digest: hashlib._Hash,
) -> int | None:
    """Stream a Storage object into a local file.

    Args:
        object_path: Path inside the configured bucket.
        destination: Open binary destination.
        digest: Hash object updated as bytes arrive.

    Returns:
        Number of downloaded bytes, or None if the object is missing.

    Raises:
        urllib.error.HTTPError: If Storage returns an unexpected error.
    """
    headers = {
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "apikey": SUPABASE_KEY,
    }
    req = urllib.request.Request(
        object_url(object_path, authenticated=True),
        headers=headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            downloaded = 0
            while chunk := response.read(IO_CHUNK_SIZE):
                destination.write(chunk)
                digest.update(chunk)
                downloaded += len(chunk)
            return downloaded
    except urllib.error.HTTPError as exc:
        error_body = exc.read()
        if is_missing_error(exc, error_body):
            return None
        raise


def upload_file_range(
    source: BinaryIO,
    offset: int,
    length: int,
    object_path: str,
) -> None:
    """Stream one bounded file range to Supabase without buffering it in RAM.

    Args:
        source: Open archive file.
        offset: Starting byte offset.
        length: Number of bytes to upload.
        object_path: Destination path inside the bucket.

    Raises:
        RuntimeError: If Storage rejects the upload.
    """
    parsed = urllib.parse.urlsplit(SUPABASE_URL)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("SUPABASE_URL must be an HTTPS URL.")
    encoded_bucket = urllib.parse.quote(BUCKET, safe="")
    encoded_path = urllib.parse.quote(object_path, safe="/")
    api_path = f"{parsed.path.rstrip('/')}/storage/v1/object/{encoded_bucket}/{encoded_path}"
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=180)
    try:
        connection.putrequest("POST", api_path)
        connection.putheader("Authorization", f"Bearer {SUPABASE_KEY}")
        connection.putheader("apikey", SUPABASE_KEY)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(length))
        connection.putheader("x-upsert", "true")
        connection.endheaders()
        source.seek(offset)
        remaining = length
        while remaining:
            chunk = source.read(min(IO_CHUNK_SIZE, remaining))
            if not chunk:
                raise RuntimeError("Archive ended before the requested upload range.")
            connection.send(chunk)
            remaining -= len(chunk)
        response = connection.getresponse()
        response_body = response.read()
        if response.status not in {200, 201}:
            raise RuntimeError(
                f"Storage rejected {object_path} with HTTP {response.status}: "
                f"{response_body[:300]!r}"
            )
    finally:
        connection.close()


def add_sqlite_backup(archive: tarfile.TarFile, source: Path, arcname: str) -> None:
    """Add a consistent online SQLite backup to a tar archive.

    Args:
        archive: Open destination tar archive.
        source: Live SQLite database path.
        arcname: Path to use inside the archive.
    """
    with tempfile.NamedTemporaryFile(suffix=source.suffix, delete=False) as handle:
        backup_path = Path(handle.name)
    try:
        source_uri = f"file:{source.as_posix()}?mode=ro"
        with closing(
            sqlite3.connect(source_uri, uri=True, timeout=30)
        ) as source_db:
            with closing(sqlite3.connect(backup_path)) as backup_db:
                source_db.backup(backup_db)
        info = archive.gettarinfo(str(backup_path), arcname=arcname)
        source_stat = source.stat()
        info.mtime = int(source_stat.st_mtime)
        info.mode = source_stat.st_mode
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        with backup_path.open("rb") as backup_file:
            archive.addfile(info, backup_file)
    finally:
        backup_path.unlink(missing_ok=True)


def build_archive(destination: Path) -> None:
    """Create an uncompressed, low-memory tar snapshot.

    Args:
        destination: Output tar path.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    sqlite_suffixes = {".db", ".sqlite", ".sqlite3"}
    with tarfile.open(destination, "w") as archive:
        archive.add(DATA_DIR, arcname="data", recursive=False)
        for path in sorted(DATA_DIR.rglob("*")):
            if path == STATE_FILE:
                continue
            relative = path.relative_to(DATA_DIR)
            if (
                relative.parts[0] in EXCLUDED_ROOT_DIRS
                or any(part in EXCLUDED_DIR_NAMES for part in relative.parts)
            ):
                continue
            arcname = (Path("data") / relative).as_posix()
            if path.name.endswith(("-wal", "-shm")):
                continue
            try:
                if path.is_file() and path.suffix.lower() in sqlite_suffixes:
                    add_sqlite_backup(archive, path, arcname)
                else:
                    archive.add(path, arcname=arcname, recursive=False)
            except FileNotFoundError:
                continue


def hash_file(path: Path) -> str:
    """Return the SHA-256 digest of a file.

    Args:
        path: File to hash.

    Returns:
        Lowercase hexadecimal digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(IO_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_object(object_path: str) -> dict | None:
    """Load one JSON object from Storage.

    Args:
        object_path: Path inside the configured bucket.

    Returns:
        Parsed mapping, or None when absent.
    """
    data = request_object("GET", object_path)
    if data is None:
        return None
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid JSON object at {object_path}.")
    return payload


def write_state(restored_slot: str | None) -> None:
    """Record which remote slot matches the running data directory.

    Args:
        restored_slot: Slot name, or None for a legacy/fresh restore.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"restored_slot": restored_slot}
    STATE_FILE.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")


def read_state_slot() -> str | None:
    """Return the slot that produced the running data directory."""
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    slot = payload.get("restored_slot")
    return slot if slot in VALID_SLOTS else None


def reserve_monthly_upload_budget(upload_bytes: int) -> tuple[bool, int, str]:
    """Conservatively reserve this upload against the current UTC month.

    The reservation is published before any snapshot part is uploaded. Failed
    uploads therefore still consume the reservation, which intentionally
    favors staying below Render's free outbound-transfer allowance.

    Args:
        upload_bytes: Number of snapshot-part bytes that would be uploaded.

    Returns:
        A tuple of whether the reservation succeeded, the resulting reserved
        byte count, and the UTC month identifier.

    Raises:
        RuntimeError: If the configured budget or stored counter is invalid.
    """
    if upload_bytes < 0:
        raise RuntimeError("Upload byte reservation cannot be negative.")
    if MONTHLY_UPLOAD_BUDGET_BYTES < 0:
        raise RuntimeError("SNAPSHOT_MONTHLY_UPLOAD_BUDGET_BYTES cannot be negative.")

    now = datetime.now(timezone.utc)
    month = now.strftime("%Y-%m")
    budget = load_json_object(BUDGET_OBJECT) or {}
    if budget.get("month") == month:
        try:
            reserved_bytes = int(budget.get("reserved_bytes", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Stored monthly upload budget is invalid.") from exc
        if reserved_bytes < 0:
            raise RuntimeError("Stored monthly upload budget cannot be negative.")
    else:
        reserved_bytes = 0

    projected_bytes = reserved_bytes + upload_bytes
    if projected_bytes > MONTHLY_UPLOAD_BUDGET_BYTES:
        return False, reserved_bytes, month
    if upload_bytes == 0:
        return True, reserved_bytes, month

    payload = {
        "version": 1,
        "month": month,
        "reserved_bytes": projected_bytes,
        "limit_bytes": MONTHLY_UPLOAD_BUDGET_BYTES,
        "updated_at": now.isoformat(),
    }
    request_object(
        "POST",
        BUDGET_OBJECT,
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return True, projected_bytes, month


def download_manifest_archive(manifest: dict) -> Path:
    """Download and validate an archive described by a manifest.

    Args:
        manifest: Snapshot manifest.

    Returns:
        Temporary archive path. The caller must unlink it.

    Raises:
        RuntimeError: If any part is missing or validation fails.
    """
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        with archive_path.open("wb") as handle:
            digest = hashlib.sha256()
            for part in manifest.get("parts", []):
                object_path = str(part["path"])
                expected_size = int(part["size"])
                downloaded = download_object(object_path, handle, digest)
                if downloaded is None or downloaded != expected_size:
                    raise RuntimeError(
                        f"Snapshot part is missing or incomplete: {object_path}"
                    )
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise
    if archive_path.stat().st_size != int(manifest["size"]):
        archive_path.unlink(missing_ok=True)
        raise RuntimeError("Snapshot size does not match the manifest.")
    if digest.hexdigest() != manifest["sha256"]:
        archive_path.unlink(missing_ok=True)
        raise RuntimeError("Snapshot checksum does not match the manifest.")
    return archive_path


def validate_archive_members(archive: tarfile.TarFile) -> None:
    """Reject archive entries that escape the RIYU data directory.

    Args:
        archive: Open snapshot archive.

    Raises:
        RuntimeError: If a member resolves outside the RIYU data directory.
    """
    root = DATA_DIR.resolve()
    for member in archive.getmembers():
        if member.name == "data":
            continue
        if not member.name.startswith("data/"):
            raise RuntimeError(f"Unexpected archive member: {member.name}")
        relative = Path(member.name).relative_to("data")
        target = (root / relative).resolve()
        if target != root and root not in target.parents:
            raise RuntimeError(f"Unsafe archive member: {member.name}")


def restore_manifest(manifest: dict, slot: str | None, verify_only: bool) -> None:
    """Validate and optionally extract one snapshot manifest.

    Args:
        manifest: Snapshot manifest.
        slot: Source slot, or None for the legacy snapshot.
        verify_only: If true, validate without extracting.
    """
    archive_path = download_manifest_archive(manifest)
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            validate_archive_members(archive)
            if not verify_only:
                archive.extractall(DATA_DIR.parent, filter="data")
        if not verify_only:
            write_state(slot)
    finally:
        archive_path.unlink(missing_ok=True)


def restore(verify_only: bool = False) -> None:
    """Restore the current slot, with one previous-slot fallback."""
    pointer = load_json_object(POINTER_OBJECT)
    if pointer is not None:
        candidates: list[str] = []
        for key in ("current", "previous"):
            slot = pointer.get(key)
            if slot in VALID_SLOTS and slot not in candidates:
                candidates.append(slot)
        failures: list[str] = []
        for slot in candidates:
            try:
                manifest = load_json_object(f"{PREFIX}/slots/{slot}/manifest.json")
                if manifest is None:
                    raise RuntimeError(f"Manifest for slot {slot} is missing.")
                restore_manifest(manifest, slot, verify_only)
                action = "verified" if verify_only else "restored"
                print(
                    f"Supabase v2 snapshot {action}: slot={slot}, "
                    f"size={manifest['size']} bytes.",
                    flush=True,
                )
                return
            except Exception as exc:
                failures.append(f"slot {slot}: {exc}")
        raise RuntimeError("All published snapshot slots failed: " + "; ".join(failures))

    legacy_manifest = load_json_object(LEGACY_MANIFEST_OBJECT)
    if legacy_manifest is not None:
        restore_manifest(legacy_manifest, None, verify_only)
        action = "verified" if verify_only else "restored"
        print(
            f"Legacy Supabase snapshot {action}: "
            f"size={legacy_manifest['size']} bytes.",
            flush=True,
        )
        return

    if not verify_only:
        write_state(None)
    print("No Supabase snapshot exists; starting with an empty data directory.", flush=True)


def upload() -> None:
    """Publish a low-memory snapshot through the inactive remote slot."""
    pointer = load_json_object(POINTER_OBJECT) or {}
    restored_slot = read_state_slot()
    current_slot = pointer.get("current")
    base_slot = restored_slot or (
        current_slot if current_slot in VALID_SLOTS else None
    )
    target_slot = "b" if base_slot == "a" else "a"

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        build_archive(archive_path)
        archive_size = archive_path.stat().st_size
        archive_hash = hash_file(archive_path)

        if current_slot in VALID_SLOTS:
            current_manifest = load_json_object(
                f"{PREFIX}/slots/{current_slot}/manifest.json"
            )
            if current_manifest and current_manifest.get("sha256") == archive_hash:
                print("RIYU data is unchanged; snapshot upload skipped.", flush=True)
                return

        target_manifest = load_json_object(
            f"{PREFIX}/slots/{target_slot}/manifest.json"
        )
        target_parts = {
            part.get("path"): part
            for part in (target_manifest or {}).get("parts", [])
            if isinstance(part, dict) and isinstance(part.get("path"), str)
        }
        parts: list[dict[str, int | str]] = []
        upload_plan: list[tuple[int, int, str]] = []
        reused_parts = 0
        with archive_path.open("rb") as source:
            offset = 0
            index = 0
            while offset < archive_size:
                length = min(PART_SIZE, archive_size - offset)
                object_path = f"{PREFIX}/slots/{target_slot}/part{index:04d}.bin"
                source.seek(offset)
                remaining = length
                part_digest = hashlib.sha256()
                while remaining:
                    chunk = source.read(min(IO_CHUNK_SIZE, remaining))
                    if not chunk:
                        raise RuntimeError(
                            "Archive ended while hashing an upload part."
                        )
                    part_digest.update(chunk)
                    remaining -= len(chunk)
                part_hash = part_digest.hexdigest()
                existing_part = target_parts.get(object_path, {})
                if (
                    existing_part.get("size") == length
                    and existing_part.get("sha256") == part_hash
                ):
                    reused_parts += 1
                else:
                    upload_plan.append((offset, length, object_path))
                parts.append(
                    {"path": object_path, "size": length, "sha256": part_hash}
                )
                offset += length
                index += 1

        planned_upload_bytes = sum(length for _, length, _ in upload_plan)
        reserved, reserved_bytes, budget_month = reserve_monthly_upload_budget(
            planned_upload_bytes
        )
        if not reserved:
            print(
                "Supabase snapshot upload skipped: monthly upload budget would "
                f"be exceeded (month={budget_month}, "
                f"reserved={reserved_bytes}, planned={planned_upload_bytes}, "
                f"limit={MONTHLY_UPLOAD_BUDGET_BYTES} bytes).",
                flush=True,
            )
            return

        with archive_path.open("rb") as source:
            for offset, length, object_path in upload_plan:
                upload_file_range(source, offset, length, object_path)

        uploaded_parts = len(upload_plan)

        now = datetime.now(timezone.utc).isoformat()
        manifest = {
            "version": 2,
            "slot": target_slot,
            "format": "tar",
            "created_at": now,
            "size": archive_size,
            "sha256": archive_hash,
            "parts": parts,
        }
        manifest_object = f"{PREFIX}/slots/{target_slot}/manifest.json"
        request_object(
            "POST",
            manifest_object,
            json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
        )
        new_pointer = {
            "version": 2,
            "current": target_slot,
            "previous": base_slot,
            "updated_at": now,
        }
        request_object(
            "POST",
            POINTER_OBJECT,
            json.dumps(new_pointer, separators=(",", ":")).encode("utf-8"),
        )
        write_state(target_slot)
        print(
            f"Supabase v2 snapshot published: slot={target_slot}, "
            f"size={archive_size} bytes, parts={len(parts)}, "
            f"uploaded={uploaded_parts}, reused={reused_parts}, "
            f"month_reserved={reserved_bytes}/{MONTHLY_UPLOAD_BUDGET_BYTES}.",
            flush=True,
        )
    finally:
        archive_path.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"upload", "restore", "verify"}:
        raise SystemExit("Usage: supabase_snapshot_v2.py upload|restore|verify")
    if sys.argv[1] == "upload":
        upload()
    else:
        restore(verify_only=sys.argv[1] == "verify")
