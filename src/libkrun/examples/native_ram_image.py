"""Independent stream-map v1 RAM identity and native sparse-change oracle."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MAX_RAM_LAYOUT_BYTES = 64 * 1024
CHUNK_SIZE = 64 * 1024
MAX_INTEGER = (1 << 53) - 1


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate RAM layout field")
        result[key] = value
    return result


def validate_layout(data: bytes) -> dict:
    if not 0 < len(data) <= MAX_RAM_LAYOUT_BYTES:
        raise ValueError("RAM layout byte bound")
    record = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(record, dict) or set(record) != {
            "architecture", "kind", "magic", "packedLength", "pageGranule", "regions", "schema", "topology"}:
        raise ValueError("RAM layout fields")
    architecture = record["architecture"]
    topology_fields = {
        "x86_64": {"firmwareAddress", "initrdAddress", "ramAboveGap", "ramBelowGap", "ramLastAddress", "shmStartAddress"},
        "aarch64": {"fdtAddress", "firmwareAddress", "initrdAddress", "ramLastAddress", "ramStartAddress", "shmStartAddress"},
    }
    if architecture not in topology_fields or record["kind"] != "ram-layout" or record["magic"] != "KRUNRAML" or type(record["schema"]) is not int or record["schema"] != 1:
        raise ValueError("RAM layout magic/schema/kind/architecture")
    def integer(value):
        if type(value) is not int or not 0 <= value <= MAX_INTEGER:
            raise ValueError("RAM layout integer")
        return value
    granule = integer(record["pageGranule"])
    length = integer(record["packedLength"])
    if granule not in (4096, 8192, 16384, 32768, 65536) or not 0 < length <= 1 << 40:
        raise ValueError("RAM layout length/granule")
    topology = record["topology"]
    if not isinstance(topology, dict) or set(topology) != topology_fields[architecture]:
        raise ValueError("RAM topology fields")
    for value in topology.values():
        integer(value)
    regions = record["regions"]
    if not isinstance(regions, list) or not 1 <= len(regions) <= 512:
        raise ValueError("RAM region count")
    packed, previous_end = 0, 0
    for region in regions:
        if not isinstance(region, dict) or set(region) != {"guestPhysicalAddress", "length", "streamOffset"}:
            raise ValueError("RAM region fields")
        address, size, offset = (integer(region[key]) for key in ("guestPhysicalAddress", "length", "streamOffset"))
        if not size or any(value % granule for value in (address, size, offset)) or address < previous_end or offset != packed:
            raise ValueError("RAM region geometry")
        previous_end, packed = integer(address + size), integer(offset + size)
    if packed != length:
        raise ValueError("RAM packed length")
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if canonical != data:
        raise ValueError("noncanonical RAM layout")
    return record


def layout_digest(data: bytes) -> bytes:
    validate_layout(data)
    return hashlib.sha256(data).digest()


def _readonly_regular(fd: int) -> os.stat_result:
    import fcntl
    metadata = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    excluded = os.O_APPEND | getattr(os, "O_PATH", 0) | getattr(os, "O_DIRECT", 0)
    if not stat.S_ISREG(metadata.st_mode) or flags & os.O_ACCMODE != os.O_RDONLY or flags & excluded:
        raise ValueError("RAM authentication requires readonly regular descriptors")
    return metadata


def _read_exact(fd: int, size: int, offset: int) -> bytes:
    parts = bytearray()
    while len(parts) < size:
        data = os.pread(fd, size - len(parts), offset + len(parts))
        if not data:
            raise ValueError("truncated RAM authentication input")
        parts.extend(data)
    return bytes(parts)


def unit_identities(fd: int, length: int):
    """Independent byte oracle; short tails are never padded."""
    for index, offset in enumerate(range(0, length, CHUNK_SIZE)):
        data = _read_exact(fd, min(CHUNK_SIZE, length - offset), offset)
        yield index, hashlib.sha256(data).digest() if any(data) else None


def stream_root(fd: int, length: int) -> bytes:
    """Five 64-way frontiers, not a list proportional to logical RAM."""
    if not 0 <= length <= 1 << 40:
        raise ValueError("RAM identity length")
    slots = [{} for _ in range(5)]
    groups = [None] * 5
    tree = None

    def flush(height):
        nonlocal tree
        if not slots[height]:
            return
        bitmap = sum(1 << slot for slot in slots[height])
        prefix = (b"silo:stream-map:leaf:v1\n" if height == 0 else
                  b"silo:stream-map:branch:v1\n" + bytes([height]))
        encoded = prefix + struct.pack("<Q", bitmap)
        encoded += b"".join(slots[height][slot] for slot in sorted(slots[height]))
        digest = hashlib.sha256(encoded).digest()
        group = groups[height]
        slots[height] = {}
        groups[height] = None
        if height == 4:
            tree = digest
        else:
            push(height + 1, group, digest)

    def push(height, index, digest):
        group, slot = divmod(index, 64)
        if groups[height] is not None and groups[height] != group:
            flush(height)
        groups[height] = group
        slots[height][slot] = digest

    for index, digest in unit_identities(fd, length):
        if digest is not None:
            push(0, index, digest)
    for height in range(5):
        flush(height)
    return b"silo:stream:v1\n" + struct.pack("<BQB", 16, length, tree is not None) + (tree or b"")


def iter_changes(path: Path, length: int, mode: str):
    """Strict constant-memory decoder for native RAM changes v1."""
    if mode not in ("full", "incremental") or not 0 <= length <= 1 << 40:
        raise ValueError("RAM changes coverage/length")
    units = (length + CHUNK_SIZE - 1) // CHUNK_SIZE
    previous_end, previous_zero = 0, False
    with path.open("rb") as source:
        header = source.read(16)
        expected = b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, mode == "incremental", 0)
        if header != expected:
            raise ValueError("RAM changes header")
        while record := source.read(56):
            if len(record) != 56:
                raise ValueError("truncated RAM changes record")
            first, count, kind, reserved, digest = struct.unpack("<QQB7s32s", record)
            if (reserved != bytes(7) or kind not in (0, 1) or not count
                    or first < previous_end or first + count > units
                    or (kind == 1 and count != 1)
                    or (kind == 0 and (digest != bytes(32) or mode == "full"
                                      or (previous_zero and first == previous_end)))):
                raise ValueError("noncanonical RAM changes record")
            previous_end, previous_zero = first + count, kind == 0
            yield first, count, digest if kind else None


def authenticate_image(ram: Path, layout: Path, expected_layout_digest: bytes,
                       prepared: bytes | None = None, *, ram_fd: int | None = None,
                       layout_fd: int | None = None) -> dict:
    owned = []
    try:
        if ram_fd is None:
            ram_fd = os.open(ram, os.O_RDONLY | os.O_NONBLOCK)
            owned.append(ram_fd)
        if layout_fd is None:
            layout_fd = os.open(layout, os.O_RDONLY | os.O_NONBLOCK)
            owned.append(layout_fd)
        ram_metadata, layout_metadata = _readonly_regular(ram_fd), _readonly_regular(layout_fd)
        if (ram_metadata.st_dev, ram_metadata.st_ino) == (layout_metadata.st_dev, layout_metadata.st_ino):
            raise ValueError("RAM and layout roles alias")
        if not 0 < layout_metadata.st_size <= MAX_RAM_LAYOUT_BYTES:
            raise ValueError("RAM layout byte bound")
        data = _read_exact(layout_fd, layout_metadata.st_size, 0)
        record = validate_layout(data)
        actual_layout = hashlib.sha256(data).digest()
        if not isinstance(expected_layout_digest, bytes) or len(expected_layout_digest) != 32 or actual_layout != expected_layout_digest:
            raise ValueError("RAM layout object digest mismatch")
        if prepared is not None and data != prepared:
            raise ValueError("RAM layout differs from exact preparation")
        if ram_metadata.st_size != record["packedLength"]:
            raise ValueError("RAM image logical length mismatch")
        root = stream_root(ram_fd, ram_metadata.st_size)
        stream_digest = hashlib.sha256(root).hexdigest()
        def unchanged(fd, original):
            current = os.fstat(fd)
            return all(getattr(current, field) == getattr(original, field) for field in
                       ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns"))
        if not unchanged(ram_fd, ram_metadata) or not unchanged(layout_fd, layout_metadata):
            raise ValueError("RAM authentication input changed")
        return {"layout_digest": actual_layout.hex(), "stream_digest": stream_digest,
                "caller_authentication_bytes_read": len(data) + ram_metadata.st_size,
                "stream_root": root.hex(),
                "ram_inode": [ram_metadata.st_dev, ram_metadata.st_ino],
                "layout_inode": [layout_metadata.st_dev, layout_metadata.st_ino]}
    finally:
        for fd in owned:
            os.close(fd)


def authentication_bytes(authentication: dict) -> bytes:
    result = bytes.fromhex(authentication["layout_digest"]) + bytes.fromhex(authentication["stream_digest"])
    if len(result) != 64:
        raise ValueError("RAM authentication must contain two 32-byte identities")
    return result


def write_authentication(path: Path, authentication: dict) -> None:
    with path.open("xb") as output:
        output.write(authentication_bytes(authentication))
        output.flush()
        os.fsync(output.fileno())
