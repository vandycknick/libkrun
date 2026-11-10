"""Bounded native RAM proofs, with cumulative and accepted-generation modes.

The cumulative mode deliberately never accepts a baseline. The incremental mode
uses actual native candidates and accounting, with independent full-cut file
comparison. Neither mode qualifies physical sharing or restored reclaim.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import unittest
import tempfile

from native_device_controller import COUNTERS, Session, digest, save, seal_cut

MAX_RAM = 1024 * 1024 * 1024
SCOPE = "cumulative-union-no-accepted-baseline"
LEDGER_SCOPE = "accepted-baseline-ledger"
IO_COUNTERS = frozenset(("logical_bytes", "live_bytes_read", "baseline_bytes_read",
    "baseline_bytes_written", "overlay_bytes_written", "full_bytes_written", "layout_bytes_written",
    "baseline_hole_bytes", "zero_bytes_omitted", "explicit_zero_bytes_written", "extent_queries"))


class MemorySession(Session):
    def command(self, command: str, error: bool = False, timeout: float = 30):
        if command.startswith("capture "):
            directory = command.split(" ", 1)[1]
            return self.command(f"capture-cumulative {directory}", error=error, timeout=timeout)
        record = {"command": command, "native_pid": self.process.pid,
                  "started_monotonic_ns": time.monotonic_ns()}
        try:
            response = Session.command(self, command, error=error, timeout=timeout)
            record["response"] = response
            return response
        except BaseException as failure:
            record["error"] = str(failure)
            raise
        finally:
            record["finished_monotonic_ns"] = time.monotonic_ns()
            with (self.directory / "memory-commands.jsonl").open("a") as output:
                output.write(json.dumps(record, sort_keys=True) + "\n")


def unique_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate memory metadata field: {name}")
        result[name] = value
    return result


def bounded_file(path: Path, limit: int) -> bytes:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError(f"invalid bounded regular file: {path}")
    with path.open("rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"file exceeds bound: {path}")
    return value


def load_cut(directory: Path, scope: str = SCOPE) -> tuple[dict, bytes]:
    metadata = json.loads(bounded_file(directory / "memory-dirty.json", 128 * 1024),
                          object_pairs_hook=unique_fields)
    required = {"schema", "scope", "bitmap_encoding", "granule", "packed_len", "page_count",
                "dirty_pages", "bitmap_bytes", "pause_generation", "regions"}
    if (not isinstance(metadata, dict) or set(metadata) != required or metadata["schema"] != 1
            or metadata["scope"] != scope or metadata["bitmap_encoding"] != "u64-le-lsb0-dense"):
        raise ValueError("unknown native dirty metadata schema/scope")
    for key in ("granule", "packed_len", "page_count", "dirty_pages", "bitmap_bytes", "pause_generation"):
        if type(metadata[key]) is not int or metadata[key] < 0:
            raise ValueError(f"invalid native geometry integer: {key}")
    granule = metadata["granule"]
    if (not 4096 <= granule <= 65536 or granule & (granule - 1)
            or not 0 < metadata["packed_len"] <= MAX_RAM
            or not isinstance(metadata["regions"], list) or not 1 <= len(metadata["regions"]) <= 512):
        raise ValueError("native dirty geometry bound")
    packed = pages = previous_end = 0
    for index, region in enumerate(metadata["regions"]):
        if (not isinstance(region, dict)
                or set(region) != {"id", "gpa", "byte_len", "stream_offset", "first_page"}
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in region.values())
                or region["id"] != index or region["gpa"] < previous_end
                or region["gpa"] % granule or not region["byte_len"]
                or region["byte_len"] % granule or region["gpa"] + region["byte_len"] >= 1 << 64
                or region["stream_offset"] != packed or region["first_page"] != pages):
            raise ValueError("noncanonical native dense region geometry")
        previous_end = region["gpa"] + region["byte_len"]
        packed += region["byte_len"]
        pages += region["byte_len"] // granule
    if (packed != metadata["packed_len"] or pages != metadata["page_count"]
            or metadata["bitmap_bytes"] != ((pages + 63) // 64) * 8):
        raise ValueError("native bitmap/packed geometry mismatch")
    bitmap = bounded_file(directory / "memory-dirty.bitmap", ((MAX_RAM // 4096 + 63) // 64) * 8)
    if len(bitmap) != metadata["bitmap_bytes"]:
        raise ValueError("native dense bitmap length mismatch")
    bits = int.from_bytes(bitmap, "little")
    if bits >> pages or bits.bit_count() != metadata["dirty_pages"]:
        raise ValueError("native dense bitmap padding/count mismatch")
    ram = (directory / "memory.ram").stat()
    if not stat.S_ISREG(ram.st_mode) or ram.st_size != packed:
        raise ValueError("complete RAM cut length mismatch")
    return metadata, bitmap


def marked(bitmap: bytes, page: int) -> bool:
    return bool(bitmap[page // 8] & (1 << (page % 8)))


def compare_cuts(previous: Path, current: Path) -> dict:
    before, old_bitmap = load_cut(previous)
    after, bitmap = load_cut(current)
    geometry = ("granule", "packed_len", "page_count", "regions")
    if any(before[key] != after[key] for key in geometry):
        raise ValueError("consecutive cut registered geometry changed")
    if after["pause_generation"] <= before["pause_generation"]:
        raise ValueError("consecutive cuts lack a fresh completed native pause")
    if any(old & ~new for old, new in zip(old_bitmap, bitmap)):
        raise ValueError("unaccepted cumulative dirty coverage was lost across resume")
    changed = missing = 0
    regions = []
    granule = after["granule"]
    with (previous / "memory.ram").open("rb") as left, (current / "memory.ram").open("rb") as right:
        for region in after["regions"]:
            count = absent = dirty = 0
            for local in range(region["byte_len"] // granule):
                page = region["first_page"] + local
                old = left.read(granule)
                new = right.read(granule)
                if len(old) != granule or len(new) != granule:
                    raise ValueError("complete RAM cut truncated during comparison")
                observed = marked(bitmap, page)
                dirty += observed
                if old != new:
                    count += 1
                    absent += not observed
            regions.append({"id": region["id"], "gpa": region["gpa"],
                            "pages": region["byte_len"] // granule, "dirty_pages": dirty,
                            "changed_pages": count, "missing_dirty_pages": absent})
            changed += count
            missing += absent
    result = {"previous": str(previous), "current": str(current), "scope": SCOPE,
              "granule": granule, "scanned_pages": after["page_count"],
              "dirty_pages": after["dirty_pages"], "changed_pages": changed,
              "missing_dirty_pages": missing, "regions": regions}
    if not changed or missing:
        raise ValueError(f"native changed-page coverage failed: {json.dumps(result, sort_keys=True)}")
    return result


def fixture_page(directory: Path, gpa: int, scope: str = SCOPE,
                 require_dirty: bool = True) -> tuple[bytes, int]:
    metadata, bitmap = load_cut(directory, scope)
    if type(gpa) is not int or gpa % 4096:
        raise ValueError("fixture GPA is not an aligned integer")
    for region in metadata["regions"]:
        offset = gpa - region["gpa"]
        if 0 <= offset and offset + 4096 <= region["byte_len"]:
            with (directory / "memory.ram").open("rb") as source:
                source.seek(region["stream_offset"] + offset)
                data = source.read(4096)
            page = region["first_page"] + offset // metadata["granule"]
            if require_dirty and not marked(bitmap, page):
                raise ValueError("actual fixture page absent from harvested native union")
            return data, page
    raise ValueError("fixture GPA not contained in actual registered RAM")

def saved_ram_range(directory: Path, gpa: int, length: int, scope: str,
                    require_dirty: bool) -> bytes:
    metadata, bitmap = load_cut(directory, scope)
    if type(gpa) is not int or gpa < 0 or type(length) is not int or not 0 < length <= 4096:
        raise ValueError("bounded saved RAM range")
    result = bytearray()
    with (directory / "memory.ram").open("rb") as source:
        for region in metadata["regions"]:
            offset = gpa + len(result) - region["gpa"]
            if not 0 <= offset < region["byte_len"]:
                continue
            size = min(length - len(result), region["byte_len"] - offset)
            if require_dirty:
                first = region["first_page"] + offset // metadata["granule"]
                last = region["first_page"] + (offset + size - 1) // metadata["granule"]
                if any(not marked(bitmap, page) for page in range(first, last + 1)):
                    raise ValueError("native installation structure absent from dirty coverage")
            source.seek(region["stream_offset"] + offset)
            data = source.read(size)
            if len(data) != size:
                raise ValueError("saved native structure truncated")
            result.extend(data)
            if len(result) == length:
                return bytes(result)
    raise ValueError("native installation structure crosses unregistered RAM")


def wall_clock_observations(previous: Path, current: Path, gpas: list[int],
                            scope: str = LEDGER_SCOPE) -> list[dict]:
    # Linux pvclock_wall_clock is packed version/sec/nsec, not an entire page.
    records = []
    for gpa in gpas:
        inherited = saved_ram_range(previous, gpa, 12, scope, require_dirty=False)
        installed = saved_ram_range(current, gpa, 12, scope, require_dirty=True)
        records.append({"gpa": gpa, "bytes": 12, "inherited_hex": inherited.hex(),
                        "installed_hex": installed.hex(), "changed": inherited != installed})
    return records



def validate_buffer(observation: dict, token: str) -> None:
    required = {"request_token", "host_gpa", "cpu_gpa", "bytes", "host_byte", "cpu_byte",
                "cpu_generation", "mlocked", "pipe_page_refs_retained", "pipe_bytes",
                "pagemap_present"}
    if (not isinstance(observation, dict) or set(observation) != required
            or observation["request_token"] != token
            or any(observation[key] is not True
                   for key in ("mlocked", "pipe_page_refs_retained", "pagemap_present"))
            or any(type(observation[key]) is not int or observation[key] < 0
                   for key in ("host_gpa", "cpu_gpa", "bytes", "host_byte", "cpu_byte",
                               "cpu_generation", "pipe_bytes"))
            or any(not 0 < observation[key] < (1 << 64) or observation[key] % 4096
                   for key in ("host_gpa", "cpu_gpa"))
            or observation["host_gpa"] == observation["cpu_gpa"]
            or observation["bytes"] != 4096 or observation["pipe_bytes"] != 8192
            or observation["host_byte"] > 255 or observation["cpu_byte"] > 255):
        raise RuntimeError("guest memory buffer ownership/nonce observation differs")




def observe_buffer(source: Session, cpu_write: bool = False, cpu_zero: bool = False) -> dict:
    token = os.urandom(16).hex()
    source.observations.pop("memory-buffer", None)
    if cpu_write and cpu_zero:
        raise ValueError("one CPU write operation per observation")
    command = ("Z" if cpu_zero else "D" if cpu_write else "H") + token + "\n"
    started = time.monotonic_ns()
    if os.write(source.console, command.encode("ascii")) != len(command):
        raise RuntimeError("guest memory request write was short")
    source.until(lambda: "memory-buffer" in source.observations, "actual pinned guest memory observation")
    observation = json.loads(source.observations["memory-buffer"], object_pairs_hook=unique_fields)
    validate_buffer(observation, token)
    observation.update(command=command.strip(), started_monotonic_ns=started,
                       completed_monotonic_ns=time.monotonic_ns())
    return observation


def capture(source: Session, directory: Path, observation: dict) -> dict:
    source.command("pause")
    source.command("status")
    source.command("state")
    source.command(f"capture {directory}")
    metadata, _ = load_cut(directory)
    for kind in ("host", "cpu"):
        data, page = fixture_page(directory, observation[f"{kind}_gpa"])
        if data != bytes([observation[f"{kind}_byte"]]) * 4096:
            raise RuntimeError(f"final paused RAM differs from actual {kind} buffer observation")
        observation[f"{kind}_dense_page"] = page
    manifest = seal_cut(directory)
    for name in ("memory-dirty.json", "memory-dirty.bitmap"):
        path = directory / name
        manifest[name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        path.chmod(0o400)
    save(directory / "memory-proof-manifest.json", manifest)
    save(directory / "memory-buffer-observation.json", observation)
    return {"cut": str(directory), "layout": metadata, "manifest": manifest, "buffer": observation}


def validate_host_write(observed: dict, gpa: int, page: int, before: int, after: int) -> None:
    expected = {"gpa": gpa, "dense_page": page, "bytes": 4096, "before": before, "after": after,
                "host_dirty_before": False, "host_dirty_after": True, "readback_verified": True,
                "path": "RuntimeGuestMemory::write_slice"}
    if (observed != expected or observed.get("host_dirty_before") is not False
            or observed.get("host_dirty_after") is not True):
        raise RuntimeError("actual host write lacks clean-to-dirty active host-map transition/readback")


def observe_host_page(source: Session, gpa: int, page: int) -> dict:
    start = len(source.replies)
    source.command(f"memory-host-page {gpa}")
    raw = [line for line in source.replies[start:] if line.startswith("HOST_MEMORY_PAGE ")]
    if len(raw) != 1:
        raise RuntimeError("missing read-only active host-page observation")
    observed = json.loads(raw[0].split(" ", 1)[1])
    if observed != {"gpa": gpa, "dense_page": page, "host_dirty": False} or observed.get("host_dirty") is not False:
        raise RuntimeError("dedicated CPU page has unexpected active host-writer coverage")
    return observed


def source_identity(root: Path) -> dict:
    files = ["src/libkrun/src/api/vmm_builder/native_device_probe.rs",
             "src/libkrun/examples/native_device_controller.py",
             "src/libkrun/examples/native_memory_controller.py",
             "src/libkrun/examples/native_device_linux.c", "src/arch/src/guest_memory/domain.rs",
             "src/devices/src/virtio/memory.rs", "src/libkrun/src/vmm/memory.rs",
             "src/libkrun/src/vmm/linux/vstate.rs", "src/libkrun/src/api/device_builders.rs",
             "src/libkrun/src/vmm/execution/device_restore.rs", "Cargo.lock", "Makefile"]
    return {"revision": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                                 text=True, timeout=5).strip(),
            "files": {name: digest(root / name) for name in files},
            "binary_source_binding": "binary and current source separately hashed, not a reproducible-build attestation"}


def run(args, echo) -> dict:
    # Four complete cuts plus one repeated frozen cut and their two 128MiB disks.
    if shutil.disk_usage(args.evidence).free < 8 * MAX_RAM:
        raise RuntimeError("memory proof requires 8GiB free for bounded retained full-cut oracle")
    root = Path(__file__).resolve().parents[3]
    save(args.evidence / "memory-source-identity.json", source_identity(root))
    report = {"scope": SCOPE, "baseline_accepted": False, "incremental_image_equivalence": False,
              "redirty_after_baseline_clear": "not-tested-commit8", "cuts": [], "comparisons": [],
              "host_writer_coverage": "actual-active-host-map-clean-to-dirty-before-final-union",
              "cpu_writer_scope": "guest-D-store-and-full-cut-change-with-host-map-clean; cumulative CPU coverage only",
              "host_writes": [], "all_reaped": False}
    disks = []
    source = None
    try:
        for index in range(2):
            path = args.evidence / f"memory-source-disk{index}.raw"
            with path.open("xb") as output:
                output.truncate(128 * 1024 * 1024)
            command = ["mkfs.ext4", "-F", "-q", str(path)]
            save(args.evidence / f"memory-mkfs{index}-command.json", command)
            with path.with_suffix(".mkfs.log").open("xb") as log:
                subprocess.run(command, check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT)
            disks.append(path)
        source = MemorySession.create(args, args.evidence / "memory-source", disks, echo)
        source.start_mux()
        previous_work = source.progress()
        source.profile()
        observation = observe_buffer(source)
        if (observation["host_byte"], observation["cpu_byte"], observation["cpu_generation"]) != (0x48, 0x43, 0):
            raise RuntimeError("initial real allocated memory buffers differ")
        previous = args.evidence / "memory-cut-0"
        report["cuts"].append(capture(source, previous, observation))
        refusal = source.command(f"memory-host-write {observation['host_gpa']} 72 73", error=True)
        report["sealed_writer_refusal"] = refusal
        source.pump(.2)
        repeated = args.evidence / "memory-cut-0-repeated"
        source.command(f"capture {repeated}")
        load_cut(repeated)
        for name in ("memory.ram", "memory-dirty.json", "memory-dirty.bitmap", "execution.state",
                     "devices.state", "disk0.raw", "disk1.raw"):
            if digest(previous / name) != digest(repeated / name):
                raise RuntimeError(f"final paused cut mutated under actual endpoint stimulation: {name}")
        report["frozen_repeated_cut"] = {"cut": str(repeated), "memory_sha256": digest(repeated / "memory.ram")}
        initial_gpas = (observation["host_gpa"], observation["cpu_gpa"])
        for generation, writer in enumerate(("host", "cpu", "host"), 1):
            source.command("resume")
            prior = observation.copy()
            cpu_host_before = observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
            if writer == "host":
                before = observation["host_byte"]
                command = f"memory-host-write {observation['host_gpa']} {before} {before + 1}"
                start = len(source.replies)
                response = source.command(command)
                raw = [line for line in source.replies[start:] if line.startswith("HOST_MEMORY_WRITE ")]
                if len(raw) != 1:
                    raise RuntimeError("missing actual RuntimeGuestMemory host write readback observation")
                observed_write = json.loads(raw[0].split(" ", 1)[1])
                validate_host_write(observed_write, observation["host_gpa"], observation["host_dense_page"],
                                    before, before + 1)
                report["host_writes"].append({"command": command, "response": response,
                                               "native_observation": observed_write})
            previous_work = source.progress(previous_work)
            observation = observe_buffer(source, cpu_write=writer == "cpu")
            cpu_host_after = observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
            if (observation["host_gpa"], observation["cpu_gpa"]) != initial_gpas:
                raise RuntimeError("pinned buffer GPA changed across real resume")
            expected_host = prior["host_byte"] + (writer == "host")
            expected_cpu = prior["cpu_byte"] + (writer == "cpu")
            if (observation["host_byte"], observation["cpu_byte"], observation["cpu_generation"]) != (
                    expected_host, expected_cpu, prior["cpu_generation"] + (writer == "cpu")):
                raise RuntimeError("CPU/host directional buffer changes differ from actual guest observation")
            current = args.evidence / f"memory-cut-{generation}"
            report["cuts"].append(capture(source, current, observation))
            comparison = compare_cuts(previous, current)
            for kind in ("host", "cpu"):
                old, _ = fixture_page(previous, observation[f"{kind}_gpa"])
                new, _ = fixture_page(current, observation[f"{kind}_gpa"])
                if (old != new) != (kind == writer):
                    raise RuntimeError("dedicated page changed without its actual directional writer")
            comparison.update(writer=writer, guest_work=previous_work,
                              native_pid=source.process.pid, guest_observation=observation)
            comparison["cpu_active_host_map"] = {"before": cpu_host_before, "after": cpu_host_after}
            if any(previous_work[key] <= 0 for key in COUNTERS):
                raise RuntimeError("actual ordinary provider workload observation missing")
            save(args.evidence / f"memory-comparison-{generation}.json", comparison)
            report["comparisons"].append(comparison)
            previous = current
        source.stop()
        report["native_stop"] = json.loads((source.directory / "native-stop.json").read_text())
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        if source is not None:
            native_reaped = source.native_reaped
            netd_pid = source.netd.pid if source.netd else None
            netd = source.netd
            failures = source.close()
            report["reaping"] = {"native_reaped": native_reaped, "netd_pid": netd_pid,
                                 "netd_exit_status": netd.returncode if netd else None,
                                 "cleanup_failures": failures}
            report["all_reaped"] = native_reaped and netd is not None and netd.returncode is not None and not failures
        if report.get("status") == "passed" and not report["all_reaped"]:
            report.update(status="failed", error="native/netd reaping evidence missing")
        save(args.evidence / "memory-report.json", report)
    if not report["all_reaped"]:
        raise RuntimeError("memory proof lacks actual native/netd owner reaping evidence")
    return report


def image_record(directory: Path, mode: str, baseline: int | None) -> dict:
    record = json.loads(bounded_file(directory / "memory-image.json", 128 * 1024),
                        object_pairs_hook=unique_fields)
    required = {"schema", "scope", "mode", "fallback", "baseline_generation",
                "candidate_generation", "attempt_sequence", "pause_generation",
                "dirty_pages", "stats", "affected_chunks"}
    if (not isinstance(record, dict) or set(record) != required
            or type(record["schema"]) is not int or record["schema"] != 1
            or record["scope"] != LEDGER_SCOPE or record["mode"] != mode
            or record["baseline_generation"] != baseline
            or type(record["baseline_generation"]) not in (int, type(None))
            or not isinstance(record["stats"], dict) or set(record["stats"]) != IO_COUNTERS):
        raise ValueError("native RAM image mode/baseline/schema mismatch")
    for key in ("candidate_generation", "attempt_sequence", "pause_generation", "dirty_pages"):
        if type(record[key]) is not int or record[key] < 0:
            raise ValueError("native RAM image identity/count integer")
    if (record["candidate_generation"] <= (baseline or 0)
            or not record["attempt_sequence"]):
        raise ValueError("native RAM candidate identity did not advance")
    if any(type(value) is not int or value < 0 for value in record["stats"].values()):
        raise ValueError("native RAM I/O counter integer")
    if ((mode == "incremental" and (baseline is None or record["fallback"] is not None))
            or (mode == "full" and record["fallback"] not in
                ("requested-full", "no-baseline", "baseline-token", "coverage-lost", "dirty-crossover"))):
        raise ValueError("native RAM image fallback contradicts selection")
    scope = SCOPE if baseline is None else LEDGER_SCOPE
    metadata, bitmap = load_cut(directory, scope)
    stats = record["stats"]
    if (record["pause_generation"] != metadata["pause_generation"]
            or record["dirty_pages"] != metadata["dirty_pages"]
            or stats["logical_bytes"] != metadata["packed_len"]
            or stats["layout_bytes_written"] != (directory / "memory-layout.json").stat().st_size):
        raise ValueError("native RAM image accounting/cut mismatch")
    expected_live = (metadata["dirty_pages"] * metadata["granule"]
                     if mode == "incremental" else metadata["packed_len"])
    if stats["live_bytes_read"] != expected_live:
        raise ValueError("native writer live-read accounting differs from selected pages")
    if mode == "incremental":
        if (stats["full_bytes_written"] or stats["overlay_bytes_written"] != expected_live
                or stats["explicit_zero_bytes_written"] > stats["overlay_bytes_written"]):
            raise ValueError("native dirty overlay accounting mismatch")
        chunks = sorted({page * metadata["granule"] // (8 * 1024 * 1024)
                         for page in range(metadata["page_count"]) if marked(bitmap, page)})
    else:
        if any(stats[key] for key in ("baseline_bytes_read", "baseline_bytes_written",
                                      "overlay_bytes_written", "explicit_zero_bytes_written")):
            raise ValueError("native full writer claims incremental work")
        chunks = list(range((metadata["packed_len"] + 8 * 1024 * 1024 - 1) // (8 * 1024 * 1024)))
    if (not isinstance(record["affected_chunks"], list)
            or any(type(chunk) is not int for chunk in record["affected_chunks"])
            or record["affected_chunks"] != chunks):
        raise ValueError("native affected-chunk accounting mismatch")
    return record


def same_cut(incremental: Path, full: Path, baseline: int) -> dict:
    left = image_record(incremental, "incremental", baseline)
    right = image_record(full, "full", baseline)
    old, bitmap = load_cut(incremental, LEDGER_SCOPE)
    new, full_bitmap = load_cut(full, LEDGER_SCOPE)
    if (old != new or bitmap != full_bitmap
            or left["pause_generation"] != right["pause_generation"]
            or left["attempt_sequence"] == right["attempt_sequence"]):
        raise ValueError("comparison lacks distinct attempts at the exact same sealed cut")
    for name in ("memory.ram", "memory-layout.json", "execution.state", "devices.state"):
        if digest(incremental / name) != digest(full / name):
            raise ValueError(f"incremental and forced-full same-cut output differs: {name}")
    return {"incremental": str(incremental), "forced_full": str(full),
            "incremental_receipt": left, "full_receipt": right,
            "memory_sha256": digest(full / "memory.ram"),
            "live_read_evidence": "actual native writer counters, not inferred from equality"}


def accept_image(session: MemorySession, directory: Path) -> dict:
    from native_ram_image import authentication_bytes
    authentication = json.loads(bounded_file(directory / "memory-authentication.json", 128 * 1024),
                                object_pairs_hook=unique_fields)
    path = directory / "memory-authentication.bin"
    if bounded_file(path, 64) != authentication_bytes(authentication):
        raise ValueError("completed candidate authentication identity changed")
    session.command(f"memory-accept {path}")
    return authentication


def retain_image(directory: Path) -> dict:
    manifest = seal_cut(directory)
    for name in ("memory-layout.json", "memory-image.json", "memory-dirty.json", "memory-dirty.bitmap"):
        path = directory / name
        manifest[name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        path.chmod(0o400)
    save(directory / "memory-proof-manifest.json", manifest)
    return manifest


def native_capture(session: MemorySession, directory: Path, mode: str,
                   baseline: int | None, prepared: bool = False, request: str | None = None) -> dict:
    command = "prepared-memory-capture" if prepared else "memory-capture"
    session.command(f"{command} {directory} {request or mode}")
    record = image_record(directory, mode, baseline)
    from native_ram_image import authenticate_image, write_authentication
    if session.prepared_layout is None:
        raise RuntimeError("native candidate lacks exact pre-capture canonical preparation")
    expected = bounded_file(directory / "binding/ram-layout", 32)
    authentication = authenticate_image(directory / "memory.ram", directory / "memory-layout.json",
                                        expected, session.prepared_layout)
    save(directory / "memory-authentication.json", authentication)
    write_authentication(directory / "memory-authentication.bin", authentication)
    retain_image(directory)
    return record


def compare_and_accept(session: MemorySession, root: Path, label: str, baseline: int,
                       prepared: bool = False, accept_incremental: bool = False) -> tuple[Path, dict]:
    incremental, full = root / f"{label}-incremental", root / f"{label}-full"
    first, first_mode = (full, "full") if accept_incremental else (incremental, "incremental")
    accepted, accepted_mode = (incremental, "incremental") if accept_incremental else (full, "full")
    native_capture(session, first, first_mode, baseline, prepared)
    refusal = observe_busy(session, "release" if prepared else "resume")
    session.command("memory-abandon")
    native_capture(session, accepted, accepted_mode, baseline, prepared)
    comparison = same_cut(incremental, full, baseline)
    comparison["busy_resume"] = refusal
    comparison["accepted_mode"] = accepted_mode
    comparison["accepted_generation"] = comparison[
        "incremental_receipt" if accept_incremental else "full_receipt"]["candidate_generation"]
    comparison["authentication"] = accept_image(session, accepted)
    return accepted, comparison


def host_write(session: MemorySession, observation: dict, after: int) -> dict:
    start = len(session.replies)
    gpa = observation["host_gpa"]
    session.command(f"memory-host-write {gpa} {observation['host_byte']} {after}")
    records = [line for line in session.replies[start:] if line.startswith("HOST_MEMORY_WRITE ")]
    if len(records) != 1:
        raise RuntimeError("missing actual host writer evidence")
    record = json.loads(records[0].split(" ", 1)[1], object_pairs_hook=unique_fields)
    validate_host_write(record, gpa, observation["host_dense_page"], observation["host_byte"], after)
    return record


def check_buffer_image(directory: Path, observation: dict, dirty: tuple[str, ...]) -> dict:
    result = dict(observation)
    for kind in ("host", "cpu"):
        data, page = fixture_page(directory, observation[f"{kind}_gpa"], LEDGER_SCOPE,
                                  require_dirty=kind in dirty)
        if data != bytes([observation[f"{kind}_byte"]]) * 4096:
            raise RuntimeError("actual fixture bytes differ from completed RAM output")
        result[f"{kind}_dense_page"] = page
    return result


def zero_cut(session: MemorySession, root: Path, label: str, baseline: int,
             reference: Path, prepared: bool = False) -> tuple[Path, dict]:
    directory = root / label
    record = native_capture(session, directory, "incremental", baseline, prepared)
    if record["dirty_pages"] or record["stats"]["live_bytes_read"] or record["affected_chunks"]:
        raise RuntimeError("same-cut accepted baseline did not yield zero live reads/dirties")
    if any(digest(reference / name) != digest(directory / name)
           for name in ("memory.ram", "memory-layout.json")):
        raise RuntimeError("zero-dirty output is not the complete unchanged stream")
    record["authentication"] = accept_image(session, directory)
    return directory, record


def prepared_observation(session: MemorySession, path: Path) -> dict:
    session.command(f"memory-prepared {path}")
    record = json.loads(bounded_file(path, 64 * 1024), object_pairs_hook=unique_fields)
    validate_prepared(record)
    return record


def validate_prepared(record: dict) -> None:
    if (not isinstance(record, dict) or set(record) != {"schema", "native_run_entries",
            "wall_clock_gpas", "baseline_generation", "backing"}
            or type(record["schema"]) is not int or record["schema"] != 1):
        raise RuntimeError("prepared child evidence schema differs")
    runs = record.get("native_run_entries")
    gpas = record.get("wall_clock_gpas")
    if (not isinstance(runs, list) or not runs
            or any(type(value) is not int or value != 0 for value in runs)
            or not isinstance(gpas, list) or not gpas
            or any(type(value) is not int or not 0 < value < 1 << 64 for value in gpas)
            or type(record.get("baseline_generation")) is not int or record["baseline_generation"] < 1
            or not isinstance(record["backing"], dict)
            or set(record["backing"]) != {"device", "inode"}
            or any(type(value) is not int or value < 0 for value in record["backing"].values())
            or not record["backing"]["inode"]):
        raise RuntimeError("prepared child lacks actual zero-entry/PV wall-clock baseline evidence")


def failed_output_record(directory: Path, baseline: int, logical_bytes: int) -> dict:
    record = json.loads(bounded_file(directory / "memory-failure.json", 128 * 1024),
                        object_pairs_hook=unique_fields)
    required = {"schema", "kind", "role", "problem", "effects",
                "baseline_generation", "attempt_sequence", "stats"}
    if (not isinstance(record, dict) or set(record) != required
            or type(record["schema"]) is not int or record["schema"] != 1
            or record["kind"] != "ram-image-failure" or record["role"] != "output-ram"
            or record["problem"] != "wrong-access" or record["effects"] != "none"
            or type(record["baseline_generation"]) is not int
            or record["baseline_generation"] != baseline
            or type(record["attempt_sequence"]) is not int or record["attempt_sequence"] <= 0
            or not isinstance(record["stats"], dict) or set(record["stats"]) != IO_COUNTERS
            or any(type(value) is not int or value != (logical_bytes if key == "logical_bytes" else 0)
                   for key, value in record["stats"].items())):
        raise ValueError("typed output failure role/effects/accounting/baseline mismatch")
    return record


def observe_busy(session: MemorySession, command: str) -> dict:
    start = len(session.replies)
    releases = len(session.releases)
    response = session.command(command, error=True)
    records = [line for line in session.replies[start:] if line.startswith("MEMORY_COMMAND_FAILURE ")]
    if len(records) != 1:
        raise RuntimeError("missing typed native Busy refusal")
    evidence = json.loads(records[0].split(" ", 1)[1], object_pairs_hook=unique_fields)
    validate_busy(evidence, command)
    if len(session.releases) != releases:
        raise RuntimeError("refused resume changed native release/time ownership")
    return {"response": response, "evidence": evidence}


def validate_busy(record: dict, command: str) -> None:
    if (record != {"schema": 1, "command": command, "kind": "busy"}
            or type(record.get("schema")) is not int):
        raise ValueError("native refusal is not typed Busy for the exact command")


def validate_recovery(record: dict, fault_slot: int, recovered: bool,
                      coverage_valid: bool = False) -> None:
    required = {"schema", "registered_slots", "successful_slots", "epoch", "failure",
                "tracking_failure", "coverage_valid", "full_required"}
    expected_failure = {"operation": "collect", "slot": fault_slot,
                        "native_code": errno.EFAULT, "effect": "coverage-lost"}
    if (not isinstance(record, dict) or set(record) != required
            or type(record["schema"]) is not int or record["schema"] != 1
            or record["tracking_failure"] != expected_failure
            or any(type(record["tracking_failure"].get(key)) is not int
                   for key in ("slot", "native_code"))
            or record["coverage_valid"] is not coverage_valid
            or record["full_required"] is not (not coverage_valid)):
        raise ValueError("typed failed-cut recovery/coverage evidence mismatch")
    if recovered:
        registered, successful = record["registered_slots"], record["successful_slots"]
        if (not isinstance(registered, list) or not registered
                or any(type(slot) is not int or not 0 <= slot < 1 << 32 for slot in registered)
                or len(set(registered)) != len(registered) or fault_slot not in registered
                or successful != registered or any(type(slot) is not int for slot in successful)
                or type(record["epoch"]) is not int or record["epoch"] <= 0
                or record["failure"] is not None):
            raise ValueError("recovery lacks actual all-registered-slot GET success and fresh epoch")


def recovery_proof(source: MemorySession, root: Path, baseline: int,
                   observation: dict) -> tuple[Path, int, dict, dict]:
    source.command("resume")
    prior = observation
    host_before = host_write(source, prior, prior["host_byte"] + 1)
    observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
    observation = observe_buffer(source, cpu_write=True)
    observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
    if (any(observation[f"{kind}_gpa"] != prior[f"{kind}_gpa"] for kind in ("host", "cpu"))
            or observation["host_byte"] != prior["host_byte"] + 1
            or observation["cpu_byte"] != prior["cpu_byte"] + 1
            or observation["cpu_generation"] != prior["cpu_generation"] + 1):
        raise RuntimeError("actual writes preceding failed harvest lost pinned-page identity")
    start = len(source.replies)
    source.command("memory-fail-next-harvest")
    slots = [line for line in source.replies[start:] if line.startswith("MEMORY_FAIL_NEXT_HARVEST_SLOT ")]
    if len(slots) != 1:
        raise RuntimeError("missing actual selected KVM slot for next GET fault")
    fault_slot = int(slots[0].split(" ", 1)[1])
    if not 0 <= fault_slot < 1 << 32:
        raise ValueError("native KVM fault slot bound")
    pause_error = source.command("pause", error=True)
    releases = len(source.releases)
    fenced_resume = source.command("resume", error=True)
    if len(source.releases) != releases:
        raise RuntimeError("failed memory cut started native release/time preparation")
    before_path = root / "memory-recovery-before.json"
    source.command(f"memory-recovery-stats {before_path}")
    before = json.loads(bounded_file(before_path, 64 * 1024), object_pairs_hook=unique_fields)
    validate_recovery(before, fault_slot, recovered=False)
    source.command("memory-recover-cut")
    recovered_path = root / "memory-recovery-reestablished.json"
    source.command(f"memory-recovery-stats {recovered_path}")
    reestablished = json.loads(bounded_file(recovered_path, 64 * 1024), object_pairs_hook=unique_fields)
    validate_recovery(reestablished, fault_slot, recovered=True)
    full = root / "memory-recovered-forced-full"
    full_receipt = native_capture(source, full, "full", baseline, request="incremental")
    if full_receipt["fallback"] != "coverage-lost":
        raise RuntimeError("real reestablishment incorrectly made the lost baseline incrementally eligible")
    authentication = accept_image(source, full)
    observation = check_buffer_image(full, observation, ("host",))
    accepted_path = root / "memory-recovery-accepted.json"
    source.command(f"memory-recovery-stats {accepted_path}")
    accepted = json.loads(bounded_file(accepted_path, 64 * 1024), object_pairs_hook=unique_fields)
    validate_recovery(accepted, fault_slot, recovered=True, coverage_valid=True)
    if accepted["epoch"] != reestablished["epoch"]:
        raise RuntimeError("full acceptance invented another native CPU tracking epoch")
    source.command("resume")
    prior = observation
    host_after = host_write(source, prior, prior["host_byte"] + 1)
    observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
    observation = observe_buffer(source, cpu_write=True)
    observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
    if (any(observation[f"{kind}_gpa"] != prior[f"{kind}_gpa"] for kind in ("host", "cpu"))
            or observation["host_byte"] != prior["host_byte"] + 1
            or observation["cpu_byte"] != prior["cpu_byte"] + 1
            or observation["cpu_generation"] != prior["cpu_generation"] + 1):
        raise RuntimeError("post-recovery accepted-generation re-dirty lost actual page identity")
    source.command("pause")
    current, comparison = compare_and_accept(source, root, "memory-recovered-redirty",
        full_receipt["candidate_generation"], accept_incremental=True)
    observation = check_buffer_image(current, observation, ("host", "cpu"))
    result = {"fault_slot": fault_slot, "pause_error": pause_error, "fenced_resume": fenced_resume,
              "before": before, "reestablished": reestablished, "accepted": accepted,
              "full_receipt": full_receipt, "authentication": authentication,
              "host_writes": [host_before, host_after], "redirty": comparison}
    return current, comparison["accepted_generation"], observation, result


def run_incremental(args, echo) -> dict:
    """Stage one bounded sequence; only Main executes this real native entry point."""
    if shutil.disk_usage(args.evidence).free < 32 * MAX_RAM:
        raise RuntimeError("accepted-generation proof requires 32GiB free for retained RAM and disk roles")
    save(args.evidence / "memory-source-identity.json",
         source_identity(Path(__file__).resolve().parents[3]))
    report = {"scope": LEDGER_SCOPE, "status": "running", "comparisons": [], "host_writes": [],
              "prepared_children": [], "reaping": [], "all_reaped": False,
              "physical_sharing": "not-qualified", "restored_reclaim": "not-qualified",
              "caller_authentication": "file reads recorded separately from native live-RAM reads"}
    sessions = []
    try:
        disks = []
        for index in range(2):
            path = args.evidence / f"incremental-source-disk{index}.raw"
            with path.open("xb") as output:
                output.truncate(128 * 1024 * 1024)
            command = ["mkfs.ext4", "-F", "-q", str(path)]
            save(args.evidence / f"incremental-mkfs{index}-command.json", command)
            with path.with_suffix(".mkfs.log").open("xb") as log:
                subprocess.run(command, check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT)
            disks.append(path)
        source = MemorySession.create(args, args.evidence / "incremental-source", disks, echo)
        sessions.append(source)
        source.start_mux()
        work = source.progress()
        source.profile()
        observation = observe_buffer(source)
        initial_gpas = (observation["host_gpa"], observation["cpu_gpa"])
        source.command("pause")
        initial = args.evidence / "accepted-baseline"
        first = native_capture(source, initial, "full", None)
        for kind in ("host", "cpu"):
            data, page = fixture_page(initial, observation[f"{kind}_gpa"])
            if data != bytes([observation[f"{kind}_byte"]]) * 4096:
                raise RuntimeError("initial baseline differs from actual pinned page")
            observation[f"{kind}_dense_page"] = page
        first["authentication"] = accept_image(source, initial)
        report["initial_baseline"] = first
        baseline = first["candidate_generation"]
        initial_hash = digest(initial / "memory.ram")
        current, zero = zero_cut(source, args.evidence, "accepted-zero-dirty", baseline, initial)
        report["zero_dirty"] = zero
        baseline = zero["candidate_generation"]
        for generation in (1, 2):
            source.command("resume")
            prior = observation
            cpu_before = observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
            report["host_writes"].append(host_write(source, prior, prior["host_byte"] + 1))
            observation = observe_buffer(source, cpu_write=True)
            cpu_after = observe_host_page(source, prior["cpu_gpa"], prior["cpu_dense_page"])
            if ((observation["host_gpa"], observation["cpu_gpa"]) != initial_gpas
                    or observation["host_byte"] != prior["host_byte"] + 1
                    or observation["cpu_byte"] != prior["cpu_byte"] + 1
                    or observation["cpu_generation"] != prior["cpu_generation"] + 1):
                raise RuntimeError("accepted-generation same-page native writers changed identity/value")
            work = source.progress(work)
            source.command("pause")
            current, comparison = compare_and_accept(
                source, args.evidence, f"accepted-redirty-{generation}", baseline, accept_incremental=True)
            observation = check_buffer_image(current, observation, ("host", "cpu"))
            comparison.update(guest_buffer=observation, cpu_active_host_map={
                "before": cpu_before, "after": cpu_after}, guest_work=work)
            report["comparisons"].append(comparison)
            baseline = comparison["accepted_generation"]
        source.command("resume")
        prior = observation
        report["host_writes"].append(host_write(source, prior, 0))
        observation = observe_buffer(source, cpu_zero=True)
        if (observation["host_byte"] != 0 or observation["cpu_byte"] != 0
                or observation["cpu_generation"] != prior["cpu_generation"] + 1
                or (observation["host_gpa"], observation["cpu_gpa"]) != initial_gpas):
            raise RuntimeError("actual host/CPU nonzero-to-zero writes lack pinned-page evidence")
        source.command("pause")
        current, comparison = compare_and_accept(source, args.evidence, "accepted-zero-update", baseline)
        observation = check_buffer_image(current, observation, ("host", "cpu"))
        if comparison["incremental_receipt"]["stats"]["explicit_zero_bytes_written"] < 8192:
            raise RuntimeError("actual native overlay did not account both explicit zero pages")
        report["zero_update"] = comparison
        baseline = comparison["accepted_generation"]
        source.command("resume")
        report["host_writes"].append(host_write(source, observation, 1))
        observation = observe_buffer(source)
        observation["host_dense_page"] = prior["host_dense_page"]
        observation["cpu_dense_page"] = prior["cpu_dense_page"]
        source.command("pause")
        abandoned_dir = args.evidence / "explicitly-abandoned-incremental"
        abandoned = native_capture(source, abandoned_dir, "incremental", baseline)
        check_buffer_image(abandoned_dir, observation, ("host",))
        source.command("memory-abandon")
        report["abandoned_attempt"] = abandoned
        failure_dir = args.evidence / "failed-readonly-output"
        failure = source.command(f"memory-capture-fail {failure_dir} incremental", error=True)
        failed_receipt = failed_output_record(failure_dir, baseline, abandoned["stats"]["logical_bytes"])
        report["failed_output_receipt"] = failed_receipt
        busy = observe_busy(source, "resume")
        source.command("memory-abandon")
        source.command("resume")
        cpu_before = observe_host_page(source, observation["cpu_gpa"], observation["cpu_dense_page"])
        prior_failure = observation
        observation = observe_buffer(source, cpu_write=True)
        observe_host_page(source, observation["cpu_gpa"], prior["cpu_dense_page"])
        if ((observation["host_gpa"], observation["cpu_gpa"]) != initial_gpas
                or observation["host_byte"] != 1 or observation["cpu_byte"] != 1
                or observation["cpu_generation"] != prior_failure["cpu_generation"] + 1):
            raise RuntimeError("failed-attempt continuation lost actual disjoint writer evidence")
        source.command("pause")
        current, comparison = compare_and_accept(source, args.evidence, "failed-attempt-retained", baseline)
        observation = check_buffer_image(current, observation, ("host", "cpu"))
        comparison.update(output_failure=failure, failed_attempt_busy=busy,
                          cpu_active_host_before=cpu_before, guest_buffer=observation)
        report["failure_retention"] = comparison
        baseline = comparison["accepted_generation"]
        current, baseline, observation, recovery = recovery_proof(
            source, args.evidence, baseline, observation)
        report["actual_failed_harvest_recovery"] = recovery
        report["final_source_generation"] = baseline
        immutable = {name: digest(current / name) for name in
                     ("memory.ram", "memory-layout.json", "execution.state", "devices.state",
                      "disk0.raw", "disk1.raw")}
        backing = (current / "memory.ram").stat()
        for index in range(2):
            child_disks = []
            for disk in range(2):
                destination = args.evidence / f"prepared-child-{index}-disk{disk}.raw"
                shutil.copyfile(current / f"disk{disk}.raw", destination)
                child_disks.append(destination)
            child = MemorySession.create(args, args.evidence / f"prepared-child-{index}",
                                         child_disks, echo, restore=current)
            sessions.append(child)
            before = prepared_observation(child, child.directory / "prepared-before.json")
            if before["baseline_generation"] != 1:
                raise RuntimeError("fresh private child did not seed local baseline generation one")
            inherited = before.get("backing")
            if inherited != {"device": backing.st_dev, "inode": backing.st_ino}:
                raise RuntimeError("fresh child does not retain the authenticated readonly input inode")
            output, child_comparison = compare_and_accept(
                child, args.evidence, f"prepared-child-{index}", 1, prepared=True)
            wall_clocks = wall_clock_observations(current, output, before["wall_clock_gpas"])
            changed = [record["gpa"] for record in wall_clocks if record["changed"]]
            if not changed:
                raise RuntimeError("no actual native PV wall-clock structure byte change observed")
            after = prepared_observation(child, child.directory / "prepared-after.json")
            if after["baseline_generation"] != child_comparison["accepted_generation"]:
                raise RuntimeError("prepared child acceptance did not advance its local baseline")
            _, child_zero = zero_cut(child, args.evidence, f"prepared-child-{index}-zero",
                                     after["baseline_generation"], output, prepared=True)
            prepared_observation(child, child.directory / "prepared-final.json")
            report["prepared_children"].append({
                "native_pid": child.process.pid, "before": before, "after": after,
                "actual_changed_wall_clock_gpas": changed, "same_cut": child_comparison,
                "wall_clock_structures": wall_clocks,
                "zero_dirty": child_zero})
            if any(digest(current / name) != expected for name, expected in immutable.items()):
                raise RuntimeError("private child native installation changed immutable source inputs")
            if index:
                sibling = args.evidence / "prepared-child-0-full"
                sibling_check = args.evidence / "prepared-sibling-isolation-full"
                native_capture(sessions[1], sibling_check, "full",
                               report["prepared_children"][0]["zero_dirty"]["candidate_generation"],
                               prepared=True)
                sessions[1].command("memory-abandon")
                if digest(sibling_check / "memory.ram") != digest(sibling / "memory.ram"):
                    raise RuntimeError("second child installation changed the first child's live private RAM")
                report["sibling_isolation_full"] = str(sibling_check)
        source_check = args.evidence / "source-isolation-full"
        native_capture(source, source_check, "full", baseline)
        source.command("memory-abandon")
        if digest(source_check / "memory.ram") != immutable["memory.ram"]:
            raise RuntimeError("private child installation changed the paused source's live RAM")
        report["source_isolation_full"] = str(source_check)
        if digest(initial / "memory.ram") != initial_hash:
            raise RuntimeError("accepted source generations modified their original baseline inode")
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        for session in reversed(sessions):
            native_pid = session.process.pid
            try:
                if not session.native_reaped:
                    session.stop()
            except BaseException as error:
                report["reaping"].append({"native_pid": native_pid, "stop_error": str(error)})
            netd = session.netd
            try:
                failures = session.close()
            except BaseException as error:
                failures = [f"native/netd close failed: {error}"]
            report["reaping"].append({"native_pid": native_pid,
                "native_reaped": session.native_reaped, "netd_pid": netd.pid if netd else None,
                "netd_exit_status": netd.returncode if netd else None, "cleanup_failures": failures})
        report["all_reaped"] = bool(sessions) and all(
            record.get("native_reaped") is True and record.get("netd_exit_status") is not None
            and not record.get("cleanup_failures") for record in report["reaping"])
        if report["status"] == "passed" and not report["all_reaped"]:
            report.update(status="failed", error="native/netd cleanup ownership remains unresolved")
        save(args.evidence / "memory-incremental-report.json", report)
    if report["status"] != "passed":
        raise RuntimeError(report["error"])
    return report


class DirtyOracleTests(unittest.TestCase):
    def make_cut(self, root: Path, name: str, generation: int, ram: bytes, bitmap: bytes) -> Path:
        directory = root / name
        directory.mkdir()
        metadata = {"schema": 1, "scope": SCOPE, "bitmap_encoding": "u64-le-lsb0-dense",
                    "granule": 4096, "packed_len": len(ram), "page_count": len(ram) // 4096,
                    "dirty_pages": int.from_bytes(bitmap, "little").bit_count(),
                    "bitmap_bytes": len(bitmap), "pause_generation": generation,
                    "regions": [{"id": 0, "gpa": 4096, "byte_len": len(ram),
                                 "stream_offset": 0, "first_page": 0}]}
        (directory / "memory-dirty.json").write_text(json.dumps(metadata))
        (directory / "memory-dirty.bitmap").write_bytes(bitmap)
        (directory / "memory.ram").write_bytes(ram)
        return directory

    def test_changed_to_zero_requires_actual_dirty_bit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = self.make_cut(root, "before", 1, b"a" * 8192, bytes(8))
            missing = self.make_cut(root, "missing", 2, b"a" * 4096 + bytes(4096), bytes(8))
            with self.assertRaisesRegex(ValueError, "coverage failed"):
                compare_cuts(before, missing)
            covered = self.make_cut(root, "covered", 2, b"a" * 4096 + bytes(4096), b"\x02" + bytes(7))
            self.assertEqual(compare_cuts(before, covered)["changed_pages"], 1)

    def test_padding_and_truncated_ram_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            padding = self.make_cut(root, "padding", 1, bytes(4096), b"\x02" + bytes(7))
            with self.assertRaisesRegex(ValueError, "padding"):
                load_cut(padding)
            truncated = self.make_cut(root, "truncated", 1, bytes(4096), bytes(8))
            (truncated / "memory.ram").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "length"):
                load_cut(truncated)

    def test_lost_cumulative_union_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = self.make_cut(root, "before", 1, b"a" * 4096, b"\x01" + bytes(7))
            after = self.make_cut(root, "after", 2, bytes(4096), bytes(8))
            with self.assertRaisesRegex(ValueError, "lost across resume"):
                compare_cuts(before, after)

    def test_duplicate_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            json.loads('{"schema":1,"schema":1}', object_pairs_hook=unique_fields)

    def test_dense_indexes_skip_gpa_holes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = self.make_cut(root, "before", 1, b"a" * 8192, bytes(8))
            after = self.make_cut(root, "after", 2, b"a" * 4096 + b"b" * 4096, b"\x02" + bytes(7))
            for directory in (before, after):
                path = directory / "memory-dirty.json"
                metadata = json.loads(path.read_text())
                metadata["regions"] = [
                    {"id": 0, "gpa": 4096, "byte_len": 4096, "stream_offset": 0, "first_page": 0},
                    {"id": 1, "gpa": 65536, "byte_len": 4096, "stream_offset": 4096, "first_page": 1},
                ]
                path.write_text(json.dumps(metadata))
            comparison = compare_cuts(before, after)
            self.assertEqual(comparison["regions"][1]["changed_pages"], 1)
            self.assertEqual(fixture_page(after, 65536), (b"b" * 4096, 1))
            with self.assertRaisesRegex(ValueError, "not contained"):
                fixture_page(after, 8192)

    def test_host_write_requires_causal_active_bitmap_transition(self):
        observed = {"gpa": 4096, "dense_page": 0, "bytes": 4096, "before": 72, "after": 73,
                    "host_dirty_before": False, "host_dirty_after": True, "readback_verified": True,
                    "path": "RuntimeGuestMemory::write_slice"}
        validate_host_write(observed, 4096, 0, 72, 73)
        for key, value in (("host_dirty_before", True), ("host_dirty_after", False), ("dense_page", 1)):
            invalid = {**observed, key: value}
            with self.assertRaisesRegex(RuntimeError, "clean-to-dirty"):
                validate_host_write(invalid, 4096, 0, 72, 73)

    def make_image(self, root: Path, name: str, mode: str = "incremental",
                   dirty: int = 1, attempt: int = 1) -> Path:
        directory = self.make_cut(root, name, 7, b"a" * 8192, dirty.to_bytes(8, "little"))
        metadata_path = directory / "memory-dirty.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["scope"] = LEDGER_SCOPE
        metadata_path.write_text(json.dumps(metadata))
        layout = b'{"unit":"receipt-accounting-only"}'
        (directory / "memory-layout.json").write_bytes(layout)
        (directory / "execution.state").write_bytes(b"same-execution")
        (directory / "devices.state").write_bytes(b"same-devices")
        count = dirty.bit_count()
        stats = {key: 0 for key in (
            "logical_bytes", "live_bytes_read", "baseline_bytes_read", "baseline_bytes_written",
            "overlay_bytes_written", "full_bytes_written", "layout_bytes_written",
            "baseline_hole_bytes", "zero_bytes_omitted", "explicit_zero_bytes_written", "extent_queries")}
        stats.update(logical_bytes=8192, live_bytes_read=count * 4096 if mode == "incremental" else 8192,
                     overlay_bytes_written=count * 4096 if mode == "incremental" else 0,
                     full_bytes_written=8192 if mode == "full" else 0, layout_bytes_written=len(layout))
        record = {"schema": 1, "scope": LEDGER_SCOPE, "mode": mode,
                  "fallback": None if mode == "incremental" else "requested-full",
                  "baseline_generation": 3, "candidate_generation": 4, "attempt_sequence": attempt,
                  "pause_generation": 7, "dirty_pages": count, "stats": stats,
                  "affected_chunks": [0] if mode == "full" or count else []}
        (directory / "memory-image.json").write_text(json.dumps(record))
        return directory

    def test_equal_outputs_cannot_substitute_dirty_only_native_read_accounting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            incremental = self.make_image(root, "incremental")
            full = self.make_image(root, "full", "full", attempt=2)
            same_cut(incremental, full, 3)
            path = incremental / "memory-image.json"
            record = json.loads(path.read_text())
            record["stats"]["live_bytes_read"] = 8192
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "live-read"):
                same_cut(incremental, full, 3)

    def test_same_bytes_wrong_baseline_cut_or_attempt_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            incremental = self.make_image(root, "incremental")
            full = self.make_image(root, "full", "full", attempt=2)
            path = full / "memory-image.json"
            original = json.loads(path.read_text())
            for field, value in (("baseline_generation", 2), ("pause_generation", 8),
                                 ("attempt_sequence", 1), ("candidate_generation", 3),
                                 ("schema", True), ("dirty_pages", False)):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**original, field: value}))
                    with self.assertRaises(ValueError):
                        same_cut(incremental, full, 3)

    def test_zero_dirty_complete_output_requires_zero_native_live_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_image(Path(temp), "zero", dirty=0)
            record = image_record(directory, "incremental", 3)
            self.assertEqual(record["stats"]["live_bytes_read"], 0)
            path = directory / "memory-image.json"
            for stats, chunks in (({**record["stats"], "live_bytes_read": 4096}, []),
                                  (record["stats"], [0])):
                path.write_text(json.dumps({**record, "stats": stats, "affected_chunks": chunks}))
                with self.assertRaises(ValueError):
                    image_record(directory, "incremental", 3)

    def test_explicit_zero_accounting_and_overlay_cannot_exceed_actual_dirty_write(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_image(Path(temp), "zero-write")
            path = directory / "memory-image.json"
            original = json.loads(path.read_text())
            for key, value in (("overlay_bytes_written", 0), ("explicit_zero_bytes_written", 8192),
                               ("baseline_bytes_read", True), ("full_bytes_written", 4096)):
                with self.subTest(key=key):
                    path.write_text(json.dumps({**original, "stats": {**original["stats"], key: value}}))
                    with self.assertRaises(ValueError):
                        image_record(directory, "incremental", 3)

    def test_guest_nonce_and_pinned_gpa_identity_cannot_be_fabricated_by_width(self):
        observation = {"request_token": "a" * 32, "host_gpa": 4096, "cpu_gpa": 8192,
                       "bytes": 4096, "host_byte": 72, "cpu_byte": 67, "cpu_generation": 0,
                       "mlocked": True, "pipe_page_refs_retained": True, "pipe_bytes": 8192,
                       "pagemap_present": True}
        validate_buffer(observation, "a" * 32)
        for key, value in (("request_token", "b" * 32), ("host_gpa", 8192),
                           ("cpu_gpa", 0), ("host_gpa", True), ("host_byte", 256),
                           ("pipe_page_refs_retained", 1), ("cpu_generation", -1)):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeError, "ownership/nonce"):
                    validate_buffer({**observation, key: value}, "a" * 32)

    def test_authentication_rejects_wrong_object_digest_stale_preparation_and_changed_bytes(self):
        import hashlib
        from native_ram_image import authenticate_image
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ram, layout = root / "ram", root / "layout"
            record = {"architecture": "x86_64", "kind": "ram-layout", "magic": "KRUNRAML", "packedLength": 4096,
                      "pageGranule": 4096, "regions": [{"guestPhysicalAddress": 0,
                          "length": 4096, "streamOffset": 0}], "schema": 1,
                      "topology": {"firmwareAddress": 0, "initrdAddress": 4096,
                          "ramAboveGap": 0, "ramBelowGap": 4096,
                          "ramLastAddress": 4096, "shmStartAddress": 4294967296}}
            preparation = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            layout.write_bytes(preparation)
            ram.write_bytes(b"a" * 4096)
            expected = hashlib.sha256(preparation).digest()
            original = authenticate_image(ram, layout, expected, preparation)
            for incorrect in (bytes(32), hashlib.sha256(b"silo:ram-layout:v1\n" + preparation).digest()):
                with self.assertRaisesRegex(ValueError, "object digest"):
                    authenticate_image(ram, layout, incorrect, preparation)
            with self.assertRaisesRegex(ValueError, "preparation"):
                authenticate_image(ram, layout, expected, preparation + b"\n")
            ram.write_bytes(b"b" * 4096)
            changed = authenticate_image(ram, layout, expected, preparation)
            self.assertNotEqual(changed["stream_digest"], original["stream_digest"])
            record["topology"]["initrdAddress"] = 0
            layout.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
            with self.assertRaisesRegex(ValueError, "object digest"):
                authenticate_image(ram, layout, expected, preparation)

    def test_prepared_proof_requires_actual_zero_entries_wall_clock_and_backing_identity(self):
        record = {"schema": 1, "native_run_entries": [0, 0, 0], "wall_clock_gpas": [4096],
                  "baseline_generation": 1, "backing": {"device": 7, "inode": 42}}
        validate_prepared(record)
        for key, value in (("native_run_entries", [0, 1, 0]), ("native_run_entries", [False]),
                           ("native_run_entries", []), ("wall_clock_gpas", []),
                           ("wall_clock_gpas", [True]), ("baseline_generation", True),
                           ("backing", {"device": 7, "inode": 0}), ("schema", True)):
            with self.subTest(key=key, value=value):
                with self.assertRaises(RuntimeError):
                    validate_prepared({**record, key: value})

    def test_failed_output_requires_typed_role_effects_accounting_and_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            path = directory / "memory-failure.json"
            record = {"schema": 1, "kind": "ram-image-failure", "role": "output-ram",
                      "problem": "wrong-access", "effects": "none", "baseline_generation": 3,
                      "attempt_sequence": 2, "stats": dict.fromkeys(IO_COUNTERS, 0)}
            record["stats"]["logical_bytes"] = 8192
            path.write_text(json.dumps(record))
            self.assertEqual(failed_output_record(directory, 3, 8192), record)
            for key, value in (("kind", "unknown-command"), ("role", "input-ram"),
                               ("effects", "started"), ("baseline_generation", 2),
                               ("attempt_sequence", True), ("schema", True),
                               ("stats", {**record["stats"], "live_bytes_read": 4096})):
                with self.subTest(key=key):
                    path.write_text(json.dumps({**record, key: value}))
                    with self.assertRaises(ValueError):
                        failed_output_record(directory, 3, 8192)

    def test_busy_evidence_requires_exact_typed_command_not_error_prose(self):
        record = {"schema": 1, "command": "resume", "kind": "busy"}
        validate_busy(record, "resume")
        for invalid in ({**record, "schema": True}, {**record, "command": "release"},
                        {**record, "kind": "invalid-token"}, {**record, "error": "Busy"}):
            with self.assertRaises(ValueError):
                validate_busy(invalid, "resume")

    def test_unrelated_same_page_write_is_not_wall_clock_installation_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = self.make_cut(root, "before", 1, b"a" * 4096, bytes(8))
            unrelated = bytearray(b"a" * 4096)
            unrelated[128] = ord("b")
            after = self.make_cut(root, "after", 2, bytes(unrelated), b"\x01" + bytes(7))
            records = wall_clock_observations(before, after, [4100], SCOPE)
            self.assertFalse(records[0]["changed"])
            self.assertEqual(records[0]["bytes"], 12)
            unrelated[8] = ord("c")
            (after / "memory.ram").write_bytes(unrelated)
            self.assertTrue(wall_clock_observations(before, after, [4100], SCOPE)[0]["changed"])
            metadata = json.loads((after / "memory-dirty.json").read_text())
            metadata["dirty_pages"] = 0
            (after / "memory-dirty.json").write_text(json.dumps(metadata))
            (after / "memory-dirty.bitmap").write_bytes(bytes(8))
            with self.assertRaisesRegex(ValueError, "dirty coverage"):
                wall_clock_observations(before, after, [4100], SCOPE)

    def test_recovery_requires_actual_fault_complete_slots_epoch_and_full_acceptance(self):
        record = {"schema": 1, "registered_slots": [2, 7], "successful_slots": [2, 7],
                  "epoch": 9, "failure": None, "tracking_failure": {
                      "operation": "collect", "slot": 7, "native_code": errno.EFAULT,
                      "effect": "coverage-lost"}, "coverage_valid": False, "full_required": True}
        validate_recovery(record, 7, recovered=True)
        for key, value in (("successful_slots", [2]), ("registered_slots", [2, 2]),
                           ("successful_slots", [2, True]), ("epoch", None), ("epoch", True),
                           ("failure", {"native_code": errno.EFAULT}), ("coverage_valid", True),
                           ("full_required", False), ("schema", True),
                           ("tracking_failure", {**record["tracking_failure"], "slot": 2}),
                           ("tracking_failure", {**record["tracking_failure"], "native_code": 0})):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    validate_recovery({**record, key: value}, 7, recovered=True)
        accepted = {**record, "coverage_valid": True, "full_required": False}
        validate_recovery(accepted, 7, recovered=True, coverage_valid=True)
        with self.assertRaises(ValueError):
            validate_recovery(record, 7, recovered=True, coverage_valid=True)

    def test_same_cut_comparison_allows_full_reference_before_incremental(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            full = self.make_image(root, "full", "full", attempt=1)
            incremental = self.make_image(root, "incremental", attempt=2)
            comparison = same_cut(incremental, full, 3)
            self.assertGreater(comparison["incremental_receipt"]["attempt_sequence"],
                               comparison["full_receipt"]["attempt_sequence"])



if __name__ == "__main__":
    unittest.main()
