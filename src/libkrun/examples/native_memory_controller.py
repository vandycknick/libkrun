"""Bounded real-source commit-7 proof, invoked by native_device_controller --memory-dirty.

Full RAM scans here are an independent oracle, not an incremental capture API.
The native bitmap is the harvested cumulative union: no baseline is accepted or
cleared, and this does not prove re-dirty after clearing or image equivalence.
"""
from __future__ import annotations

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


class MemorySession(Session):
    def command(self, command: str, error: bool = False, timeout: float = 30):
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


def load_cut(directory: Path) -> tuple[dict, bytes]:
    metadata = json.loads(bounded_file(directory / "memory-dirty.json", 128 * 1024),
                          object_pairs_hook=unique_fields)
    required = {"schema", "scope", "bitmap_encoding", "granule", "packed_len", "page_count",
                "dirty_pages", "bitmap_bytes", "pause_generation", "regions"}
    if (not isinstance(metadata, dict) or set(metadata) != required or metadata["schema"] != 1
            or metadata["scope"] != SCOPE or metadata["bitmap_encoding"] != "u64-le-lsb0-dense"):
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


def fixture_page(directory: Path, gpa: int) -> tuple[bytes, int]:
    metadata, bitmap = load_cut(directory)
    if type(gpa) is not int or gpa % 4096:
        raise ValueError("fixture GPA is not an aligned integer")
    for region in metadata["regions"]:
        offset = gpa - region["gpa"]
        if 0 <= offset and offset + 4096 <= region["byte_len"]:
            with (directory / "memory.ram").open("rb") as source:
                source.seek(region["stream_offset"] + offset)
                data = source.read(4096)
            page = region["first_page"] + offset // metadata["granule"]
            if not marked(bitmap, page):
                raise ValueError("actual fixture page absent from harvested native union")
            return data, page
    raise ValueError("fixture GPA not contained in actual registered RAM")


def observe_buffer(source: Session, cpu_write: bool = False) -> dict:
    token = os.urandom(16).hex()
    source.observations.pop("memory-buffer", None)
    command = ("D" if cpu_write else "H") + token + "\n"
    started = time.monotonic_ns()
    if os.write(source.console, command.encode("ascii")) != len(command):
        raise RuntimeError("guest memory request write was short")
    source.until(lambda: "memory-buffer" in source.observations, "actual pinned guest memory observation")
    observation = json.loads(source.observations["memory-buffer"], object_pairs_hook=unique_fields)
    if (observation.get("request_token") != token or observation.get("mlocked") is not True
            or observation.get("pipe_page_refs_retained") is not True or observation.get("pipe_bytes") != 8192
            or observation.get("pagemap_present") is not True or observation.get("bytes") != 4096
            or observation.get("host_gpa") == observation.get("cpu_gpa")):
        raise RuntimeError("guest memory buffer ownership/nonce observation differs")
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



if __name__ == "__main__":
    unittest.main()
