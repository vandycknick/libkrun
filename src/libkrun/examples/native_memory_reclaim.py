"""Explicit owned-disposable-page actual-report diagnostic.

--memory-reclaim requires the diagnostic balloon sysfs ABI, never an allocator
fallback. This does not qualify production allocator reacquisition or private
discard-to-zero. Failed samples and cleanup diagnostics remain retained.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import time

from native_device_controller import digest, save
from native_device_pressure import inhibited_reclaim
from native_memory_controller import (
    LEDGER_SCOPE, SCOPE, MemorySession, accept_image, bounded_file,
    compare_and_accept, fixture_page, load_cut, marked, native_capture,
    prepared_observation, saved_ram_range, source_identity, unique_fields,
)
from native_memory_sharing import (
    GIB, MIB, PAGE, apply_pressure, cgroup_snapshot, close_session, make_disks,
    no_oom, pressure_delta, pressure_prerequisite,
)
from native_ram_image import authenticate_image, validate_layout

A_BYTE = 0x6B
B_BYTE = 0xA5


def c_page() -> bytes:
    return bytes(1 + (offset * 29 + 67) % 255 for offset in range(PAGE))


def fnv64(data: bytes) -> str:
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f"{value:016x}"


def validate_guest(record: dict, token: str, operation: str, gpa: int | None,
                   previous: dict | None = None) -> None:
    if (not isinstance(record, dict) or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token)
            or record.get("request_token") != token or record.get("operation") != operation
            or operation not in ("prepare", "donate", "reuse", "verify")):
        raise ValueError("guest reclaim nonce/operation mismatch")
    if record.get("success") is not True:
        raise ValueError("owned-page kernel diagnostic failed: " + json.dumps(record, sort_keys=True))
    fields = {"schema", "ownership", "request_token", "operation", "success", "target_gpa",
              "gpa_before", "gpa_after", "sysfs_attribute", "kernel"}
    if (set(record) != fields or type(record["schema"]) is not int or record["schema"] != 1
            or record["ownership"] != "kernel-order0-retained"):
        raise ValueError("guest reclaim diagnostic ownership/schema differs")
    target = record["target_gpa"]
    if (type(target) is not int or not 0 < target < 1 << 53 or target % PAGE
            or (operation != "prepare" and target != gpa)
            or (operation == "prepare" and gpa is not None)
            or type(record["gpa_before"]) is not int
            or record["gpa_before"] != (0 if operation == "prepare" else target)
            or type(record["gpa_after"]) is not int or record["gpa_after"] != target):
        raise ValueError("guest reclaim retained GPA before/after differs")
    attribute = record["sysfs_attribute"]
    if (not isinstance(attribute, str) or not re.fullmatch(
            r"/sys/bus/virtio/devices/virtio[0-9]+/silo_reclaim", attribute)):
        raise ValueError("guest reclaim actual balloon attribute differs")
    status = record["kernel"]
    status_fields = {"abi", "state", "operation", "token", "gpa", "bytes", "submitted",
                     "used_seen", "verified_bytes", "mismatches", "checksum", "error"}
    if (not isinstance(status, dict) or set(status) != status_fields
            or any(type(status[key]) is not int for key in (
                "abi", "gpa", "bytes", "submitted", "used_seen", "verified_bytes", "mismatches", "error"))
            or status["abi"] != 1 or status["gpa"] != target or status["bytes"] != PAGE
            or status["operation"] != operation or status["token"] != token or status["error"] != 0
            or status["submitted"] != (0 if operation == "prepare" else 1)):
        raise ValueError("guest reclaim kernel ABI/nonce/submission evidence differs")
    if operation == "prepare":
        valid_state = status["state"] == "owned" and status["used_seen"] == 0
    elif operation == "donate":
        valid_state = ((status["state"], status["used_seen"]) in (("inflight", 0), ("acked", 1)))
    else:
        valid_state = status["state"] == "c-ready" and status["used_seen"] == 1
    verified = operation in ("reuse", "verify")
    if (not valid_state or status["verified_bytes"] != (PAGE if verified else 0)
            or status["mismatches"] != 0
            or status["checksum"] != (fnv64(c_page()) if verified else "0" * 16)):
        raise ValueError("guest reclaim ownership/completion/full C readback differs")
    if previous is not None:
        expected_previous = {"donate": ("prepare",), "reuse": ("donate",),
                             "verify": ("reuse", "verify")}.get(operation, ())
        if (previous["operation"] not in expected_previous or previous["request_token"] == token
                or any(record[key] != previous[key] for key in (
                    "target_gpa", "gpa_after", "ownership", "sysfs_attribute"))
                or (operation == "verify" and status != {
                    **previous["kernel"], "operation": operation, "token": token})):
            raise ValueError("fresh/continued guest lost retained ownership or C identity")


def guest_observation(session: MemorySession, command: str, gpa: int | None = None,
                      previous: dict | None = None) -> dict:
    operations = {"Q": "prepare", "T": "donate", "R": "reuse", "V": "verify"}
    operation = operations[command]
    token = os.urandom(16).hex()
    session.observations.pop("memory-reclaim", None)
    request = (f"{command}{token}\n" if gpa is None else f"{command}{token} {gpa}\n").encode("ascii")
    proof = {"command": command, "request_token": token, "target_gpa": gpa,
             "native_pid": session.process.pid, "started_monotonic_ns": time.monotonic_ns()}
    try:
        if os.write(session.console, request) != len(request):
            raise RuntimeError("short exact-PFN guest command")
        session.until(lambda: "memory-reclaim" in session.observations,
                      "bounded exact-PFN guest C evidence", timeout=12)
        raw = session.observations["memory-reclaim"]
        if len(raw) > 4096:
            raise ValueError("guest reclaim observation byte bound")
        proof["guest"] = json.loads(raw, object_pairs_hook=unique_fields)
        validate_guest(proof["guest"], token, operation, gpa, previous)
        return proof["guest"]
    except BaseException as error:
        proof["error"] = str(error)
        # FAIL can arrive in the same read as OBS-END. Preserve the failed guest
        # record even when Session correctly raises before until returns.
        if "memory-reclaim" in session.observations:
            proof["raw_guest"] = session.observations["memory-reclaim"].decode("ascii", errors="replace")
        raise
    finally:
        proof["finished_monotonic_ns"] = time.monotonic_ns()
        with (session.directory / "reclaim-guest-observations.jsonl").open("a") as output:
            output.write(json.dumps(proof, sort_keys=True) + "\n")


def validate_status(status: dict, restored: bool) -> None:
    inhibited_reclaim(status, "restored-private" if restored else "boot")
    if status["failed_operations"]:
        raise ValueError("inhibited reclaim recorded failed operations")


def status_snapshot(session: MemorySession, label: str, restored: bool) -> dict:
    path = session.directory / f"reclaim-{label}.native.json"
    session.command(f"pressure snapshot {path}")
    record = json.loads(bounded_file(path, 2 * MIB), object_pairs_hook=unique_fields)
    if record.get("pid") != session.process.pid:
        raise ValueError("reclaim status belongs to a different native owner")
    validate_status(record.get("balloon", {}).get("reclaim"), restored)
    balloons = [device for device in record["devices"] if device["id"] == "balloon0"]
    if (len(balloons) != 1 or len(balloons[0]["queues"]) != 5
            or not balloons[0]["acked_features"] & (1 << 5)
            or balloons[0]["acked_features"] & (1 << 4)):
        raise ValueError("unpoisoned real free-page reporting was not negotiated")
    return {"path": str(path), "sha256": digest(path), "reclaim": record["balloon"]["reclaim"],
            "transport": balloons[0]}


def packed_offset(layout: dict, gpa: int) -> int:
    if type(gpa) is not int or gpa < 0 or gpa % PAGE:
        raise ValueError("report GPA must be an aligned exact page")
    for region in layout["regions"]:
        local = gpa - region["guestPhysicalAddress"]
        if 0 <= local and local + PAGE <= region["length"]:
            return region["streamOffset"] + local
    raise ValueError("report PFN absent from authenticated registered RAM layout")


def check_page(directory: Path, layout: dict, gpa: int, expected: bytes,
               scope: str = LEDGER_SCOPE, dirty: bool = True) -> dict:
    data, page = fixture_page(directory, gpa, scope, require_dirty=dirty)
    offset = packed_offset(layout, gpa)
    metadata, _ = load_cut(directory, scope)
    geometry = [{"guestPhysicalAddress": region["gpa"], "length": region["byte_len"],
                 "streamOffset": region["stream_offset"]} for region in metadata["regions"]]
    if (geometry != layout["regions"] or metadata["packed_len"] != layout["packedLength"]
            or len(expected) != PAGE or data != expected):
        raise ValueError("exact full report page/layout differs in captured RAM")
    return {"gpa": gpa, "dense_page": page, "packed_offset": offset,
            "verified_bytes": PAGE, "sha256": hashlib.sha256(data).hexdigest(), "dirty_required": dirty}


def compare_coverage(reference: Path, candidate: Path) -> dict:
    metadata, bitmap = load_cut(candidate, LEDGER_SCOPE)
    reference_layout = validate_layout(bounded_file(reference / "memory-layout.json", 64 * 1024))
    candidate_layout = validate_layout(bounded_file(candidate / "memory-layout.json", 64 * 1024))
    if reference_layout != candidate_layout or (reference / "memory.ram").stat().st_size != metadata["packed_len"]:
        raise ValueError("dirty comparison changed layout or complete RAM length")
    changed = missing = scanned = 0
    with (reference / "memory.ram").open("rb") as before, (candidate / "memory.ram").open("rb") as after:
        for page in range(metadata["page_count"]):
            old, new = before.read(metadata["granule"]), after.read(metadata["granule"])
            if len(old) != metadata["granule"] or len(new) != metadata["granule"]:
                raise ValueError("partial full-image dirty comparison")
            different = old != new
            changed += different
            missing += different and not marked(bitmap, page)
            scanned += len(new)
        if before.read(1) or after.read(1) or scanned != metadata["packed_len"]:
            raise ValueError("incomplete full-image dirty comparison")
    if missing:
        raise ValueError(f"changed pages lack harvested dirty membership: {missing}")
    return {"reference": str(reference), "candidate": str(candidate), "scanned_bytes": scanned,
            "scanned_pages": metadata["page_count"], "changed_pages": changed, "missing_dirty_pages": missing}


def validate_backing(prepared: dict, authentication: dict, layout: dict, gpa: int) -> None:
    expected = dict(zip(("device", "inode"), authentication["ram_inode"]))
    if prepared["backing"] != expected:
        raise ValueError("restored owner did not map the exact authenticated baseline inode")
    if prepared["baseline_generation"] != 1:
        raise ValueError("fresh restored owner has stale/incorrect baseline generation")
    packed_offset(layout, gpa)


def unchanged_baseline(directory: Path, authentication: dict) -> dict:
    observed = authenticate_image(directory / "memory.ram", directory / "memory-layout.json",
                                  (directory / "binding/ram-layout").read_bytes())
    if observed != authentication:
        raise ValueError("private report processing mutated authenticated baseline bytes/layout/inode")
    return observed


def require_reaped(records: list[dict], pressure: dict | None = None) -> None:
    if not records or any(record.get("native_reaped") is not True
                          or record.get("netd_exit_status") is None
                          or record.get("cleanup_failures") for record in records):
        raise RuntimeError("not every native/netd owner acknowledged stop and reaped cleanly")
    if pressure is not None and (pressure.get("helper_reaped") is not True
                                 or pressure.get("helper_exit_status") != 0
                                 or pressure.get("cleanup_failures")):
        raise RuntimeError("shared pressure helper did not restore/reap cleanly")


def validate_report(report: dict, prepared_gpa: int | None = None) -> None:
    if prepared_gpa is not None and (
            type(prepared_gpa) is not int or not 0 < prepared_gpa < 1 << 53 or prepared_gpa % PAGE):
        raise ValueError("prepared diagnostic GPA is invalid")
    words = ("head", "next_avail", "next_used", "avail_idx", "used_idx")
    addresses = ("gpa", "desc_table", "avail_ring", "used_ring")
    if (not isinstance(report, dict) or set(report) != {*words, *addresses, "descriptors"}
            or any(type(report[key]) is not int or not 0 <= report[key] < 1 << 16 for key in words)
            or any(type(report[key]) is not int or not 0 < report[key] < 1 << 53 for key in addresses)
            or report["gpa"] % PAGE or report["next_used"] != report["used_idx"]
            or not 1 <= (report["avail_idx"] - report["next_avail"]) & 0xffff <= 256):
        raise ValueError("invalid genuine offered report identity/indices")
    descriptors = report["descriptors"]
    if (not isinstance(descriptors, list) or len(descriptors) != 1
            or (prepared_gpa is not None and report["gpa"] != prepared_gpa)
            or (report["avail_idx"] - report["next_avail"]) & 0xffff != 1):
        raise ValueError("diagnostic report must offer exactly the prepared one-page descriptor")
    descriptor = descriptors[0]
    if (not isinstance(descriptor, dict) or set(descriptor) != {"addr", "len", "flags", "next"}
            or any(type(descriptor[key]) is not int for key in descriptor)
            or descriptor["addr"] != report["gpa"] or descriptor["len"] != PAGE
            or descriptor["flags"] != 2 or not 0 <= descriptor["next"] < 1 << 16):
        raise ValueError("diagnostic report is not the exact writable retained page")


def validate_witness(record: dict, pid: int, state: str, restored: bool,
                     source: dict | None = None) -> None:
    fields = {"schema", "native_pid", "state", "report", "seed", "verified_bytes",
              "used_after", "barrier", "parked_cpus", "failure", "reclaim", "remapper_present"}
    if (not isinstance(record, dict) or set(record) != fields
            or type(record["schema"]) is not int or record["schema"] != 1
            or type(record["native_pid"]) is not int or record["native_pid"] != pid
            or record["state"] != state or record["failure"] is not None):
        raise ValueError("actual offered-report witness owner/state/failure differs")
    validate_status(record["reclaim"], restored)
    if record["remapper_present"] is not False:
        raise ValueError("inhibited report mapping admitted a periodic remapper")
    validate_report(record["report"])
    barrier = record["barrier"]
    if (not isinstance(barrier, dict) or set(barrier) != {"operation", "generation"}
            or any(type(value) is not int or not 0 < value < 1 << 64 for value in barrier.values())
            or type(record["parked_cpus"]) is not int or record["parked_cpus"] != 2
            or type(record["verified_bytes"]) is not int or record["verified_bytes"] != PAGE
            or type(record["seed"]) is not int or record["seed"] != (B_BYTE if restored else A_BYTE)):
        raise ValueError("missing reconciled all-CPU Park/full-page boundary evidence")
    if not restored:
        if record["used_after"] is not None:
            raise ValueError("source report was acknowledged before immutable A capture")
    else:
        if source is None or record["report"] != source["report"]:
            raise ValueError("child acknowledged a different head/PFN/descriptor layout")
        if (type(record["used_after"]) is not int or not 0 <= record["used_after"] < 1 << 16
                or not 1 <= (record["used_after"] - record["report"]["used_idx"]) & 0xffff <= 256
                or barrier["generation"] <= source["barrier"]["generation"]
                or record["reclaim"]["skipped_reports"] < 1):
            raise ValueError("fabricated/missing actual used publication or stale Park generation")


def witness(session: MemorySession, label: str, timeout: float = 30) -> tuple[dict, Path]:
    path = session.directory / f"reclaim-{label}.witness.json"
    session.command(f"reclaim-witness {path}", timeout=timeout)
    return json.loads(bounded_file(path, 128 * 1024), object_pairs_hook=unique_fields), path


def child_command(source: dict) -> str:
    report = source["report"]
    validate_report(report)
    values = [A_BYTE, B_BYTE] + [report[key] for key in (
        "head", "next_avail", "next_used", "avail_idx", "used_idx", "gpa",
        "desc_table", "avail_ring", "used_ring")]
    values.append(len(report["descriptors"]))
    for descriptor in report["descriptors"]:
        values.extend(descriptor[key] for key in ("addr", "len", "flags", "next"))
    return "reclaim-complete-child " + " ".join(str(value) for value in values)


def check_publication(directory: Path, boundary: dict, snapshot: dict) -> dict:
    report = boundary["report"]
    queue = snapshot["transport"]["queues"][4]
    if (queue["ready"] is not True or type(queue["size"]) is not int
            or not 1 <= queue["size"] <= 256 or report["head"] >= queue["size"]
            or any(queue[key] != report[key] for key in ("desc_table", "avail_ring", "used_ring"))
            or queue["next_used"] != boundary["used_after"] or queue["used_idx"] != boundary["used_after"]
            or not 1 <= (queue["next_avail"] - report["next_avail"]) & 0xffff <= queue["size"]):
        raise ValueError("captured actual reporting queue contradicts used publication")
    index_gpa = report["used_ring"] + 2
    entry_gpa = report["used_ring"] + 4 + (report["next_used"] % queue["size"]) * 8
    index = saved_ram_range(directory, index_gpa, 2, LEDGER_SCOPE, True)
    entry = saved_ram_range(directory, entry_gpa, 8, LEDGER_SCOPE, True)
    if int.from_bytes(index, "little") != boundary["used_after"] or int.from_bytes(entry[:4], "little") != report["head"]:
        raise ValueError("captured real used element does not acknowledge inherited report head")
    metadata, _ = load_cut(directory, LEDGER_SCOPE)
    if metadata["pause_generation"] != boundary["barrier"]["generation"]:
        raise ValueError("B recapture does not belong to the reconciled Park/provider boundary")
    return {"used_index_gpa": index_gpa, "used_entry_gpa": entry_gpa,
            "used_after": boundary["used_after"], "head": report["head"],
            "used_element_hex": entry.hex(), "used_index_and_element_dirty": True}


def check_source(directory: Path, boundary: dict, snapshot: dict) -> None:
    report = boundary["report"]
    queue = snapshot["transport"]["queues"][4]
    if (queue["ready"] is not True or any(queue[key] != report[key] for key in (
            "next_avail", "next_used", "avail_idx", "used_idx", "desc_table", "avail_ring", "used_ring"))):
        raise ValueError("source hold moved genuine offered/used queue indices")
    metadata, _ = load_cut(directory, SCOPE)
    if metadata["pause_generation"] != boundary["barrier"]["generation"]:
        raise ValueError("source A capture has stale/missing all-CPU Park identity")


def sibling_check(session: MemorySession, root: Path, label: str, baseline: int,
                  original: Path, layout: dict, gpa: int) -> dict:
    directory = root / label
    receipt = native_capture(session, directory, "full", baseline, prepared=True)
    session.command("memory-abandon")
    page = check_page(directory, layout, gpa, bytes([A_BYTE]) * PAGE, dirty=False)
    if (digest(directory / "memory.ram") != digest(original / "memory.ram")
            or digest(directory / "memory-layout.json") != digest(original / "memory-layout.json")):
        raise ValueError("primary private mutation/pressure changed prepared sibling RAM")
    return {"directory": str(directory), "receipt": receipt, "page": page,
            "complete_ram_sha256": digest(directory / "memory.ram")}


def run(args, echo) -> dict:
    report = {"schema": 1, "scope": "commit9-owned-disposable-page-actual-report-diagnostic",
              "verdict": "diagnostic acknowledge-only restored-private safety", "status": "running",
              "private_discard_zero_qualification": "not-run", "public_capability_granted": False,
              "production_allocator_reacquisition": "not-qualified",
              "ownership": "kernel-order0-retained",
              "B_origin": "host write through production facade at reconciled all-CPU Park",
              "C_origin": "guest CPU kernel fixture on retained donated PFN",
              "reaping": [], "all_reaped": False, "pending_lanes": ["hvf-arm64", "kvm-arm64"],
              "payload_retention": "failed samples retained; Main owns successful-sample cleanup"}
    group = prerequisite = None
    held = []

    def cancelled(signum, frame):
        raise InterruptedError("reclaim gate cancelled by signal " + str(signum))

    previous_signal = signal.signal(signal.SIGTERM, cancelled)
    try:
        if os.uname().sysname != "Linux" or os.sysconf("SC_PAGE_SIZE") != PAGE:
            raise ValueError("this exact native gate requires Linux with 4KiB pages; HVF remains pending")
        if args.kernel_config is None:
            raise ValueError("--memory-reclaim requires the explicit diagnostic kernel configuration")
        config = bounded_file(args.kernel_config, MIB).decode("ascii").splitlines()
        if config.count("CONFIG_VIRTIO_BALLOON_SILO_RECLAIM_DIAG=y") != 1:
            raise ValueError("--memory-reclaim requires CONFIG_VIRTIO_BALLOON_SILO_RECLAIM_DIAG=y")
        report["diagnostic_kernel"] = {"kernel_sha256": digest(args.kernel),
                                       "config_sha256": digest(args.kernel_config), "abi": 1}
        if shutil.disk_usage(args.evidence).free < 12 * GIB:
            raise RuntimeError("insufficient storage headroom for retained full-image reclaim evidence")
        group, prerequisite = pressure_prerequisite(args.sharing_unit)
        report["pressure_prerequisite"] = prerequisite
        source_files = source_identity(Path(__file__).resolve().parents[3])
        root = Path(__file__).resolve().parents[3]
        source_files["files"].update({name: digest(root / name) for name in (
            "src/libkrun/examples/native_memory_reclaim.py",
            "src/libkrun/examples/native_ram_image.py",
            "src/libkrun/examples/native_memory_sharing.py",
            "src/libkrun/src/api/vmm_builder/native_device_pressure.rs",
            "src/devices/src/virtio/balloon/device.rs")})
        save(args.evidence / "reclaim-source-identity.json", source_files)
        source = MemorySession.create(args, args.evidence / "reclaim-source", make_disks(args, "reclaim-source"), echo)
        source.start_mux()
        source.progress()
        source.profile()
        held.append(source)
        prepared_page = guest_observation(source, "Q")
        gpa = prepared_page["target_gpa"]
        report["prepared_page"] = prepared_page
        started = time.monotonic()
        source.command(f"reclaim-hold-source {A_BYTE}")
        donated_page = guest_observation(source, "T", gpa, prepared_page)
        report["donated_page"] = donated_page
        readiness = []
        report["source_readiness"] = readiness
        while True:
            remaining = 10 - (time.monotonic() - started)
            if remaining <= 0:
                raise RuntimeError("no genuine guest-offered reporting chain within 10 seconds")
            observed, path = witness(source, f"available-{len(readiness):03}", timeout=remaining)
            readiness.append({"path": str(path), "elapsed_seconds": time.monotonic() - started})
            if observed.get("state") != "holding" or observed.get("failure") is not None:
                raise ValueError("genuine report hold failed before source pause")
            if observed.get("report") is not None:
                validate_report(observed["report"], gpa)
                break
            source.pump(min(.05, remaining))
        source.command("pause")
        a, _ = witness(source, "source-A")
        validate_witness(a, source.process.pid, "source-seeded", False)
        validate_report(a["report"], gpa)
        report["source_boundary"] = a
        source_status = status_snapshot(source, "source-A", False)
        report["source_status"] = source_status
        baseline = args.evidence / "reclaim-baseline-A"
        first = native_capture(source, baseline, "full", None)
        layout = validate_layout(bounded_file(baseline / "memory-layout.json", 64 * 1024))
        report["A_page"] = check_page(baseline, layout, gpa, bytes([A_BYTE]) * PAGE, SCOPE)
        check_source(baseline, a, source_status)
        authentication = accept_image(source, baseline)
        report["baseline"] = {"directory": str(baseline), "receipt": first, "authentication": authentication}
        source.command("reclaim-release-hold")
        held.remove(source)
        report["source_cleanup"] = close_session(source)
        require_reaped([report["source_cleanup"]])
        primary = MemorySession.create(args, args.evidence / "reclaim-primary",
                                       make_disks(args, "reclaim-primary", baseline), echo, restore=baseline)
        sibling = MemorySession.create(args, args.evidence / "reclaim-sibling",
                                       make_disks(args, "reclaim-sibling", baseline), echo, restore=baseline)
        prepared = []
        for owner in (primary, sibling):
            observed = prepared_observation(owner, owner.directory / "reclaim-prepared.json")
            validate_backing(observed, authentication, layout, gpa)
            prepared.append(observed)
        if primary.process.pid == sibling.process.pid:
            raise ValueError("primary and sibling are not fresh distinct native processes")
        report["prepared_owners"] = prepared
        sibling_initial = args.evidence / "reclaim-sibling-initial"
        report["sibling_initial"] = native_capture(sibling, sibling_initial, "full", 1, prepared=True)
        sibling.command("memory-abandon")
        check_page(sibling_initial, layout, gpa, bytes([A_BYTE]) * PAGE, dirty=False)
        held.append(primary)
        primary.command(child_command(a))
        primary.command("release")
        primary.profile()
        primary.command("pause")
        b, _ = witness(primary, "child-B")
        validate_witness(b, primary.process.pid, "child-completed", True, a)
        report["B_boundary"] = b
        b_status = status_snapshot(primary, "child-B", True)
        report["B_status"] = b_status
        current, comparison = compare_and_accept(primary, args.evidence, "reclaim-B", 1, accept_incremental=True)
        report["B_comparison"] = comparison
        report["B_page"] = check_page(current, layout, gpa, bytes([B_BYTE]) * PAGE)
        report["B_publication"] = check_publication(current, b, b_status)
        report["B_dirty_coverage"] = compare_coverage(baseline, current)
        report["baseline_after_B"] = unchanged_baseline(baseline, authentication)
        report["sibling_after_B"] = sibling_check(sibling, args.evidence, "reclaim-sibling-after-B",
                                                  1, sibling_initial, layout, gpa)
        # No resume, activation, or guest ownership command may occur between
        # publication/B readback and this pressure-window recapture.
        report["pressure"] = prerequisite.copy()
        apply_pressure(args.sharing_unit, group, args.evidence, report["pressure"])
        pressure_current, pressure_compare = compare_and_accept(
            primary, args.evidence, "reclaim-pressure-B", comparison["accepted_generation"],
            accept_incremental=True)
        report["pressure_B_comparison"] = pressure_compare
        report["pressure_B_page"] = check_page(pressure_current, layout, gpa, bytes([B_BYTE]) * PAGE, dirty=False)
        if digest(pressure_current / "memory.ram") != digest(current / "memory.ram"):
            raise ValueError("host pressure changed paused B or any byte of primary RAM")
        report["pressure_B_dirty_coverage"] = compare_coverage(current, pressure_current)
        report["pressure_B_status"] = status_snapshot(primary, "pressure-B", True)
        report["baseline_after_pressure"] = unchanged_baseline(baseline, authentication)
        report["sibling_after_pressure"] = sibling_check(
            sibling, args.evidence, "reclaim-sibling-after-pressure", 1, sibling_initial, layout, gpa)
        report["B_before_guest_reuse"] = True
        primary.command("reclaim-release-hold")
        held.remove(primary)
        primary.command("resume")
        c = guest_observation(primary, "R", gpa, donated_page)
        report["guest_C"] = c
        primary.command("pause")
        c_current, c_compare = compare_and_accept(
            primary, args.evidence, "reclaim-C", pressure_compare["accepted_generation"], accept_incremental=True)
        report["C_comparison"] = c_compare
        report["C_page"] = check_page(c_current, layout, gpa, c_page())
        report["C_dirty_coverage"] = compare_coverage(pressure_current, c_current)
        report["C_status"] = status_snapshot(primary, "guest-C", True)
        fresh = MemorySession.create(args, args.evidence / "reclaim-fresh-C",
                                     make_disks(args, "reclaim-fresh-C", c_current), echo, restore=c_current)
        fresh_prepared = prepared_observation(fresh, fresh.directory / "reclaim-prepared.json")
        c_authentication = c_compare["authentication"]
        validate_backing(fresh_prepared, c_authentication, layout, gpa)
        report["fresh_C_prepared"] = fresh_prepared
        fresh_snapshot = args.evidence / "reclaim-fresh-C-prepared"
        report["fresh_C_image"] = native_capture(fresh, fresh_snapshot, "full", 1, prepared=True)
        fresh.command("memory-abandon")
        report["fresh_C_page"] = check_page(fresh_snapshot, layout, gpa, c_page(), dirty=False)
        report["fresh_C_complete_coverage"] = compare_coverage(c_current, fresh_snapshot)
        fresh.command("release")
        fresh.profile()
        report["fresh_C_guest"] = guest_observation(fresh, "V", gpa, c)
        report["fresh_C_continued_guest"] = guest_observation(fresh, "V", gpa, c)
        fresh.command("pause")
        report["fresh_C_status"] = status_snapshot(fresh, "continued-C", True)
        report["baseline_final"] = unchanged_baseline(baseline, authentication)
        report["sibling_final"] = sibling_check(sibling, args.evidence, "reclaim-sibling-final",
                                                1, sibling_initial, layout, gpa)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        for session in reversed(held):
            try:
                session.command("reclaim-release-hold")
            except BaseException as error:
                report["status"] = "failed"
                report.setdefault("hold_cleanup_errors", []).append({
                    "directory": str(session.directory), "error": str(error)})
        for session in reversed(args.sessions):
            try:
                report["reaping"].append(close_session(session))
            except BaseException as error:
                report["reaping"].append({"directory": str(session.directory), "native_reaped": False,
                                           "cleanup_failures": [str(error)]})
        try:
            require_reaped(report["reaping"], report.get("pressure"))
            report["all_reaped"] = True
        except BaseException as error:
            report.update(status="failed", cleanup_error=str(error))
        if group is not None and prerequisite is not None:
            try:
                report["final_cgroup"] = cgroup_snapshot(group)
                no_oom(pressure_delta(prerequisite["snapshot"], report["final_cgroup"]))
            except BaseException as error:
                report.update(status="failed", final_cgroup_error=str(error))
        try:
            save(args.evidence / "memory-reclaim-report.json", report)
        finally:
            signal.signal(signal.SIGTERM, previous_signal)
    if report["status"] != "passed":
        raise RuntimeError(report.get("cleanup_error", report.get("final_cgroup_error", "reclaim safety gate failed")))
    return report
