"""Standalone KVM sharing/lifetime gate, one fresh cohort per invocation.

Main runs N=1, then N=2, then N=4, retaining text and removing only successful
cohort payloads after all owners are reaped. No automatic bulk cleanup occurs.
Example (use absolute paths and a new evidence directory/unit for every N):

  systemd-run --user --quiet --wait --pipe --collect \
    --unit=silo-phase10-sharing-1 -p MemoryAccounting=yes \
    -p MemoryMax=6G -p MemoryHigh=5G -p RuntimeMaxSec=300 \
    python3 src/libkrun/examples/native_device_controller.py \
    --memory-sharing 1 --sharing-unit silo-phase10-sharing-1.service \
    --probe /absolute/native-device-probe --netd /absolute/silo-netd \
    --guest-init /absolute/native-device-linux --kernel /absolute/vmlinux \
    --register-fixture /absolute/native-device-registers \
    --evidence /absolute/new-evidence

For N=2/4 add --sharing-control /absolute/N1/memory-sharing-report.json.
The probe must include native-device-probe (native-device-witness-probe target).
The read-only memory-mappings diagnostic binds every registered region's exact
host address to its retained descriptor device/inode and packed offset. smaps
selection uses those host ranges, not a filename or device-number translation:
Btrfs smaps superblock devices differ from stat's subvolume devices. Both raw
identities remain in evidence, with exact readonly FD and native region checks.
Reporting readiness uses memory-reporting's actual queue used publication,
including the guest-memory used-ring index. One absolute 30-second deadline
covers polling, pause and the final stopped assertion; churn counts and elapsed
time are not acknowledgements. Every native readiness observation is retained.
Pressure is confined to this exact user unit: Max=6GiB, initial High=5GiB,
512MiB anonymous helper, temporary High=min(current+128MiB,5GiB), at most20s.
Require >=8GiB host MemAvailable, high/pgscan/pgsteal/PSI-some deltas >0,
no max/oom/oom_kill deltas. Restore the observed original High in finally.
Tolerance is fixed before measurements: 8MiB + N*4MiB, no fitted threshold.
This does not qualify private reclaim, HVF, or any public capability.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import signal
import sys
import time

from native_device_controller import Session, digest, save, seal_cut
from native_memory_controller import image_record, prepared_observation, source_identity, unique_fields
from native_device_pressure import inhibited_reclaim
from native_ram_image import authenticate_image, validate_layout

MIB = 1024 * 1024
GIB = 1024 * MIB
SET_BYTES = 64 * MIB
PAGE = 4096
QUARTER = SET_BYTES // 4
MEMORY_MAX = 6 * GIB
INITIAL_HIGH = 5 * GIB
HELPER_BYTES = 512 * MIB
HIGH_HEADROOM = 128 * MIB
PRESSURE_SECONDS = 20
HOST_AVAILABLE_MIN = 8 * GIB
SMAPS_BOUND = 16 * MIB
METRICS = ("Size", "Rss", "Pss", "Private_Dirty", "Private_Clean", "Shared_Clean",
           "Shared_Dirty", "Anonymous", "Swap", "AnonHugePages", "FilePmdMapped", "KSM")
REQUIRED_METRICS = frozenset(("Size", "Rss", "Pss", "Private_Dirty", "Private_Clean",
                              "Shared_Clean", "Shared_Dirty", "Anonymous", "Swap"))
MAP_HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: +(.*))?$")
HELPER_CODE = """import mmap, sys
size = 512 * 1024 * 1024
with mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS) as memory:
    for offset in range(0, size, 4096):
        memory[offset] = 0xa7
    print('RESIDENT 536870912', flush=True)
    sys.stdin.buffer.read(1)
"""


def bounded_text(path: Path, limit: int) -> str:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"text observation exceeds bound: {path}")
    return data.decode("utf-8", errors="strict")


def parse_smaps(text: str) -> list[dict]:
    if len(text.encode()) > SMAPS_BOUND:
        raise ValueError("smaps byte bound")
    mappings = []
    current = None
    for line in text.splitlines():
        header = MAP_HEADER.fullmatch(line)
        if header:
            start, end, permissions, offset, major, minor, inode, name = header.groups()
            current = {"start": int(start, 16), "end": int(end, 16), "permissions": permissions,
                       "offset": int(offset, 16), "device": os.makedev(int(major, 16), int(minor, 16)),
                       "inode": int(inode), "name": name or "", "metrics": {}}
            if current["end"] <= current["start"]:
                raise ValueError("empty or reversed VMA")
            mappings.append(current)
            continue
        if current is None:
            raise ValueError("smaps record without VMA")
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError("malformed smaps record")
        if key == "VmFlags":
            if "vm_flags" in current:
                raise ValueError("duplicate VMA flags")
            current["vm_flags"] = value.split()
        elif key in METRICS or key in ("KernelPageSize", "MMUPageSize"):
            fields = value.split()
            if len(fields) != 2 or fields[1] != "kB" or not fields[0].isdigit() or key in current["metrics"]:
                raise ValueError("malformed or duplicate smaps measurement")
            current["metrics"][key] = int(fields[0]) * 1024
    if not mappings:
        raise ValueError("empty smaps")
    return mappings


def validate_mapping_evidence(record: dict, device: int, inode: int, layout: dict) -> None:
    if (not isinstance(record, dict) or set(record) != {"schema", "native_pid", "packed_len", "regions"}
            or type(record["schema"]) is not int or record["schema"] != 1
            or type(record["native_pid"]) is not int or record["native_pid"] <= 0
            or type(record["packed_len"]) is not int or record["packed_len"] != layout["packedLength"]
            or not isinstance(record["regions"], list) or len(record["regions"]) != len(layout["regions"])):
        raise ValueError("native mapping evidence schema/count/length")
    for actual, expected in zip(record["regions"], layout["regions"]):
        if (not isinstance(actual, dict)
                or set(actual) != {"gpa", "length", "stream_offset", "host_start", "device", "inode"}
                or any(type(value) is not int or value < 0 for value in actual.values())
                or actual["gpa"] != expected["guestPhysicalAddress"] or actual["length"] != expected["length"]
                or actual["stream_offset"] != expected["streamOffset"]
                or (actual["device"], actual["inode"]) != (device, inode)
                or not 0 < actual["host_start"] < 1 << 64 or actual["host_start"] % PAGE
                or actual["host_start"] + actual["length"] >= 1 << 64):
            raise ValueError("native mapping evidence differs from authenticated RAM identity/layout")
    previous_end = 0
    for region in sorted(record["regions"], key=lambda item: item["host_start"]):
        if region["host_start"] < previous_end:
            raise ValueError("native RAM host ranges overlap")
        previous_end = region["host_start"] + region["length"]


def ram_measurement(text: str, device: int, inode: int, layout: dict, evidence: dict) -> dict:
    validate_mapping_evidence(evidence, device, inode, layout)
    # Btrfs stat reports a subvolume device, but smaps reports the superblock
    # device. Exact domain-owned HVAs avoid both pathname guesses and ambiguous
    # (superblock device, inode) collisions between different subvolumes.
    mappings = [mapping for mapping in parse_smaps(text) if any(
        mapping["start"] < region["host_start"] + region["length"]
        and region["host_start"] < mapping["end"] for region in evidence["regions"])]
    if not mappings:
        raise ValueError("no actual domain RAM VMAs")
    for mapping in mappings:
        size = mapping["end"] - mapping["start"]
        metrics = mapping["metrics"]
        if (mapping["permissions"] != "rw-p" or mapping["inode"] != inode or not mapping["device"]
                or not REQUIRED_METRICS <= metrics.keys() or metrics["Size"] != size
                or "vm_flags" not in mapping or "sh" in mapping["vm_flags"]
                or "mg" in mapping["vm_flags"] or metrics.get("KSM", 0) or metrics["Swap"]):
            raise ValueError("RAM VMA is not exact resident nonmergeable file-private backing")
    if (sum(mapping["end"] - mapping["start"] for mapping in mappings) != layout["packedLength"]
            or len({mapping["device"] for mapping in mappings}) != 1):
        raise ValueError("domain RAM VMAs include gaps, extra bytes or different superblock devices")
    regions = []
    for region, native in zip(layout["regions"], evidence["regions"]):
        low, high = native["host_start"], native["host_start"] + native["length"]
        parts = []
        for mapping in mappings:
            start, end = max(low, mapping["start"]), min(high, mapping["end"])
            if start < end:
                actual_offset = mapping["offset"] + start - mapping["start"]
                expected_offset = native["stream_offset"] + start - low
                if actual_offset != expected_offset:
                    raise ValueError("actual RAM VMA offset differs from domain packed region")
                parts.append({"stream_offset": actual_offset, "bytes": end - start, "host_address": start})
        if sum(part["bytes"] for part in parts) != region["length"]:
            raise ValueError("canonical RAM region not completely mapped")
        regions.append({**region, "vma_parts": parts})
    totals = {key: sum(mapping["metrics"].get(key, 0) for mapping in mappings) for key in METRICS}
    if totals["Pss"] < totals["Anonymous"]:
        raise ValueError("RAM PSS smaller than nonmergeable private anonymous resident bytes")
    return {"device": device, "inode": inode, "smaps_superblock_device": mappings[0]["device"],
            "identity_method": "native-domain-HVA-and-per-region-retained-file-identity",
            "native_mapping_evidence": evidence, "mappings": mappings, "regions": regions,
            "totals_bytes": totals, "file_pss_bytes": totals["Pss"] - totals["Anonymous"]}


def validate_observation(record: dict, token: str, slot: int | None,
                         baseline: dict | None = None, previous: dict | None = None) -> None:
    fixed = {"schema": 1, "bytes": SET_BYTES, "page_size": PAGE, "pages": SET_BYTES // PAGE,
             "verified_bytes": SET_BYTES, "mismatches": 0}
    fields = {*fixed, "request_token", "write_slot", "checksum", "baseline_checksum", "first_gpa", "mlocked"}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("guest sharing observation fields")
    if any(type(record[key]) is not int or record[key] != value for key, value in fixed.items()):
        raise ValueError("guest sharing full-set verification/counts")
    if (not re.fullmatch(r"[0-9a-f]{32}", token) or record["request_token"] != token
            or type(record["write_slot"]) not in (int, type(None)) or record["write_slot"] != slot
            or record["mlocked"] is not True or type(record["first_gpa"]) is not int
            or not 0 < record["first_gpa"] < 1 << 53 or record["first_gpa"] % PAGE):
        raise ValueError("guest sharing nonce/slot/pinned identity")
    for field in ("checksum", "baseline_checksum"):
        if not isinstance(record[field], str) or not re.fullmatch(r"[0-9a-f]{16}", record[field]):
            raise ValueError("guest sharing actual FNV checksum encoding")
    if (slot is None) != (record["checksum"] == record["baseline_checksum"]):
        raise ValueError("guest sharing mutation checksum")
    if baseline is not None and (record["baseline_checksum"] != baseline["checksum"]
                                 or record["first_gpa"] != baseline["first_gpa"]):
        raise ValueError("guest sharing captured baseline identity changed")
    if previous is not None and any(record[key] != previous[key] for key in
            ("checksum", "baseline_checksum", "first_gpa", "write_slot")):
        raise ValueError("guest sharing exact current contents changed")


def observe(session: Session, command: str, slot: int | None, baseline: dict | None = None,
            previous: dict | None = None) -> dict:
    token = os.urandom(16).hex()
    session.observations.pop("memory-sharing", None)
    request = (command + token + "\n").encode("ascii")
    started = time.monotonic_ns()
    if os.write(session.console, request) != len(request):
        raise RuntimeError("short guest sharing request")
    session.until(lambda: "memory-sharing" in session.observations,
                  "actual full 64MiB guest sharing verification", timeout=25)
    raw = session.observations["memory-sharing"]
    if len(raw) > 4096:
        raise ValueError("guest sharing observation bound")
    record = json.loads(raw, object_pairs_hook=unique_fields)
    validate_observation(record, token, slot, baseline, previous)
    with (session.directory / "sharing-observations.jsonl").open("a") as output:
        output.write(json.dumps({"command": command, "native_pid": session.process.pid,
                                 "started_monotonic_ns": started, "completed_monotonic_ns": time.monotonic_ns(),
                                 "guest": record}, sort_keys=True) + "\n")
    return record


def first_page(slot: int | None) -> bytes:
    variant = 0 if slot is None else slot + 1
    return bytes(8) + bytes(1 + ((offset * 29 + variant * 47) % 255) for offset in range(8, PAGE))


def check_saved_first_page(fd: int, layout: dict, gpa: int, slot: int | None) -> dict:
    for region in layout["regions"]:
        offset = gpa - region["guestPhysicalAddress"]
        if 0 <= offset and offset + PAGE <= region["length"]:
            stream_offset = region["streamOffset"] + offset
            data = os.pread(fd, PAGE, stream_offset)
            if data != first_page(slot):
                raise ValueError("captured common GPA differs from independently derived slot bytes")
            return {"gpa": gpa, "stream_offset": stream_offset, "bytes_verified": PAGE,
                    "sha256": hashlib.sha256(data).hexdigest(), "write_slot": slot}
    raise ValueError("real first GPA absent from saved registered RAM")


def readonly_owners(pid: int, device: int, inode: int) -> list[dict]:
    owners = []
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            info = entry.stat()
            if (info.st_dev, info.st_ino) != (device, inode):
                continue
            fields = dict(line.split(":", 1) for line in bounded_text(Path(f"/proc/{pid}/fdinfo/{entry.name}"), 4096).splitlines())
            flags = int(fields["flags"].strip(), 8)
            if flags & os.O_ACCMODE != os.O_RDONLY or flags & getattr(os, "O_PATH", 0):
                raise ValueError("native RAM descriptor is not readable readonly")
            owners.append({"fd": int(entry.name), "flags": flags, "target": str(entry.readlink())})
        except FileNotFoundError:
            continue
    if not owners:
        raise ValueError("native worker lacks retained readonly RAM descriptor")
    return owners


def snapshot(session: Session, label: str, timeout: float = 30) -> dict:
    path = session.directory / f"sharing-{label}.native.json"
    session.command(f"pressure snapshot {path}", timeout=timeout)
    record = json.loads(bounded_text(path, 2 * MIB), object_pairs_hook=unique_fields)
    if record["pid"] != session.process.pid:
        raise ValueError("actual tracked/restored native owner identity")
    inhibited_reclaim(record["balloon"]["reclaim"])
    balloons = [device for device in record["devices"] if device["id"] == "balloon0"]
    if len(balloons) != 1 or len(balloons[0]["queues"]) != 5:
        raise ValueError("actual reporting queue absent")
    return {"path": str(path), "sha256": digest(path), "balloon": record["balloon"],
            "transport": balloons[0], "report_used": balloons[0]["queues"][4]["next_used"]}


def reporting_advanced(record: dict, native_pid: int, baseline_used: int) -> bool:
    fields = {"schema", "native_pid", "reporting_negotiated", "reclaim",
              "ready", "next_used", "used_idx", "used_ring"}
    if (not isinstance(record, dict) or set(record) != fields
            or type(record["schema"]) is not int or record["schema"] != 1
            or type(record["native_pid"]) is not int or record["native_pid"] != native_pid
            or type(record["reporting_negotiated"]) is not bool or type(record["ready"]) is not bool
            or type(baseline_used) is not int or not 0 <= baseline_used <= 0xffff):
        raise ValueError("actual reporting readiness schema/identity/policy")
    inhibited_reclaim(record["reclaim"], "restored-private")
    if not record["ready"]:
        if any(record[field] is not None for field in ("next_used", "used_idx", "used_ring")):
            raise ValueError("unready reporting queue exposed completion state")
        return False
    if (any(type(record[field]) is not int or not 0 <= record[field] <= 0xffff
            for field in ("next_used", "used_idx"))
            or type(record["used_ring"]) is not int or not 0 < record["used_ring"] < 1 << 53
            or record["used_ring"] % 2):
        raise ValueError("actual reporting readiness queue geometry/indices")
    return (record["reporting_negotiated"] and record["next_used"] == record["used_idx"]
            and (record["used_idx"] - baseline_used) & 0xffff != 0)


def pause_after_reporting(session: Session, label: str, baseline_used: int) -> dict:
    deadline = time.monotonic() + 30
    proof = {"native_pid": session.process.pid, "baseline_used": baseline_used,
             "deadline_seconds": 30, "started_monotonic_ns": time.monotonic_ns(),
             "observations": [], "status": "waiting"}

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("actual reporting publication/pause exceeded its 30-second deadline")
        return value

    try:
        while True:
            sequence = len(proof["observations"])
            path = session.directory / f"sharing-{label}-reporting-{sequence:04}.json"
            session.command(f"memory-reporting {path}", timeout=remaining())
            record = json.loads(bounded_text(path, 4096), object_pairs_hook=unique_fields)
            proof["observations"].append({"path": str(path), "sha256": digest(path),
                                           "monotonic_ns": time.monotonic_ns(), "native": record})
            remaining()
            if reporting_advanced(record, session.process.pid, baseline_used):
                proof["published"] = record
                break
            session.pump(min(.02, remaining()))
        session.command("pause", timeout=remaining())
        proof["paused"] = snapshot(session, label + "-paused", timeout=remaining())
        remaining()
        paused_queue = proof["paused"]["transport"]["queues"][4]
        if (paused_queue["ready"] is not True or paused_queue["next_used"] != paused_queue["used_idx"]
                or (paused_queue["used_idx"] - baseline_used) & 0xffff == 0):
            raise ValueError("final paused reporting queue lacks actual used publication advancement")
        proof["status"] = "observed"
        return proof
    except BaseException as error:
        proof.update(status="failed", error=str(error))
        raise
    finally:
        proof["finished_monotonic_ns"] = time.monotonic_ns()
        save(session.directory / f"sharing-{label}-reporting-readiness.json", proof)


def measure(session: Session, label: str, info: os.stat_result, layout: dict) -> dict:
    native_path = session.directory / f"sharing-{label}.mappings.json"
    session.command(f"memory-mappings {native_path}")
    evidence = json.loads(bounded_text(native_path, 256 * 1024), object_pairs_hook=unique_fields)
    if evidence["native_pid"] != session.process.pid:
        raise ValueError("mapping evidence belongs to a different native worker")
    text = bounded_text(Path(f"/proc/{session.process.pid}/smaps"), SMAPS_BOUND)
    path = session.directory / f"sharing-{label}.smaps"
    path.write_text(text)
    record = ram_measurement(text, info.st_dev, info.st_ino, layout, evidence)
    record.update(native_pid=session.process.pid, raw_smaps=str(path),
                  raw_smaps_sha256=digest(path), monotonic_ns=time.monotonic_ns(),
                  readonly_descriptors=readonly_owners(session.process.pid, info.st_dev, info.st_ino))
    record.update(native_mapping_path=str(native_path), native_mapping_sha256=digest(native_path))
    return record


def measurement_totals(records: list[dict]) -> dict:
    return {"ram_vma_pss_bytes": sum(record["totals_bytes"]["Pss"] for record in records),
            "ram_vma_private_dirty_bytes": sum(record["totals_bytes"]["Private_Dirty"] for record in records),
            "ram_vma_anonymous_bytes": sum(record["totals_bytes"]["Anonymous"] for record in records),
            "ram_vma_file_pss_bytes": sum(record["file_pss_bytes"] for record in records)}


def evaluate_measurements(n: int, clean: dict, dirty: dict, control: dict | None) -> dict:
    tolerance = 8 * MIB + n * 4 * MIB
    baseline = clean if n == 1 else control
    if baseline is None:
        raise ValueError("N>1 requires measured N=1 resident control")
    if (clean["ram_vma_file_pss_bytes"] < SET_BYTES - tolerance
            or abs(clean["ram_vma_file_pss_bytes"] - baseline["ram_vma_file_pss_bytes"]) > tolerance):
        raise ValueError("clean RAM file-PSS does not scale as one resident baseline")
    expected_growth = 0 if n == 1 else n * QUARTER + (n - 2) * PAGE
    expected_private = n * QUARTER + (n - 1) * PAGE
    delta = {key: dirty[key] - clean[key] for key in clean}
    if abs(delta["ram_vma_pss_bytes"] - expected_growth) > tolerance:
        raise ValueError("RAM-VMA PSS private-write growth outside predeclared tolerance")
    # Private_Dirty can include exclusively mapped dirty file-cache pages in N=1;
    # Anonymous distinguishes newly COWed resident pages even in that control.
    if abs(delta["ram_vma_anonymous_bytes"] - expected_private) > tolerance:
        raise ValueError("actual private COW resident growth outside predeclared tolerance")
    if n > 1 and delta["ram_vma_private_dirty_bytes"] < expected_private - tolerance:
        raise ValueError("private-dirty growth does not cover actual guest writes")
    return {"status": "passed", "tolerance_bytes": tolerance, "expected_pss_growth_bytes": expected_growth,
            "expected_private_cow_bytes": expected_private, "delta_bytes": delta,
            "clean_scaling": "one resident file baseline plus measured per-child anonymous COW",
            "n1_control": "private replacement need not increase PSS or Private_Dirty"}


def key_values(text: str) -> dict[str, int]:
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in values or not fields[1].isdigit():
            raise ValueError("malformed cgroup counters")
        values[fields[0]] = int(fields[1])
    return values


def pressure_totals(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] in result:
            raise ValueError("malformed PSI observation")
        totals = [field[6:] for field in fields[1:] if field.startswith("total=")]
        if len(totals) != 1 or not totals[0].isdigit():
            raise ValueError("missing PSI total")
        result[fields[0]] = int(totals[0])
    if set(result) != {"some", "full"}:
        raise ValueError("incomplete PSI observation")
    return result


def cgroup_snapshot(directory: Path) -> dict:
    raw = {name: bounded_text(directory / name, 128 * 1024) for name in
           ("memory.events", "memory.stat", "memory.pressure", "memory.current", "memory.high", "memory.max")}
    return {"raw": raw, "events": key_values(raw["memory.events"]),
            "stat": key_values(raw["memory.stat"]), "psi_us": pressure_totals(raw["memory.pressure"]),
            "current_bytes": int(raw["memory.current"].strip()), "monotonic_ns": time.monotonic_ns()}


def pressure_delta(before: dict, after: dict) -> dict:
    result = {}
    for section, fields in (("events", ("high", "max", "oom", "oom_kill", "oom_group_kill")),
                            ("stat", ("pgscan", "pgsteal")), ("psi_us", ("some", "full"))):
        result[section] = {}
        for field in fields:
            if field == "oom_group_kill" and field not in before[section] and field not in after[section]:
                continue
            delta = after[section][field] - before[section][field]
            if delta < 0:
                raise ValueError("cgroup pressure counter regressed")
            result[section][field] = delta
    return result


def no_oom(delta: dict) -> None:
    if any(delta["events"].get(field, 0) for field in ("max", "oom", "oom_kill", "oom_group_kill")):
        raise RuntimeError("bounded proof encountered cgroup max/OOM event")


def real_pressure(delta: dict) -> bool:
    no_oom(delta)
    return (delta["events"]["high"] > 0 and delta["stat"]["pgscan"] > 0
            and delta["stat"]["pgsteal"] > 0 and delta["psi_us"]["some"] > 0)


def systemctl(*arguments: str) -> str:
    return subprocess.check_output(["systemctl", "--user", *arguments], text=True, timeout=15).strip()


def current_cgroup() -> str:
    lines = bounded_text(Path("/proc/self/cgroup"), 16 * 1024).splitlines()
    unified = [line[3:] for line in lines if line.startswith("0::")]
    if len(unified) != 1 or not unified[0].startswith("/") or ".." in Path(unified[0]).parts:
        raise ValueError("proof requires unified cgroup v2")
    return unified[0]


def available_memory() -> int:
    fields = dict(line.split(":", 1) for line in bounded_text(Path("/proc/meminfo"), 128 * 1024).splitlines())
    value, unit = fields["MemAvailable"].split()
    if unit != "kB":
        raise ValueError("unknown MemAvailable units")
    return int(value) * 1024


def validate_unit_binding(unit: str, actual_group: str, reported_group: str) -> None:
    if (not re.fullmatch(r"silo-phase10-sharing-[A-Za-z0-9_-]+\.service", unit)
            or not actual_group.startswith("/") or ".." in Path(actual_group).parts
            or actual_group != reported_group or not actual_group.endswith("/" + unit)):
        raise ValueError("refusing to change anything other than this dedicated proof unit")


def pressure_prerequisite(unit: str) -> tuple[Path, dict]:
    if not re.fullmatch(r"silo-phase10-sharing-[A-Za-z0-9_-]+\.service", unit):
        raise ValueError("an explicit new silo-phase10-sharing-*.service unit is required")
    group = current_cgroup()
    validate_unit_binding(unit, group, systemctl("show", unit, "--property=ControlGroup", "--value"))
    directory = Path("/sys/fs/cgroup") / group.lstrip("/")
    before = cgroup_snapshot(directory)
    original = systemctl("show", unit, "--property=MemoryHigh", "--value")
    if (before["raw"]["memory.max"].strip() != str(MEMORY_MAX)
            or before["raw"]["memory.high"].strip() != str(INITIAL_HIGH)
            or original != str(INITIAL_HIGH)):
        raise ValueError("own unit must launch with MemoryMax=6G and MemoryHigh=5G")
    if any(before["events"].get(key, 0) for key in ("max", "oom", "oom_kill", "oom_group_kill")):
        raise RuntimeError("new proof unit already has max/OOM events")
    available = available_memory()
    if available < HOST_AVAILABLE_MIN:
        raise RuntimeError("insufficient host MemAvailable safety margin")
    return directory, {"unit": unit, "cgroup": group, "original_memory_high_property": original,
                       "host_memavailable_bytes": available, "snapshot": before,
                       "helper_bytes": HELPER_BYTES, "high_headroom_bytes": HIGH_HEADROOM,
                       "deadline_seconds": PRESSURE_SECONDS, "host_memavailable_min_bytes": HOST_AVAILABLE_MIN}


def apply_pressure(unit: str, directory: Path, evidence: Path, proof: dict) -> None:
    helper = None
    changed = False
    try:
        if unit != proof["unit"] or current_cgroup() != proof["cgroup"] or available_memory() < HOST_AVAILABLE_MIN:
            raise RuntimeError("own cgroup/host pressure safety prerequisite changed")
        validate_unit_binding(unit, current_cgroup(), systemctl("show", unit, "--property=ControlGroup", "--value"))
        before = cgroup_snapshot(directory)
        proof["before"] = before
        high = min(before["current_bytes"] + HIGH_HEADROOM, INITIAL_HIGH)
        if before["current_bytes"] + HELPER_BYTES >= MEMORY_MAX - 512 * MIB:
            raise RuntimeError("insufficient own-unit max headroom for bounded helper")
        proof["temporary_memory_high_bytes"] = high
        changed = True
        systemctl("set-property", "--runtime", unit, f"MemoryHigh={high}")
        if (directory / "memory.high").read_text().strip() != str(high):
            raise RuntimeError("own unit MemoryHigh change did not take effect")
        started = time.monotonic()
        with (evidence / "sharing-pressure-helper.stderr").open("xb") as error:
            helper = subprocess.Popen([sys.executable, "-c", HELPER_CODE], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=error)
        proof.update(helper_pid=helper.pid, helper_command=[sys.executable, "-c", HELPER_CODE])
        if bounded_text(Path(f"/proc/{helper.pid}/cgroup"), 16 * 1024).strip() != "0::" + proof["cgroup"]:
            raise RuntimeError("pressure helper escaped the proof unit")
        output = bytearray()
        ready = False
        while time.monotonic() - started < PRESSURE_SECONDS:
            readable, _, _ = select.select([helper.stdout], [], [], .05)
            if readable:
                data = os.read(helper.stdout.fileno(), 4096)
                output.extend(data)
                if len(output) > 4096 or (data and not b"RESIDENT 536870912\n".startswith(output)):
                    raise RuntimeError("malformed bounded helper resident observation")
                ready = bytes(output) == b"RESIDENT 536870912\n"
            after = cgroup_snapshot(directory)
            proof["after_allocation"] = after
            delta = pressure_delta(before, after)
            no_oom(pressure_delta(proof["snapshot"], after))
            if ready and real_pressure(delta):
                proof.update(delta=delta, resident_helper_bytes=HELPER_BYTES, status="observed")
                break
            if helper.poll() is not None:
                raise RuntimeError("pressure helper exited before measured pressure")
        else:
            raise RuntimeError("no bounded real high/reclaim/PSI pressure within 20 seconds")
        proof["helper_stdout"] = output.decode("ascii")
    except BaseException as error:
        proof.update(status="failed", error=str(error))
        raise
    finally:
        failures = []
        if changed:
            try:
                systemctl("set-property", "--runtime", unit,
                          "MemoryHigh=" + proof["original_memory_high_property"])
                restored = (directory / "memory.high").read_text().strip()
                proof["restored_memory_high_bytes"] = restored
                if restored != proof["original_memory_high_property"]:
                    raise RuntimeError("original own-unit MemoryHigh not restored")
            except BaseException as error:
                failures.append(str(error))
        if helper is not None:
            try:
                helper.stdin.close()
                helper.wait(timeout=5)
            except BaseException as error:
                failures.append(str(error))
                try:
                    helper.kill()
                    helper.wait(timeout=5)
                except BaseException as failure:
                    failures.append("pressure helper forced reap: " + str(failure))
            finally:
                for endpoint in (helper.stdin, helper.stdout):
                    try:
                        endpoint.close()
                    except BaseException as error:
                        failures.append("pressure helper pipe cleanup: " + str(error))
                proof.update(helper_exit_status=helper.returncode, helper_reaped=helper.returncode is not None)
            if helper.returncode != 0:
                failures.append("bounded helper did not exit normally")
        try:
            proof["after_cleanup"] = cgroup_snapshot(directory)
            no_oom(pressure_delta(proof["snapshot"], proof["after_cleanup"]))
        except BaseException as error:
            failures.append(str(error))
        proof["cleanup_failures"] = failures
        save(evidence / "sharing-pressure.json", proof)
        if failures:
            raise RuntimeError("pressure cleanup failed: " + "; ".join(failures))


def kernel_facts() -> dict:
    paths = ("/sys/kernel/mm/transparent_hugepage/enabled", "/sys/kernel/mm/transparent_hugepage/defrag",
             "/sys/kernel/mm/transparent_hugepage/shmem_enabled", "/sys/kernel/mm/ksm/run",
             "/sys/kernel/mm/ksm/pages_shared", "/sys/kernel/mm/ksm/pages_sharing", "/proc/sys/vm/overcommit_memory")
    facts = {}
    for name in paths:
        try:
            facts[name] = bounded_text(Path(name), 16 * 1024).strip()
        except FileNotFoundError:
            facts[name] = None
    return {"uname": list(os.uname()), "page_size": os.sysconf("SC_PAGE_SIZE"), "settings": facts}


def close_session(session: Session) -> dict:
    closed = getattr(session, "sharing_cleanup_record", None)
    if closed is not None:
        return closed
    process = getattr(session, "process", None)
    netd = getattr(session, "netd", None)
    record = {"directory": str(session.directory), "native_pid": process.pid if process else None,
              "netd_pid": netd.pid if netd else None, "cleanup_failures": []}
    try:
        if process is not None and not session.native_reaped:
            session.stop()
    except BaseException as error:
        record["cleanup_failures"].append("native stop: " + str(error))
    try:
        record["cleanup_failures"].extend(session.close())
    except BaseException as error:
        record["cleanup_failures"].append("session close: " + str(error))
        # A failed resource close must not prevent reaping the other subprocess.
        for child in (process, netd):
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                except BaseException as failure:
                    record["cleanup_failures"].append("forced reap: " + str(failure))
    record.update(native_reaped=session.native_reaped,
                  native_exit_status=process.returncode if process else 0 if session.native_reaped else None,
                  netd_exit_status=netd.returncode if netd else None)
    session.sharing_cleanup_record = record
    return record


def make_disks(args, prefix: str, original: Path | None = None) -> list[Path]:
    disks = []
    for index in range(2):
        path = args.evidence / f"{prefix}-disk{index}.raw"
        if original is None:
            with path.open("xb") as output:
                output.truncate(128 * MIB)
            command = ["mkfs.ext4", "-F", "-q", str(path)]
            save(path.with_suffix(".command.json"), command)
            with path.with_suffix(".mkfs.log").open("xb") as log:
                subprocess.run(command, check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT)
        else:
            shutil.copyfile(original / f"disk{index}.raw", path)
        disks.append(path)
    return disks


def load_control(args, identities: dict) -> dict | None:
    if args.memory_sharing == 1:
        if args.sharing_control is not None:
            raise ValueError("N=1 establishes rather than consumes the resident control")
        return None
    if args.sharing_control is None:
        raise ValueError("N=2/4 require the successful N=1 report")
    report = json.loads(bounded_text(args.sharing_control, 4 * MIB), object_pairs_hook=unique_fields)
    facts = kernel_facts()
    old_facts = report["kernel_facts"]
    settings = [key for key in facts["settings"] if not key.endswith(("/pages_shared", "/pages_sharing"))]
    if (report["status"] != "passed" or report["all_reaped"] is not True or report["cohort_size"] != 1
            or report["input_identities"] != identities
            or any(old_facts[key] != facts[key] for key in ("uname", "page_size"))
            or any(old_facts["settings"][key] != facts["settings"][key] for key in settings)):
        raise ValueError("N=1 control is not a reaped matching-input/kernel cohort")
    return {"path": str(args.sharing_control.resolve()), "sha256": digest(args.sharing_control),
            "clean_totals": report["clean_totals"]}


def run(args, echo) -> dict:
    n = args.memory_sharing
    report = {"schema": 1, "scope": "commit8-native-kvm-sharing-lifetime", "status": "running",
              "cohort_size": n, "tolerance_bytes": 8 * MIB + n * 4 * MIB,
              "native_pids": [], "children": [], "clean_measurements": [], "dirty_measurements": [],
              "sibling_content_checks": [], "recaptures": [], "reaping": [], "all_reaped": False,
              "pending_lanes": ["hvf-arm64", "kvm-arm64"], "public_capability_granted": False,
              "restored_private_reclaim_qualification": "not-run", "destructive_reclaim_enabled": False,
              "reporting_scope": "real ordinary guest free-page reporting completion; pinned sharing pages are not reported",
              "retention": "Main-controlled sequential cohorts; failed payloads retained; successful payloads not deleted here"}
    ram_fd = layout_fd = None
    unlinked = False
    group = prerequisite = None

    def cancelled(signum, frame):
        raise InterruptedError("sharing proof cancelled by signal " + str(signum))

    original_termination_handler = signal.signal(signal.SIGTERM, cancelled)
    try:
        save(args.evidence / "sharing-policy.json", {
            "cohort_size": n, "tolerance_bytes": report["tolerance_bytes"],
            "measurements": "native-domain HVA-bound rw-p VMAs with per-region retained file identity and exact offsets, never process RSS",
            "clean_scaling": "sum(PSS-Anonymous) versus measured N=1 file-resident baseline",
            "expected_pss_growth_bytes": 0 if n == 1 else n * QUARTER + (n - 2) * PAGE,
            "expected_private_cow_bytes": n * QUARTER + (n - 1) * PAGE,
            "memory_max_bytes": MEMORY_MAX, "initial_memory_high_bytes": INITIAL_HIGH,
            "helper_bytes": HELPER_BYTES, "temporary_high_headroom_bytes": HIGH_HEADROOM,
            "pressure_deadline_seconds": PRESSURE_SECONDS, "host_memavailable_min_bytes": HOST_AVAILABLE_MIN,
            "required_positive_deltas": ["memory.events.high", "memory.stat.pgscan", "memory.stat.pgsteal",
                                         "memory.pressure.some.total"],
            "forbidden_event_deltas": ["max", "oom", "oom_kill", "oom_group_kill"],
            "reclaim_qualification": "not-run", "pending_lanes": report["pending_lanes"]})
        identities = json.loads(bounded_text(args.evidence / "inputs.json", 128 * 1024))["identities"]
        facts = kernel_facts()
        report.update(input_identities=identities, kernel_facts=facts)
        if facts["page_size"] != PAGE or os.uname().sysname != "Linux":
            raise ValueError("this measured gate requires Linux with 4KiB host pages; HVF remains pending")
        group, prerequisite = pressure_prerequisite(args.sharing_unit)
        report["pressure_prerequisite"] = prerequisite
        control = load_control(args, identities)
        report["control"] = control
        if shutil.disk_usage(args.evidence).free < (n + 3) * (GIB + 256 * MIB) + 2 * GIB:
            raise RuntimeError("insufficient filesystem headroom for bounded sequential cohort")
        root = Path(__file__).resolve().parents[3]
        source = source_identity(root)
        extra_sources = ("src/libkrun/examples/native_memory_sharing.py", "src/libkrun/examples/native_ram_image.py",
                         "src/libkrun/src/api/vmm_builder/native_device_pressure.rs",
                         "src/devices/src/virtio/balloon/device.rs", "src/libkrun/src/vmm/builder/restore.rs")
        source["files"].update({name: digest(root / name) for name in extra_sources})
        save(args.evidence / "sharing-source-identity.json", source)
        parent = Session.create(args, args.evidence / "sharing-source", make_disks(args, "sharing-source"), echo)
        report["native_pids"].append(parent.process.pid)
        parent.start_mux()
        parent.progress()
        parent.profile()
        initial = observe(parent, "A", None)
        report["source_guest"] = initial
        report["source_reporting_readiness"] = pause_after_reporting(parent, "source", 0)
        report["source_reporting"] = report["source_reporting_readiness"]["paused"]
        if report["source_reporting"]["report_used"] == 0:
            raise ValueError("no actual source balloon reporting used completion")
        cut = args.evidence / "sharing-baseline"
        parent.command(f"capture {cut}")
        report["baseline_manifest"] = seal_cut(cut)
        report["baseline_image"] = image_record(cut, "full", None)
        ram_fd = os.open(cut / "memory.ram", os.O_RDONLY)
        layout_fd = os.open(cut / "memory-layout.json", os.O_RDONLY)
        info = os.fstat(ram_fd)
        layout = validate_layout((cut / "memory-layout.json").read_bytes())
        report["baseline_inode"] = {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size}
        report["baseline_first_page"] = check_saved_first_page(ram_fd, layout, initial["first_gpa"], None)
        children = []
        for index in range(n):
            child = Session.create(args, args.evidence / f"sharing-child-{index}",
                                   make_disks(args, f"sharing-child-{index}", cut), echo, restore=cut)
            children.append(child)
            report["native_pids"].append(child.process.pid)
            prepared = prepared_observation(child, child.directory / "sharing-prepared.json")
            if prepared["backing"] != {"device": info.st_dev, "inode": info.st_ino}:
                raise ValueError("child native backing differs from single authenticated cohort inode")
            child.command("release")
            os.write(child.console, b"M\n")
            child.start_mux()
            child.command("activate")
            child.progress()
            child.profile()
            clean = observe(child, "A", None, initial)
            child.command("pause")
            record = {"native_pid": child.process.pid, "slot": index, "prepared": prepared,
                      "clean_guest": clean, "current_guest": clean, "clean_reporting": snapshot(child, "clean-paused")}
            report["children"].append(record)
        if len(set(report["native_pids"])) != n + 1:
            raise ValueError("cohort did not use fresh distinct native worker processes")
        for child in children:
            report["clean_measurements"].append(measure(child, "clean", info, layout))
        report["clean_totals"] = measurement_totals(report["clean_measurements"])
        for index, child in enumerate(children):
            child.command("resume")
            dirty = observe(child, "IJKL"[index], index, initial)
            child.command("pause")
            report["children"][index]["current_guest"] = dirty
            for sibling_index, sibling in enumerate(children):
                sibling.command("resume")
                expected = report["children"][sibling_index]["current_guest"]
                checked = observe(sibling, "E", expected["write_slot"], initial, expected)
                sibling.command("pause")
                report["sibling_content_checks"].append({"after_writer_slot": index,
                    "sibling_slot": sibling_index, "native_pid": sibling.process.pid, "guest": checked})
        if len({record["current_guest"]["checksum"] for record in report["children"]}) != n:
            raise ValueError("slot-distinct siblings have identical full-set checksums")
        for child in children:
            report["dirty_measurements"].append(measure(child, "dirty", info, layout))
        report["dirty_totals"] = measurement_totals(report["dirty_measurements"])
        report["measurement_assessment"] = evaluate_measurements(n, report["clean_totals"], report["dirty_totals"],
                                                                 control["clean_totals"] if control else None)
        parent.stop()
        report["source_stop"] = json.loads((parent.directory / "native-stop.json").read_text())
        report["source_cleanup"] = close_session(parent)
        if report["source_cleanup"]["cleanup_failures"]:
            raise RuntimeError("source resources did not close before original unlink")
        cut.joinpath("memory.ram").unlink()
        unlinked = True
        if os.fstat(ram_fd).st_nlink != 0:
            raise ValueError("disposable original inode still has another pathname")
        report["unlink"] = {"original_path": str(cut / "memory.ram"), "st_nlink": os.fstat(ram_fd).st_nlink,
                            "after_all_children_mapped": True, "controller_readonly_fd": ram_fd,
                            "source_reaped_before_unlink": parent.native_reaped}
        report["after_unlink_measurements"] = [measure(child, "unlinked", info, layout) for child in children]
        report["pressure"] = prerequisite.copy()
        apply_pressure(args.sharing_unit, group, args.evidence, report["pressure"])
        report["baseline_after_pressure_authentication"] = authenticate_image(
            cut / "memory.ram", cut / "memory-layout.json", (cut / "binding/ram-layout").read_bytes(),
            ram_fd=ram_fd, layout_fd=layout_fd)
        original_auth = json.loads((cut / "memory-authentication.json").read_text())
        if report["baseline_after_pressure_authentication"] != original_auth:
            raise ValueError("unlinked baseline bytes/identity changed after private writes and pressure")
        for index, child in enumerate(children):
            child.command("resume")
            expected = report["children"][index]["current_guest"]
            continued = observe(child, "E", index, initial, expected)
            before = child.samples[-1].copy()
            work = child.progress(before)
            clean_reporting = report["children"][index]["clean_reporting"]
            report["children"][index]["post_pressure_reporting_readiness"] = pause_after_reporting(
                child, "post-pressure", clean_reporting["report_used"])
            reporting = report["children"][index]["post_pressure_reporting_readiness"]["paused"]
            if (reporting["report_used"] - clean_reporting["report_used"]) & 0xffff == 0:
                raise ValueError("no actual restored balloon reporting used completion")
            if any(reporting["transport"][field] != clean_reporting["transport"][field]
                   for field in ("avail_features", "acked_features")):
                raise ValueError("restored reporting changed negotiated source features")
            recapture = args.evidence / f"sharing-recapture-{index}"
            child.command(f"capture {recapture}")
            manifest = seal_cut(recapture)
            receipt = image_record(recapture, "full", 1)
            with (recapture / "memory.ram").open("rb") as saved:
                common = check_saved_first_page(saved.fileno(), layout, initial["first_gpa"], index)
            child.command("resume")
            final_guest = observe(child, "E", index, initial, expected)
            child.command("pause")
            report["recaptures"].append({"native_pid": child.process.pid, "directory": str(recapture),
                "guest_after_pressure": continued, "ordinary_provider_progress": work,
                "reporting": reporting, "manifest": manifest, "image": receipt,
                "common_page": common, "guest_after_recapture_continue": final_guest,
                "original_backing_after_new_baseline": measure(child, "recaptured", info, layout)})
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        for session in reversed(args.sessions):
            try:
                report["reaping"].append(close_session(session))
            except BaseException as error:
                report["reaping"].append({"directory": str(session.directory), "native_reaped": False,
                                           "cleanup_failures": [str(error)]})
        report["all_reaped"] = bool(args.sessions) and all(
            record.get("native_reaped") is True and record.get("netd_exit_status") is not None
            and not record.get("cleanup_failures") for record in report["reaping"])
        if report.get("pressure", {}).get("helper_pid") is not None:
            report["all_reaped"] = report["all_reaped"] and report["pressure"].get("helper_reaped") is True
        if group is not None and prerequisite is not None:
            try:
                report["final_cgroup"] = cgroup_snapshot(group)
                no_oom(pressure_delta(prerequisite["snapshot"], report["final_cgroup"]))
            except BaseException as error:
                report.update(status="failed", final_cgroup_error=str(error))
        if report["status"] == "passed" and not report["all_reaped"]:
            report.update(status="failed", error="not every native/netd owner reaped cleanly")
        if report["status"] != "passed" and unlinked and ram_fd is not None:
            # Lifetime deliberately removed the pathname. Retain failing bytes as
            # a distinct diagnostic artifact, never as a restore/copy fallback.
            try:
                recovery = args.evidence / "failed-unlinked-baseline.ram"
                size = os.fstat(ram_fd).st_size
                with recovery.open("xb") as output:
                    offset = 0
                    while offset < size:
                        chunk = os.pread(ram_fd, min(MIB, size - offset), offset)
                        if not chunk:
                            raise ValueError("truncated failure-retention copy")
                        output.write(chunk)
                        offset += len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                report["retained_failed_original"] = {"path": str(recovery), "sha256": digest(recovery),
                    "different_inode": True, "role": "diagnostic bytes, not original mapping inode"}
            except BaseException as error:
                report["failure_retention_error"] = str(error)
        for fd in (ram_fd, layout_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    report.update(status="failed", descriptor_close_error=str(error))
        report["payload_cleanup"] = {"mode": "Main-controlled-cohort", "deleted_payloads": [],
                                     "original_ram_path_unlinked_for_lifetime": unlinked,
                                     "successful_payloads_disposable": report["status"] == "passed" and report["all_reaped"],
                                     "replayable_original_ram": not unlinked}
        try:
            save(args.evidence / "memory-sharing-report.json", report)
        finally:
            signal.signal(signal.SIGTERM, original_termination_handler)
    if report["status"] != "passed":
        raise RuntimeError(report.get("error", "sharing gate cleanup/cgroup failed"))
    return report
