#!/usr/bin/env python3
"""Explicit native execution gate. Never imported by a Cargo/pytest test target.

All input binaries are built by Main before invocation. The controller does not
build, modify host timer configuration, grant capabilities, or substitute devices.
Failure retains every artifact; the outer process timeout is not a native reap ACK.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

CASES = ("future", "due", "due-no-irr", "masked", "pending-future", "in-service", "io", "mmio")


def digest(path: Path) -> bytes:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.digest()

def capture_manifest(directory: Path) -> dict:
    limits = {"execution.state": 16 * 1024 * 1024, "memory.fixture": 3145728,
              "capture.json": 65536, "native-inventory.txt": 16 * 1024 * 1024}
    result = {}
    for name, limit in limits.items():
        path = directory / name
        size = path.stat().st_size
        if not path.is_file() or size > limit or (name == "memory.fixture" and size != limit):
            raise RuntimeError(f"invalid bounded capture object {path}")
        result[name] = {"bytes": size, "sha256": digest(path).hex()}
    return result


def save(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def invoke(command: list[str], evidence: Path, name: str) -> dict:
    started = time.monotonic_ns()
    with (evidence / f"{name}.stdout").open("xb") as stdout, (evidence / f"{name}.stderr").open("xb") as stderr:
        os.chmod(stdout.name, 0o600)
        os.chmod(stderr.name, 0o600)
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            status = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            save(evidence / f"{name}.invocation.json", {"command": command, "pid": process.pid, "timeout": True,
                "native_cleanup_acknowledged": False, "duration_ns": time.monotonic_ns() - started})
            raise RuntimeError(f"{name}: process timeout, NOT a successful native cleanup") from None
    save(evidence / f"{name}.invocation.json", {"command": command, "pid": process.pid, "exit_status": status,
        "started_monotonic_ns": started, "duration_ns": time.monotonic_ns() - started})
    if status:
        raise RuntimeError(f"{name}: native process exited {status}; retain {evidence}")
    if (evidence / f"{name}.stdout").stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError(f"{name}: oversized evidence record")
    result = json.loads((evidence / f"{name}.stdout").read_text())
    if result.get("status") != "passed" or result.get("all_reaped") is not True:
        raise RuntimeError(f"{name}: missing actual pass/reap evidence")
    if result.get("qualification_eligible") is not False or result.get("native_pause") is not False:
        raise RuntimeError(f"{name}: diagnostic attempted a capability/qualification grant")
    if "pid" in result and result["pid"] != process.pid:
        raise RuntimeError(f"{name}: result PID differs from the actual owned process")
    return result


def production_extension(driver: Path, evidence: Path, kernel: Path, linux_fixture: Path) -> dict:
    """Run an actual production driver, not a fabricated provider implementation.

    Commit 6's production controller must consume the ordinary boot profile,
    exercise the actual provider/controller seams, and produce this closed set of
    observed witness records. An absent driver leaves these gates REQUIRED/PENDING.
    """
    command = [str(driver), "--evidence", str(evidence / "production"), "--kernel", str(kernel),
               "--register-fixture", str(linux_fixture), "--execution-completeness", "--busy-devices"]
    result = invoke(command, evidence, "production-driver")
    if result.get("scope") != "whole-machine-production":
        raise RuntimeError("CPU-only evidence cannot satisfy production busy-device proof")
    required = ("normal_kernel_profile", "native_pit_predicate", "source_resume", "three_fresh_generations",
                "original_due_no_irr", "original_pending", "pending_plus_future", "masked_unmask",
                "in_service_eoi", "offline_start", "halted_wake", "live_xstate", "io_mmio_exact_once",
                "long_prepared_dwell", "contemporary_clock_bracket", "partial_install_reaped",
                "unsupported_participant_named", "busy_block", "busy_net", "busy_vsock", "busy_console",
                "balloon_rng_legacy", "shared_irq", "no_post_release_controller_rewrite")
    witnesses = result.get("witnesses")
    if not isinstance(witnesses, dict) or set(witnesses) != set(required):
        raise RuntimeError("production driver omitted/added an unrecognized witness")
    root = (evidence / "production").resolve(strict=True)
    objects = {}
    for name in required:
        witness = witnesses[name]
        if not isinstance(witness, dict) or set(witness) != {"status", "observations"} or witness["status"] != "passed":
            raise RuntimeError(f"production witness {name} has invalid fields/status")
        observations = witness["observations"]
        if not isinstance(observations, list) or not 1 <= len(observations) <= 64:
            raise RuntimeError(f"production witness {name} lacks bounded observed evidence")
        for record in observations:
            if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
                raise RuntimeError(f"production witness {name} has malformed artifact binding")
            path = Path(record["path"])
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("production evidence path escapes its owned directory")
            path = (root / path).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():
                raise RuntimeError("production evidence is not a retained regular file")
            size = path.stat().st_size
            if not 0 < size <= 16 * 1024 * 1024 or record["bytes"] != size:
                raise RuntimeError("production evidence byte bound/match failed")
            if record["sha256"] != digest(path).hex():
                raise RuntimeError("production evidence digest mismatch")
            objects[path] = size
            if sum(objects.values()) > 64 * 1024 * 1024:
                raise RuntimeError("production observation budget exceeds 64 MiB")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--symbols", required=True, type=Path, help="nm -n output from exact fixture ELF")
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path, help="ordinary production kernel, identity only for CPU fixture")
    parser.add_argument("--production-driver", type=Path)
    parser.add_argument("--linux-fixture", type=Path)
    parser.add_argument("--dwell-ms", type=int, default=2000)
    parser.add_argument("--cpus", required=True, type=int, choices=(1, 2))
    parser.add_argument("--case", required=True, choices=CASES + ("offline", "active-pit", "count-lapic"))
    args = parser.parse_args()
    if args.dwell_ms < 1500 or args.dwell_ms > 60000:
        parser.error("long dwell must be 1500..60000 ms, original sleep is 500 ms")
    if args.case == "offline" and args.cpus != 2:
        parser.error("offline requires two CPUs")
    args.evidence.mkdir(mode=0o700)
    symbols = {}
    for line in args.symbols.read_text().splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    for name in ("interrupt", "io_complete", "mmio_complete"):
        if name not in symbols:
            raise RuntimeError(f"missing exact fixture ELF symbol {name}")
    native = {"host": platform.uname()._asdict(), "probe_sha256": digest(args.probe).hex(),
              "fixture_sha256": digest(args.fixture).hex(), "symbols_sha256": digest(args.symbols).hex(),
              "production_kernel_sha256": digest(args.kernel).hex(), "command": os.sys.argv,
              "scope": "cpu-execution-only", "qualification_eligible": False,
              "native_live": {name: False for name in ("pause", "capture", "restore", "fork", "incremental")}}
    for module, parameter in (("kvm_amd", "avic"), ("kvm", "pi_inject_timer"), ("kvm", "lapic_timer_advance")):
        path = Path("/sys/module") / module / "parameters" / parameter
        native[f"{module}/{parameter}"] = path.read_text().strip() if path.exists() else None
    save(args.evidence / "inputs.json", native)
    cases = []
    for cpus in (args.cpus,):
        for case in (args.case,):
            name = f"cpu{cpus}-{case}"
            lane = args.evidence / name
            lane.mkdir(mode=0o700)
            binding = lane / "binding.bin"
            material = (digest(args.probe) + hashlib.sha256(digest(args.fixture) + digest(args.symbols)).digest()
                        + hashlib.sha256(f"cpu-only:{cpus}".encode()).digest()
                        + hashlib.sha256(b"fixture-ram:0:3145728:no-reclaim").digest() + os.urandom(32))
            binding.write_bytes(material)
            binding.chmod(0o600)
            symbols_arg = ":".join(f"{symbols[key]:x}" for key in ("interrupt", "io_complete", "mmio_complete"))
            source = lane / "generation-0"
            if case in ("active-pit", "count-lapic"):
                invoke([str(args.probe), "negative", str(source), str(binding), str(args.fixture), symbols_arg, str(cpus), case], lane, "negative")
                cases.append({"cpus": cpus, "case": case, "native_refusal": True, "status": "passed"})
                continue
            invoke([str(args.probe), "source", str(source), str(binding), str(args.fixture), symbols_arg, str(cpus), case], lane, "source")
            manifest = capture_manifest(source)
            save(lane / "generation-0.manifest.json", manifest)
            invoke([str(args.probe), "partial", str(source), str(binding), str(cpus), "2"], lane, "partial-install")
            if capture_manifest(source) != manifest:
                raise RuntimeError("failed destination installation modified the source checkpoint")
            previous = source
            generation_case = case
            for generation in range(3):
                child = lane / f"generation-{generation + 1}"
                invoke([str(args.probe), "restore", str(previous), str(child), str(binding), str(cpus), generation_case,
                       str(generation + 2), str(args.dwell_ms)], lane, f"restore-{generation + 1}")
                save(lane / f"generation-{generation + 1}.manifest.json", capture_manifest(child))
                previous = child
                if generation_case == "offline":
                    generation_case = "future"  # actual guest started AP; recapture is now a live two-CPU cut
            cases.append({"cpus": cpus, "case": case, "fresh_generations": 3, "status": "passed"})
    production = {"status": "pending", "reason": "actual production kernel native PIT predicate and commit6 provider-complete driver required"}
    if args.production_driver:
        if not args.linux_fixture:
            parser.error("--production-driver requires --linux-fixture")
        production = production_extension(args.production_driver, args.evidence, args.kernel, args.linux_fixture)
    save(args.evidence / "result.json", {"schema": 1, "scope": "cpu-execution-only", "cpu_cases": cases,
        "production": production, "pending_lanes": ["kvm-arm64", "hvf-arm64"], "qualification_eligible": False})
    print(json.dumps({"status": "passed", "scope": "cpu-execution-only", "production": production["status"],
                      "qualification_eligible": False, "evidence": str(args.evidence)}))


if __name__ == "__main__":
    main()
