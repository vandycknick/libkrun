#!/usr/bin/env python3
"""Explicit native execution gate. Never imported by a Cargo/pytest test target.

All input binaries are built by Main before invocation. The controller does not
build, modify host timer configuration, grant capabilities, or substitute devices.
Failure retains every artifact; the outer process timeout is not a native reap ACK.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import socket
import struct
import time
import unittest

from native_ram_image import (
    MAX_RAM_LAYOUT_BYTES, authenticate_image, authentication_bytes,
    layout_digest, validate_layout, write_authentication,
)

CASES = ("future", "due", "due-no-irr", "masked", "pending-future", "in-service", "io", "mmio")


def digest(path: Path) -> bytes:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.digest()

def capture_manifest(directory: Path) -> dict:
    limits = {"execution.state": 16 * 1024 * 1024, "ram.bin": 3145728,
              "memory-layout.json": MAX_RAM_LAYOUT_BYTES,
              "capture.json": 65536, "native-inventory.txt": 16 * 1024 * 1024}
    result = {}
    for name, limit in limits.items():
        path = directory / name
        size = path.stat().st_size
        if not path.is_file() or size > limit or (name == "ram.bin" and size != limit):
            raise RuntimeError(f"invalid bounded capture object {path}")
        result[name] = {"bytes": size, "sha256": digest(path).hex()}
    return result


def save(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")

def remaining(deadline: float) -> float:
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise TimeoutError("layout binding invocation deadline expired")
    return duration


def socket_receive(channel: socket.socket, length: int, deadline: float) -> bytes:
    output = bytearray()
    while len(output) < length:
        channel.settimeout(remaining(deadline))
        block = channel.recv(length - len(output))
        if not block:
            raise RuntimeError("layout binding unexpected EOF")
        output.extend(block)
    return bytes(output)


def receive_layout(channel: socket.socket, deadline: float) -> bytes:
    length = struct.unpack("<I", socket_receive(channel, 4, deadline))[0]
    if not 0 < length <= MAX_RAM_LAYOUT_BYTES:
        raise RuntimeError("layout binding length outside bound")
    data = socket_receive(channel, length, deadline)
    validate_layout(data)
    channel.settimeout(remaining(deadline))
    if channel.recv(1):
        raise RuntimeError("layout preparation contains trailing bytes")
    remaining(deadline)
    return data


def send_binding(channel: socket.socket, material: bytes, deadline: float) -> None:
    if len(material) != 128:
        raise RuntimeError("layout binding must contain exactly 128 bytes")
    pending = memoryview(material)
    while pending:
        channel.settimeout(remaining(deadline))
        count = channel.send(pending)
        if not count:
            raise RuntimeError("layout binding write made no progress")
        pending = pending[count:]
    remaining(deadline)
    channel.shutdown(socket.SHUT_WR)


def prepare_authentication(
    directory: Path, expected: bytes, prepared: bytes, ram_fd: int, layout_fd: int,
) -> dict:
    authentication = authenticate_image(
        directory / "ram.bin", directory / "memory-layout.json", expected,
        prepared=prepared, ram_fd=ram_fd, layout_fd=layout_fd,
    )
    target = directory / "ram-authentication.bin"
    encoded = authentication_bytes(authentication)
    if target.exists():
        if target.read_bytes() != encoded:
            raise RuntimeError("saved RAM authentication changed")
    else:
        write_authentication(target, authentication)
    return authentication


def authenticate_checkpoint(directory: Path, expected: bytes, prepared: bytes) -> dict:
    with ExitStack() as resources:
        descriptors = []
        for role in ("ram.bin", "memory-layout.json"):
            descriptor = os.open(directory / role, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            resources.callback(os.close, descriptor)
            descriptors.append(descriptor)
        return prepare_authentication(directory, expected, prepared, *descriptors)



def invoke(
    command: list[str], evidence: Path, name: str, *, timeout: float,
    layout_binding: tuple[bytes, Path] | None = None,
    restore_image: tuple[Path, bytes, bytes] | None = None,
) -> dict:
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    authentication = None
    command = list(command)
    with ExitStack() as resources:
        stdout = resources.enter_context((evidence / f"{name}.stdout").open("xb"))
        stderr = resources.enter_context((evidence / f"{name}.stderr").open("xb"))
        os.chmod(stdout.name, 0o600)
        os.chmod(stderr.name, 0o600)
        inherited = []
        channel = native_channel = None
        if layout_binding is not None:
            channel, native_channel = socket.socketpair()
            resources.enter_context(channel)
            resources.enter_context(native_channel)
            inherited.append(native_channel.fileno())
            command[3] = str(native_channel.fileno())
        if restore_image is not None:
            directory, expected, prepared = restore_image
            descriptors = []
            for role in ("ram.bin", "memory-layout.json"):
                descriptor = os.open(directory / role, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                resources.callback(os.close, descriptor)
                descriptors.append(descriptor)
            authentication = prepare_authentication(directory, expected, prepared, *descriptors)
            inherited.extend(descriptors)
            command.extend(str(descriptor) for descriptor in descriptors)
        remaining(deadline)
        process = subprocess.Popen(
            command, stdout=stdout, stderr=stderr, start_new_session=True, pass_fds=tuple(inherited),
        )
        if native_channel is not None:
            native_channel.close()
        try:
            if channel is not None and layout_binding is not None:
                material, binding_path = layout_binding
                prepared = receive_layout(channel, deadline)
                material = material[:64] + layout_digest(prepared) + material[96:]
                with binding_path.open("xb") as output:
                    os.chmod(output.name, 0o600)
                    output.write(material)
                with (binding_path.parent / "prepared-memory-layout.json").open("xb") as output:
                    os.chmod(output.name, 0o600)
                    output.write(prepared)
                send_binding(channel, material, deadline)
            status = process.wait(timeout=remaining(deadline))
        except (subprocess.TimeoutExpired, TimeoutError, RuntimeError, ValueError, OSError) as failure:
            if channel is not None:
                channel.close()
            cleanup = {"process_group": process.pid, "grace_seconds": 120,
                       "forced_reap_seconds": 10, "controller_exited_during_grace": False,
                       "group_kill_sent": False, "controller_reaped": False, "errors": []}
            try:
                os.kill(process.pid, signal.SIGINT)
                deadline = time.monotonic() + cleanup["grace_seconds"]
                # WNOWAIT reserves the session leader's PID/PGID until the final
                # group signal. Popen.poll/wait here could reap and release it.
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    grace_remaining = deadline - time.monotonic()
                    if grace_remaining <= 0:
                        break
                    time.sleep(min(.05, grace_remaining))
                else:
                    cleanup["controller_exited_during_grace"] = True
            except OSError as error:
                cleanup["errors"].append(f"controller interruption: {error}")
            try:
                # Native and netd children inherit this dedicated group. Signal
                # survivors even when the controller already finished unwinding.
                os.killpg(process.pid, signal.SIGKILL)
                cleanup["group_kill_sent"] = True
            except ProcessLookupError:
                cleanup["group_absent_before_kill"] = True
            except OSError as error:
                cleanup["errors"].append(f"owned group kill: {error}")
            try:
                cleanup["controller_exit_status"] = process.wait(timeout=cleanup["forced_reap_seconds"])
                cleanup["controller_reaped"] = True
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup["errors"].append(f"controller reap: {error}")
            save(evidence / f"{name}.invocation.json", {"command": command, "pid": process.pid,
                "timeout": isinstance(failure, (subprocess.TimeoutExpired, TimeoutError)),
                "error": str(failure), "native_cleanup_acknowledged": False,
                "duration_ns": time.monotonic_ns() - started, "timeout_seconds": timeout, "cleanup": cleanup})
            raise RuntimeError(f"{name}: invocation failed ({failure}), NOT a successful native cleanup") from failure
    save(evidence / f"{name}.invocation.json", {"command": command, "pid": process.pid, "exit_status": status,
        "started_monotonic_ns": started, "duration_ns": time.monotonic_ns() - started,
        "timeout_seconds": timeout, "caller_authentication": authentication})
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
    result = invoke(command, evidence, "production-driver", timeout=600)
    if result.get("scope") != "whole-machine-production":
        raise RuntimeError("CPU-only evidence cannot satisfy production busy-device proof")
    required = ("normal_kernel_profile", "native_pit_predicate", "source_resume", "three_fresh_generations",
                "original_due_no_irr", "original_pending", "pending_plus_future", "masked_unmask",
                "in_service_eoi", "offline_start", "halted_wake", "live_xstate", "io_mmio_exact_once",
                "long_prepared_dwell", "contemporary_clock_bracket", "partial_install_reaped",
                "unsupported_participant_named", "busy_block", "busy_net", "busy_vsock", "busy_console",
                "balloon_rng_legacy", "shared_irq", "no_post_release_controller_rewrite",
                "absolute_timer_delivery")
    witnesses = result.get("witnesses")
    if not isinstance(witnesses, dict) or set(witnesses) != set(required):
        raise RuntimeError("production driver omitted/added an unrecognized witness")
    root = (evidence / "production").resolve(strict=True)
    objects = {}
    for name in required:
        witness = witnesses[name]
        expected_status = "observed-not-gating" if name == "absolute_timer_delivery" else "passed"
        if not isinstance(witness, dict) or set(witness) != {"status", "observations"} or witness["status"] != expected_status:
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
            material = (hashlib.sha256(digest(args.fixture) + digest(args.symbols)).digest()
                        + hashlib.sha256(f"cpu-only:{cpus}".encode()).digest()
                        + bytes(32) + os.urandom(32))
            symbols_arg = ":".join(f"{symbols[key]:x}" for key in ("interrupt", "io_complete", "mmio_complete"))
            source = lane / "generation-0"
            if case in ("active-pit", "count-lapic"):
                invoke([str(args.probe), "negative", str(source), "LAYOUT_BINDING_FD", str(args.fixture), symbols_arg, str(cpus), case],
                       lane, "negative", timeout=120, layout_binding=(material, binding))
                cases.append({"cpus": cpus, "case": case, "native_refusal": True, "status": "passed"})
                continue
            invoke([str(args.probe), "source", str(source), "LAYOUT_BINDING_FD", str(args.fixture), symbols_arg, str(cpus), case],
                   lane, "source", timeout=120, layout_binding=(material, binding))
            prepared = (lane / "prepared-memory-layout.json").read_bytes()
            expected_layout = binding.read_bytes()[64:96]
            save(lane / "generation-0.authentication.json", authenticate_checkpoint(source, expected_layout, prepared))
            manifest = capture_manifest(source)
            save(lane / "generation-0.manifest.json", manifest)
            invoke([str(args.probe), "partial", str(source), str(binding), str(cpus), "2"],
                   lane, "partial-install", timeout=120, restore_image=(source, expected_layout, prepared))
            if capture_manifest(source) != manifest:
                raise RuntimeError("failed destination installation modified the source checkpoint")
            previous = source
            generation_case = case
            for generation in range(3):
                child = lane / f"generation-{generation + 1}"
                invoke([str(args.probe), "restore", str(previous), str(child), str(binding), str(cpus), generation_case,
                       str(generation + 2), str(args.dwell_ms)], lane, f"restore-{generation + 1}", timeout=120,
                       restore_image=(previous, expected_layout, prepared))
                save(lane / f"generation-{generation + 1}.authentication.json",
                     authenticate_checkpoint(child, expected_layout, prepared))
                save(lane / f"generation-{generation + 1}.manifest.json", capture_manifest(child))
                previous = child
                if generation_case == "offline":
                    generation_case = "future"  # actual guest started AP; recapture is now a live two-CPU cut
            cases.append({"cpus": cpus, "case": case, "fresh_generations": 3, "status": "passed",
                          "absolute_no_early_requirement": "not-measured"})
    production = {"status": "pending", "reason": "actual production kernel native PIT predicate and commit6 provider-complete driver required"}
    if args.production_driver:
        if not args.linux_fixture:
            parser.error("--production-driver requires --linux-fixture")
        production = production_extension(args.production_driver, args.evidence, args.kernel, args.linux_fixture)
    save(args.evidence / "result.json", {"schema": 1, "scope": "cpu-execution-only", "cpu_cases": cases,
        "production": production, "pending_lanes": ["kvm-arm64", "hvf-arm64"], "qualification_eligible": False,
        "absolute_no_early_requirement": "not-measured"})
    print(json.dumps({"status": "passed", "scope": "cpu-execution-only", "production": production["status"],
                      "qualification_eligible": False, "evidence": str(args.evidence),
                      "absolute_no_early_requirement": "not-measured"}))


class LayoutBindingTests(unittest.TestCase):
    """Socket, caller-boundary and actual subprocess tests. No hypervisor."""

    @staticmethod
    def canonical_layout() -> bytes:
        return (
            b'{"architecture":"x86_64","kind":"ram-layout","magic":"KRUNRAML","packedLength":4096,'
            b'"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":4096,'
            b'"streamOffset":0}],"schema":1,"topology":{"firmwareAddress":0,'
            b'"initrdAddress":4096,"ramAboveGap":0,"ramBelowGap":4096,'
            b'"ramLastAddress":4096,"shmStartAddress":4294967296}}'
        )

    def test_exact_layout_and_binding_half_close(self) -> None:
        native, controller = socket.socketpair()
        with native, controller:
            layout = self.canonical_layout()
            native.sendall(struct.pack("<I", len(layout)) + layout)
            native.shutdown(socket.SHUT_WR)
            prepared = receive_layout(controller, time.monotonic() + 1)
            self.assertEqual(prepared, layout)
            material = b"a" * 64 + layout_digest(prepared) + b"b" * 32
            send_binding(controller, material, time.monotonic() + 1)
            self.assertEqual(socket_receive(native, 128, time.monotonic() + 1), material)
            self.assertEqual(native.recv(1), b"")

    def test_layout_rejects_bounds_eof_noncanonical_and_extra(self) -> None:
        layout = self.canonical_layout()
        frames = [
            b"", b"\x01\x00", struct.pack("<I", 0),
            struct.pack("<I", MAX_RAM_LAYOUT_BYTES + 1),
            struct.pack("<I", len(layout)) + layout[:-1],
            struct.pack("<I", len(layout) + 1) + layout + b"\n",
            struct.pack("<I", len(layout)) + layout + b"x",
        ]
        for frame in frames:
            with self.subTest(frame=frame[:4]):
                native, controller = socket.socketpair()
                with native, controller:
                    native.sendall(frame)
                    native.shutdown(socket.SHUT_WR)
                    with self.assertRaises((RuntimeError, ValueError)):
                        receive_layout(controller, time.monotonic() + 1)

    def test_absolute_deadline_and_binding_width(self) -> None:
        native, controller = socket.socketpair()
        with native, controller:
            native.sendall(b"\x01")
            with self.assertRaises(TimeoutError):
                receive_layout(controller, time.monotonic() + .01)
            with self.assertRaises(TimeoutError):
                socket_receive(controller, 1, time.monotonic() - 1)
            for length in (0, 127, 129):
                with self.assertRaises(RuntimeError):
                    send_binding(controller, bytes(length), time.monotonic() + 1)

    def test_correct_width_wrong_layout_digest_fails_before_ram_scan(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = self.canonical_layout()
            (root / "memory-layout.json").write_bytes(layout)
            (root / "ram.bin").write_bytes(bytes(4096))
            wrong = bytes(value ^ 1 for value in layout_digest(layout))
            with self.assertRaises((RuntimeError, ValueError)):
                authenticate_checkpoint(root, wrong, layout)
            with self.assertRaises((RuntimeError, ValueError)):
                authenticate_checkpoint(root, layout_digest(layout), layout + b"\n")

    def test_invoke_launches_waits_and_records_actual_child_exit(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            command = [os.sys.executable, "-c", "raise SystemExit(7)"]
            with self.assertRaisesRegex(RuntimeError, "native process exited 7"):
                invoke(command, evidence, "actual-child", timeout=5)
            record = json.loads((evidence / "actual-child.invocation.json").read_text())
            self.assertEqual(record["exit_status"], 7)
            self.assertEqual(record["command"], command)
            self.assertGreater(record["pid"], 0)
            self.assertGreater(record["duration_ns"], 0)


if __name__ == "__main__":
    main()
