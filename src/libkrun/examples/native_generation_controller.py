#!/usr/bin/env python3
"""Bounded ordinary-guest generation proof through the production native owner.

No host register writes, external network, Cargo VM tests or capability grants.
Run each case separately. Negative cases require the isolated fault kernel.
Faults/expiry compare the captured schema-1 payload and transport metadata with
stopped native observations. This is source retention, not fresh-process restore.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import struct
import time

from native_device_controller import Session, cpio, digest, save


def fields(raw: bytes) -> dict[str, str]:
    if not 0 < len(raw) <= 4096:
        raise ValueError("guest generation record byte bound")
    result = {}
    for word in raw.decode("ascii").split():
        key, value = word.split("=", 1)
        if key in result:
            raise ValueError("duplicate generation evidence field")
        result[key] = value
    return result


def validate_ack(native: dict, guest: dict[str, str], before: int, *, clock: bool) -> None:
    identity = bytes(native["id"]).hex()
    sequence = native["sequence"]
    if (native["outcome"] != "acknowledged" or not native["timely"]
            or native["committed_sequence"] != sequence or native["processed_sequence"] != sequence
            or native["processed_id"] != native["id"] or native["driver_status"] != 13
            or guest.get("request_id") != identity or guest.get("completed_id") != identity
            or guest.get("ack_id") != identity or int(guest["request_sequence"]) != sequence
            or int(guest["completed_sequence"]) != sequence or int(guest["ack_sequence"]) != sequence
            or int(guest["request_flags"]) != native["flags"] or int(guest["error"]) != 0
            or guest.get("ack_accessor_returned") != "1"):
        raise ValueError("native low-write receipt and coherent real-driver tuple differ")
    ack = int(guest["ack_write_order"])
    if not 0 < int(guest["clock_complete_order"]) < ack < int(guest["ack_return_order"]):
        raise ValueError("real clock completion/accessor return order differs")
    if int(guest["reseed_count"]) != before + (0 if clock else 1):
        raise ValueError("clock-only reseeded or fresh identity did not reseed exactly once")
    if not clock and (guest["rng_ready_before_call"] != "1"
                      or not 0 < int(guest["reseed_return_order"]) < ack):
        raise ValueError("real initialized-kernel reseed did not precede low-last ACK")


def validate_pending(native: dict, original: dict, phase: int, prior: dict) -> None:
    if (any(native[key] != original[key] for key in ("sequence", "id", "flags", "deadline", "config_generation"))
            or native["outcome"] != "pending" or native["committed_sequence"] == native["sequence"]):
        raise ValueError("rejected ACK replaced, renewed or committed the native attempt")
    expected_sequence = original["sequence"] ^ 1 if phase == 1 else (
        original["sequence"] if phase == 2 else prior["sequence"])
    expected_id = original["id"].copy() if phase < 3 else prior["id"]
    if phase == 2:
        expected_id[0] ^= 1
    if native["processed_sequence"] != expected_sequence or native["processed_id"] != expected_id:
        raise ValueError("actual rejected low-write raw tuple missing")


def validate_capture(payload: bytes, metadata: bytes, before: dict, after: dict, prior: dict) -> dict:
    """Check the existing generation codec's exact pending-with-receipt layout."""
    if before != after or before["outcome"] != "pending":
        raise ValueError("capture changed the stopped pending state or original deadline")
    if before["committed_sequence"] != prior["sequence"] or not 0 < prior["sequence"] < before["sequence"]:
        raise ValueError("capture lacks the independently observed prior committed receipt")
    # State magic/schema, common binding prefix, config, committed tuple, history.
    header = b"KRUNGENS\x01\x00"
    layout = struct.Struct("<HIQQIIQ16sQ16sIQBQ16sIB")
    expected = header + layout.pack(
        1, 0x5347, 1 << 32, 1 << 32,
        1, before["driver_status"], before["sequence"], bytes(before["id"]),
        before["processed_sequence"], bytes(before["processed_id"]),
        before["flags"], before["clock_latch"],
        1, prior["sequence"], bytes(prior["id"]), prior["flags"], 1,
    )
    if payload != expected:
        raise ValueError("serialized pending request/raw ACK/receipt/clock/history differs from native observations")
    transport = {key: int(value) for key, value in fields(metadata).items()}
    expected_transport = {
        "bytes": len(header) + layout.size, "config_generation": before["config_generation"],
        "interrupt_status": transport.get("before_interrupt_status"),
        "avail_features": 1 << 32, "acked_features": 1 << 32,
        "before_config_generation": before["config_generation"],
        "before_interrupt_status": transport.get("before_interrupt_status"),
        "after_config_generation": after["config_generation"],
        "after_interrupt_status": transport.get("before_interrupt_status"),
    }
    if (transport != expected_transport
            or transport["before_interrupt_status"] not in (0, 2)):
        raise ValueError("captured transport binding/counter/IRQ differs from stopped before/after observations")
    decoded = layout.unpack(payload[len(header):])
    return {
        "scope": "same-source-pending-capture, not fresh-process restore",
        "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "serialized": {
            "schema": 1, "codec_version": decoded[0], "device_type": decoded[1],
            "avail_features": decoded[2], "acked_features": decoded[3],
            "version": decoded[4], "driver_status": decoded[5],
            "sequence": decoded[6], "id": list(decoded[7]),
            "processed_sequence": decoded[8], "processed_id": list(decoded[9]),
            "flags": decoded[10], "clock_latch": decoded[11],
            "committed_present": decoded[12], "committed_sequence": decoded[13],
            "committed_id": list(decoded[14]), "committed_flags": decoded[15],
            "history": decoded[16],
        },
        "transport": transport, "before": before, "after": after,
        "prior_committed": prior,
    }


class GenerationSession(Session):
    def native(self) -> dict:
        start = len(self.replies)
        self.command("generation-snapshot")
        lines = [line.removeprefix("GENERATION ") for line in self.replies[start:]
                 if line.startswith("GENERATION ")]
        if len(lines) != 1:
            raise ValueError("one bounded native snapshot required")
        value = json.loads(lines[0])
        with (self.directory / "generation-native.jsonl").open("a") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")
        return value

    def guest(self, advance: bool = False) -> dict[str, str]:
        self.observations.pop("generation", None)
        self.observations.pop("generation-proof", None)
        if os.write(self.console, b"F\n" if advance else b"G\n") != 2:
            raise RuntimeError("short guest generation evidence request")
        self.until(lambda: "generation" in self.observations, "coherent generation_state", timeout=2)
        value = fields(self.observations["generation"])
        with (self.directory / "generation-guest.jsonl").open("a") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")
        return value

    def phase(self, expected: int) -> dict[str, str]:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            guest = self.guest()
            proof = self.observations.get("generation-proof")
            if proof and int(fields(proof)["phase"]) == expected:
                return guest
            self.pump(.005)
        raise RuntimeError(f"diagnostic real-driver phase {expected} absent")

    def acknowledged(self, before: int, *, clock: bool) -> tuple[dict, dict]:
        self.command("generation-wait", timeout=6)
        native = self.native()
        if any(native[key] != self.expected_generation[key] for key in
               ("sequence", "id", "flags", "deadline", "config_generation")):
            raise ValueError("pre-release notification replaced, renewed or republished generation")
        deadline = time.monotonic() + 2
        while True:
            guest = self.guest()
            if guest.get("ack_accessor_returned") == "1" and int(guest["ack_sequence"]) == native["sequence"]:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("native receipt lacks completed guest accessor evidence")
        validate_ack(native, guest, before, clock=clock)
        return native, guest

    def request(self, clock: bool = False) -> dict:
        self.command("pause")
        self.command("generation-clock" if clock else "generation-fresh")
        native = self.native()
        self.expected_generation = native
        self.command("generation-resume")
        return native

    def capture_pending(self, before: dict, prior: dict) -> dict:
        path = self.directory / "pending-generation.payload"
        start = len(self.replies)
        self.command(f"generation-capture {path}")
        records = [line.removeprefix("GENERATION_CAPTURE ") for line in self.replies[start:]
                   if line.startswith("GENERATION_CAPTURE ")]
        if len(records) != 1:
            raise ValueError("one bounded generation capture metadata record required")
        after = self.native()
        with path.open("rb") as source:
            payload = source.read(257)
        evidence = validate_capture(payload, records[0].encode("ascii"), before, after, prior)
        evidence["payload_path"] = str(path)
        save(self.directory / "generation-capture.json", evidence)
        return evidence


def exercise(session: GenerationSession, case: str) -> dict:
    session.start_mux()
    session.progress()
    session.profile()
    initial = session.guest()
    if case == "absent":
        if initial != {"absent": "1", "device_id": "21319"}:
            raise ValueError("absent-driver fixture unexpectedly bound")
        session.request()
        session.command("generation-wait", timeout=6)
        result = session.native()
        if result["outcome"] != "deadline" or result["committed_sequence"]:
            raise ValueError("missing real driver created a receipt")
        return result
    if "absent" in initial or session.native()["driver_status"] != 13:
        raise ValueError("actual production driver/capabilities not ready")
    if case == "positive" and "generation-proof" in session.observations:
        raise ValueError("positive proof requires the unchanged production kernel, not fault instrumentation")
    before = int(initial["reseed_count"])
    if case == "positive":
        first = session.request(clock=True)
        if first["id"] != [0] * 16:
            raise ValueError("initial clock-only lost zero identity")
        zero, guest = session.acknowledged(before, clock=True)
        session.request()
        fresh, guest = session.acknowledged(before, clock=False)
        before = int(guest["reseed_count"])
        session.request(clock=True)
        clock, guest = session.acknowledged(before, clock=True)
        clock_order = guest["clock_complete_order"]
        if clock["id"] != fresh["id"] or clock["sequence"] != fresh["sequence"] + 1:
            raise ValueError("resident clock-only identity/sequence changed incorrectly")
        session.command("pause")
        duplicate_before = session.native()
        session.command("generation-resume")
        duplicate, guest = session.acknowledged(before, clock=True)
        if (any(duplicate[key] != duplicate_before[key] for key in
                ("sequence", "id", "flags", "deadline", "config_generation"))
                or guest["clock_complete_order"] != clock_order):
            raise ValueError("duplicate notification allocated or renewed the request")
        return {"zero_clock": zero, "fresh": fresh, "clock": clock, "duplicate": duplicate}
    if case == "late":
        session.request()
        session.command("generation-wait", timeout=6)
        expired = session.native()
        session.pump(1.5)
        guest = session.guest()
        late = session.native()
        if (expired["outcome"] != "deadline" or late["outcome"] != "deadline"
                or late["committed_sequence"] == late["sequence"]
                or late["processed_sequence"] != late["sequence"]
                or late["processed_id"] != late["id"] or guest["ack_accessor_returned"] != "1"):
            raise ValueError("late exact low-write revived or failed to exercise timed-out attempt")
        return {"expired": expired, "late": late, "guest": guest}
    session.request()
    prior, guest = session.acknowledged(before, clock=False)
    before = int(guest["reseed_count"])
    original = session.request()
    session.phase(1)
    wrong_sequence = session.native()
    validate_pending(wrong_sequence, original, 1, prior)
    session.command("pause")
    paused = session.native()
    if paused != wrong_sequence:
        raise ValueError("real source pause changed pending request/raw ACK/deadline")
    capture = session.capture_pending(paused, prior)
    if case == "expiry":
        session.pump(5.1)
        expired = session.native()
        refusal = session.command("generation-resume", error=True)
        if expired["outcome"] != "deadline" or not refusal.startswith("ERROR generation-resume "):
            raise ValueError("pause extended native deadline or allowed expired-ticket release")
        return {"pending": paused, "capture": capture, "expired": expired, "release_refusal": refusal}
    session.command("generation-resume")
    retained = session.native()
    validate_pending(retained, original, 1, prior)
    session.guest(advance=True)
    session.phase(2)
    wrong_id = session.native()
    validate_pending(wrong_id, original, 2, prior)
    session.guest(advance=True)
    session.phase(3)
    stale = session.native()
    validate_pending(stale, original, 3, prior)
    session.guest(advance=True)
    exact, guest = session.acknowledged(before, clock=False)
    if any(exact[key] != original[key] for key in ("sequence", "id", "flags", "deadline")):
        raise ValueError("exact continuation did not retain original tuple/deadline")
    return {"wrong_sequence": wrong_sequence, "paused": paused, "capture": capture, "retained": retained,
            "wrong_id": wrong_id, "stale": stale, "exact": exact, "guest": guest}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("probe", "netd", "guest-init", "register-fixture", "kernel", "kernel-config", "production-patch", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--case", choices=("positive", "faults", "late", "absent", "expiry"), required=True)
    args = parser.parse_args()
    args.sessions = []
    args.execution_completeness = False
    args.generation = True
    args.generation_proof_mode = {"positive": 0, "faults": 1, "late": 2, "absent": 3, "expiry": 1}[args.case]
    args.kernel_modules = "CONFIG_MODULES=y" in args.kernel_config.read_text().splitlines()
    args.evidence.mkdir(mode=0o700)
    args.binding = args.evidence / "binding"
    args.binding.mkdir(mode=0o700)
    identity = {name: digest(getattr(args, name)) for name in
                ("probe", "netd", "guest_init", "register_fixture", "kernel", "kernel_config")}
    source = Path(__file__).resolve().parent
    identity["controller"] = digest(Path(__file__).resolve())
    identity["guest_source"] = digest(source / "native_device_linux.c")
    identity["fault_patch"] = digest(source / "native_generation_fault.patch")
    identity["fault_header"] = digest(source / "native_generation_fault.h")
    identity["production_patch"] = digest(args.production_patch)
    material = json.dumps(identity, sort_keys=True).encode()
    for name in ("profile", "topology", "ram-layout"):
        (args.binding / name).write_bytes(hashlib.sha256(name.encode() + material).digest())
    for name in ("source-run", "capture"):
        (args.binding / name).write_bytes(os.urandom(16))
    args.initramfs = args.evidence / "initramfs.cpio"
    cpio(args.initramfs, [("init", args.guest_init.read_bytes(), 0o100755),
                         ("register-fixture", args.register_fixture.read_bytes(), 0o100755)])
    identity["initramfs"] = digest(args.initramfs)
    save(args.evidence / "inputs.json", {"argv": os.sys.argv, "sha256": identity,
         "diagnostic_kernel_required": args.case != "positive", "vcpus": 2, "ram_mib": 512,
         "generation_deadline_seconds": 5, "controller_bound_seconds": 180,
         "production_guest_patch": "unchanged", "capability_grant": False})
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo.setblocking(False)
    session = None
    report = {"scope": "standalone-generation-driver", "case": args.case, "status": "failed"}
    def timeout(_signum, _frame):
        raise TimeoutError("explicit 180-second generation controller bound")
    previous = signal.signal(signal.SIGALRM, timeout)
    signal.alarm(180)
    try:
        disks = []
        for index in range(2):
            path = args.evidence / f"disk{index}.raw"
            with path.open("xb") as output:
                output.truncate(128 * 1024 * 1024)
            subprocess.run(["mkfs.ext4", "-F", "-q", str(path)], check=True, timeout=30, capture_output=True)
            disks.append(path)
        session = GenerationSession.create(args, args.evidence / "source", disks, echo)
        report["observations"] = exercise(session, args.case)
        session.stop()
        if session.close() or not session.native_reaped:
            raise RuntimeError("owned native/backend resources not reaped")
        report.update(status="passed", all_reaped=True)
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        cleanup = []
        for owner in args.sessions:
            failure = None
            stop_failure = None
            returned = []
            if owner is not session or not owner.native_reaped:
                process = getattr(owner, "process", None)
                if not owner.native_reaped and process is not None and process.poll() is None:
                    try:
                        owner.stop()
                    except BaseException as error:
                        stop_failure = str(error)
                try:
                    returned = owner.close()
                except BaseException as error:
                    failure = str(error)
            cleanup.append({
                "directory": str(owner.directory),
                "native_stop_acknowledged": bool(owner.native_reaped),
                "failures": list(getattr(owner, "cleanup_failures", returned)),
                "exception": failure,
                "stop_exception": stop_failure,
            })
        report["cleanup"] = cleanup
        report["all_reaped"] = bool(cleanup) and all(
            item["native_stop_acknowledged"] and not item["failures"]
            and item["stop_exception"] is None and item["exception"] is None
            for item in cleanup
        )
        cleanup_invalidated_pass = report["status"] == "passed" and not report["all_reaped"]
        if cleanup_invalidated_pass:
            report.update(status="failed", error="owned native/backend cleanup failed")
        echo.close()
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        save(args.evidence / "generation-report.json", report)
        print(json.dumps(report, sort_keys=True))
        if cleanup_invalidated_pass:
            raise RuntimeError(report["error"])


if __name__ == "__main__":
    main()
