"""Actual standalone device pressure, called only by the production controller.

No native result is inferred from a timeout, helper allocation counter, process
exit, or a pure test. Missing native observations fail this gate. Inputs and all
Session/netd/VM resources are supplied and owned by the calling controller.
"""
from __future__ import annotations

import array
import copy
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from native_device_controller import Session

KEYS = ("busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy",
        "shared_irq", "no_post_release_controller_rewrite")
MAGIC = 0x5052455353555245
ECHO = 0x484F53544543484F
PACKET = struct.Struct("<6Q")


def save(path: Path, value: object) -> Path:
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
    return path


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(f"actual device pressure: {reason}")


def integer(value: object, label: str) -> int:
    require(type(value) is int and 0 <= value < 1 << 64, f"invalid {label}")
    return value


def validate_reclaim_status(record: dict, backing: str | None = None) -> dict:
    counters = ("released_bytes", "released_extents", "retried_faults", "skipped_reports",
                "failed_operations", "mapping_limit_skips", "replaced_islands")
    fields = {"backing", "reason", "requested", "qualification", "effective", *counters}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("actual reclaim status fields")
    linux = os.uname().sysname == "Linux"
    reasons = {"boot": "tracked-capture", "restored-private": "restored-private-mapping"}
    if (type(record["backing"]) is not str or record["backing"] not in reasons
            or backing is not None and record["backing"] != backing
            or record["reason"] != ("none" if linux else reasons[record["backing"]])
            or record["requested"] is not linux or record["effective"] is not linux
            or record["qualification"] != "not-run"):
        raise ValueError("actual tracked/restored reclaim policy")
    for field in counters:
        if type(record[field]) is not int or not 0 <= record[field] < 1 << 64:
            raise ValueError(f"actual reclaim counter {field}")
    if not linux and any(record[field] != 0 for field in (
            "released_bytes", "released_extents", "retried_faults", "mapping_limit_skips", "replaced_islands")):
        raise ValueError("inhibited reclaim reported successful advice/fault retry")
    return record


@contextmanager
def stopped_child(child: Session, root: Path):
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        save(root / "destination-failure.json", {"error": str(error), "type": type(error).__name__})
        raise
    finally:
        outcome = {"explicit_stop_requested": True, "native_cleanup_acknowledged": False,
                   "stop_error": None, "close_error": None, "close_failures": []}
        try:
            child.stop()
            outcome["native_cleanup_acknowledged"] = child.native_reaped
        except BaseException as error:
            outcome["stop_error"] = {"error": str(error), "type": type(error).__name__}
        try:
            outcome["close_failures"] = child.close()
        except BaseException as error:
            outcome["close_error"] = {"error": str(error), "type": type(error).__name__}
        save(root / "destination-cleanup.json", outcome)
        if primary is None:
            require(outcome["native_cleanup_acknowledged"] and not outcome["stop_error"]
                    and not outcome["close_error"] and not outcome["close_failures"],
                    f"fresh child/netd cleanup failed: {outcome}")


@dataclass(frozen=True)
class ConsoleRecords:
    data: bytes
    records: tuple[int, ...]
    trailing: bytes

    @classmethod
    def parse(cls, data: bytes, first: int = 1) -> ConsoleRecords:
        lines = data.split(b"\n")
        trailing = lines.pop()
        records = []
        for sequence, line in enumerate(lines, first):
            require(line == f"CONSOLE {sequence}".encode("ascii"),
                    "lost/duplicated/corrupt numbered console bytes")
            records.append(sequence)
        expected = f"CONSOLE {first + len(records)}\n".encode("ascii")
        require(expected.startswith(trailing), "corrupt trailing numbered console prefix")
        return cls(data, tuple(records), trailing)

    def continued(self, data: bytes) -> ConsoleRecords:
        require(bool(self.records), "missing numbered console cut boundary")
        # The saved prefix is observer state, never input to a guest or endpoint.
        return self.parse(self.trailing + data, self.records[-1] + 1)


class Pressure:
    def __init__(self, args, session: Session, echo: socket.socket):
        self.args, self.session, self.echo = args, session, echo
        self.root = args.evidence / "device-pressure"
        self.root.mkdir(mode=0o700)
        self.token = 0
        self.artifacts: dict[str, list[Path]] = {name: [] for name in KEYS}
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.setblocking(False)
        self.packets: list[dict] = []
        self.control_buffer = bytearray()
        self.control_fds: list[int] = []
        self.accepted: list[socket.socket] = []
        self.accept_pending: dict[socket.socket, bytearray] = {}
        self.control_requests: list[dict] = []
        self.children: list[Session] = []
        self.source_devices: dict[str, dict] = {}
        self.source_guest: dict = {}

    def pump(self, duration: float = .02) -> None:
        end = time.monotonic() + duration
        while time.monotonic() < end:
            self.session.pump(min(.01, max(0, end - time.monotonic())))
            while True:
                try:
                    deferred = getattr(self.session, "pressure_deferred_packets", [])
                    packet, peer = deferred.pop(0) if deferred else self.udp.recvfrom(65536)
                except BlockingIOError:
                    break
                received = time.monotonic_ns()
                with (self.root / "actual-netd-packets.jsonl").open("a", encoding="utf-8") as output:
                    os.chmod(output.name, 0o600)
                    output.write(json.dumps({"payload_hex": packet.hex(), "peer": list(peer),
                                             "received_host_ns": received}) + "\n")
                require(len(packet) == PACKET.size, "malformed actual netd UDP payload")
                magic, token, sequence, phase, sent, marker = PACKET.unpack(packet)
                require(magic == MAGIC and phase <= 2 and marker == 0, "foreign netd UDP record")
                self.packets.append({"token": token, "sequence": sequence, "phase": phase,
                                     "sent_guest_ns": sent, "received_host_ns": received, "peer": list(peer)})
                require(len(self.packets) <= 100000, "bounded UDP observation budget exhausted")
                self.udp.sendto(PACKET.pack(magic, token, sequence, phase, sent, ECHO), peer)
            self.service_control()
            for stream in tuple(self.accepted):
                try:
                    packet = stream.recv(65536)
                except BlockingIOError:
                    continue
                if not packet:
                    stream.close(); self.accepted.remove(stream); self.accept_pending.pop(stream, None)
                    continue
                self.accept_pending[stream].extend(packet)
                pending = self.accept_pending[stream]
                try:
                    done = stream.send(pending)
                except BlockingIOError:
                    continue
                del pending[:done]

    def service_control(self) -> None:
        while True:
            try:
                data, ancillary, flags, _ = self.session.mux.recvmsg(4096, socket.CMSG_SPACE(16 * array.array("i").itemsize))
            except BlockingIOError:
                break
            for level, kind, rights in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array("i")
                    descriptors.frombytes(rights[:len(rights) - len(rights) % descriptors.itemsize])
                    self.control_fds.extend(descriptors)
            require(all(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
                        for level, kind, _ in ancillary), "unexpected mux ancillary data")
            require(not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC), "truncated real SCM_RIGHTS frame")
            require(bool(data), "actual mux control endpoint closed")
            self.control_buffer.extend(data)
            require(len(self.control_buffer) <= 131072 and len(self.control_fds) <= 1024, "mux control observation bounds")
            while b"\n" in self.control_buffer:
                line, _, rest = self.control_buffer.partition(b"\n")
                self.control_buffer = bytearray(rest)
                fields = line.split()
                require(len(fields) == 4 and fields[0] == b"CONNECT" and self.control_fds,
                        "unexpected actual outgoing listener request")
                request, host_port, guest_port = map(int, fields[1:])
                require(host_port == 14567, "unbound outgoing guest service")
                stream = socket.socket(fileno=self.control_fds[0])
                self.control_fds.pop(0)
                self.accepted.append(stream); self.accept_pending[stream] = bytearray()
                stream.setblocking(False)
                self.control_requests.append({"request": request, "host_port": host_port,
                                              "guest_port": guest_port, "accepted_fd": stream.fileno()})
                self.session.mux.sendall(f"OK {request}\n".encode())

    def until(self, predicate, label: str, timeout: float = 30) -> None:
        end = time.monotonic() + timeout
        while not predicate():
            require(time.monotonic() < end, f"timeout observing {label}, not a successful native ACK")
            self.pump()

    def guest(self, command: str = "SNAP") -> dict:
        self.token += 1
        token = self.token
        text = command.format(token=token, port=self.udp.getsockname()[1])
        if text == "SNAP":
            text = f"SNAP {token}"
        os.write(self.session.console, ("P" + text + "\n").encode())
        self.until(lambda: any(item.get("token") == token for item in self.session.pressure_samples), text)
        result = next(item for item in reversed(self.session.pressure_samples) if item.get("token") == token)
        require(result.get("failed") == 0 and result.get("operation") == "snapshot", "actual guest pressure failed")
        require(integer(result.get("disk_checks"), "disk_checks") > 0, "no persisted numbered disk verification")
        require(len(result["disk_capacity"]) == 2 and all(size > 0 for size in result["disk_capacity"])
                and result["disk_readonly"] == [0, 0]
                and len(result["disk_serial_hex"]) == 2 and all(result["disk_serial_hex"]),
                "actual guest disk capacity/readonly/serial observation missing")
        return result

    def native(self, label: str) -> tuple[dict, Path]:
        path = self.root / f"{label}.native.json"
        self.session.command(f"pressure snapshot {path}")
        require(path.is_file() and 0 < path.stat().st_size <= 16 * 1024 * 1024, "native snapshot absent/oversized")
        value = json.loads(path.read_text())
        require(value["pid"] == self.session.process.pid, "foreign native owner PID")
        require(isinstance(value["devices"], list) and isinstance(value["legacy"], list), "incomplete actual inventory")
        vsock = value["vsock"]
        require(vsock["overflowed"] is False, "native pressure counters overflowed")
        if value["controller"]["state"].startswith("RestorePrepared"):
            require(vsock["expected"] == 0 and vsock["started"] == 0 and not vsock["worker_threads"],
                    "dormant destination constructed actual running mux owners")
        else:
            require(vsock["expected"] & 3 == 3 and vsock["unfinished_workers"] >= 2,
                    "actual retained mux/reaper owners absent")
        return value, path

    def attach(self, names: tuple[str, ...], *paths: Path) -> None:
        for name in names:
            self.artifacts[name].extend(paths)
            require(len(self.artifacts[name]) <= 64, "witness artifact count exceeds closed bound")

    def progress(self, before: dict) -> dict:
        after = self.session.progress(before)
        observation = self.session.last_device_counter_observation
        path = save(self.root / f"device-progress-{observation['request_token']}.json",
                    {"observation": observation, "continued": after})
        self.attach(("busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy"), path)
        return after

    def partial_control_pause(self) -> None:
        local, remote = socket.socketpair()
        try:
            local.setblocking(False)
            passed_fd = remote.fileno()
            sent = self.session.mux.sendmsg([b"CONN"],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [passed_fd]))])
            require(sent == 4, "partial real control frame/descriptor transfer was not accepted")
            remote.close()
            self.pump(.05)
            before = self.session.samples[-1].copy()
            self.session.command("pause")
            paused, paused_path = self.native("partial-control-paused")
            require(paused["vsock"]["parked"] & paused["vsock"]["expected"] == paused["vsock"]["expected"],
                    "actual mux owners failed to park with an accepted partial SCM_RIGHTS frame")
            self.session.command("resume")
            require(self.session.mux.send(b"ECT 1028\n") == 9, "partial control remainder send failed")
            marker = PACKET.pack(MAGIC, 0, 0, 0, 0, 0)
            require(local.send(marker) == len(marker), "retained control stream write failed")
            received = bytearray()
            acknowledgement = None
            deadline = time.monotonic() + 30
            while acknowledgement is None or len(received) < len(marker):
                require(time.monotonic() < deadline, "retained partial control/FD failed to resume")
                try:
                    data = local.recv(64 if acknowledgement is None else len(marker) - len(received))
                    require(bool(data), "actual retained partial control stream closed")
                    received.extend(data)
                    acknowledgement = self.session.parse_mux_ack(received, acknowledgement)
                except BlockingIOError:
                    pass
                self.pump()
            record = save(self.root / "partial-control-resumed.json",
                          {"accepted_prefix_bytes": sent, "transferred_fd": passed_fd,
                           "acknowledgement": acknowledgement,
                           "sent": marker.hex(), "received": received.hex(), "pid": paused["pid"]})
            require(received == marker, "partial control pause duplicated/corrupted actual stream payload")
            self.progress(before)
            self.attach(("busy_vsock",), paused_path, record)
        finally:
            local.close(); remote.close()

    def console_records(self, session: Session, boundary: ConsoleRecords | None = None) -> ConsoleRecords:
        session.output_log.flush()
        data = (session.directory / "console-output.log").read_bytes()
        return boundary.continued(data) if boundary is not None else ConsoleRecords.parse(data)

    def mux_pressure(self) -> dict:
        before, _ = self.native("mux-before")
        stream = self.session.connect_mux(port=1028, partial=True)
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        payload = bytes(range(256)) * 4096
        sent = 0
        end = time.monotonic() + 5
        while sent < len(payload) and time.monotonic() < end:
            try:
                sent += stream.send(payload[sent:sent + 16384])
            except BlockingIOError:
                pass
            self.pump(.01)
        require(sent > 65536, "did not exceed real vsock receive credit")
        pressured, path = self.native("mux-credit-exhaustion")
        require(pressured["vsock"]["waiting_credit"] > 0 or pressured["vsock"]["deferred_credits"] > 0,
                "no actual mux credit/backpressure owner was observed")
        received = bytearray()
        acknowledgement = None
        end = time.monotonic() + 30
        while acknowledgement is None or len(received) < sent:
            require(time.monotonic() < end, "actual exhausted-credit stream failed to resume")
            try:
                data = stream.recv(min(65536, sent - len(received)))
                require(bool(data), "actual credit stream closed before all accepted bytes")
                received.extend(data)
                acknowledgement = self.session.parse_mux_ack(received, acknowledgement)
            except BlockingIOError:
                pass
            self.pump(.01)
        stream_record = save(self.root / "mux-credit-resumed.json",
                             {"acknowledgement": acknowledgement, "sent": sent,
                              "received": len(received), "exact_payload": received.hex()})
        require(received == payload[:sent], "lost/duplicated vsock payload across credit exhaustion")
        stream.close()
        outgoing = self.guest("HOLD {token} 14567")
        require(outgoing["guest_connects"] > 0 and self.control_requests, "no real listener accept with SCM_RIGHTS")
        for _ in range(16):
            transient = self.session.connect_mux(port=1028, partial=True)
            transient.close()
        self.pump(7)
        after, after_path = self.native("mux-reaped")
        require(after["vsock"]["host_connects"] > before["vsock"]["host_connects"], "host mux traffic not observed")
        require(after["vsock"]["credit_queued"] > before["vsock"]["credit_queued"]
                and after["vsock"]["credit_delivered"] > before["vsock"]["credit_delivered"], "no real credit request/update progress")
        require(after["vsock"]["reaps"] > before["vsock"]["reaps"], "deferred reaper did not run")
        record = save(self.root / "mux-workload.json", {"sent": sent, "received": len(received),
                      "acknowledgement": acknowledgement, "exact_payload": received.hex(),
                      "listener_requests": self.control_requests, "guest": outgoing})
        self.attach(("busy_vsock",), path, after_path, stream_record, record)
        return after

    def paused_cut(self) -> tuple[Path, dict, dict, ConsoleRecords]:
        network_configuration = self.guest("NET {token} {port} 0")
        self.pump(.5)
        require(bool(self.packets), "actual netd has no source UDP mapping for ingress pressure")
        peer = tuple(self.packets[-1]["peer"])
        before = self.session.samples[-1].copy()
        disk_before = self.guest()
        self.source_guest = disk_before
        self.session.command("pause")
        state, state_path = self.native("source-cut")
        vsock = state["vsock"]
        require(vsock["paused"] and vsock["parked"] & vsock["expected"] == vsock["expected"],
                "not all actual mux/reaper/timesync owners parked")
        require(vsock["expected"] & 4 == 0 or vsock["parked"] & 4, "actual host timesync owner did not park")
        require(all(device["lifecycle"]["stage"] == "Quiesced" and device["lifecycle"]["failure"] is None
                    for device in state["devices"]), "a real participant remained unsettled/faulted")
        devices = {device["id"]: device for device in state["devices"]}
        self.source_devices = devices
        validate_reclaim_status(state["balloon"]["reclaim"], "boot")
        for name in ("disk0", "disk1", "net0", "vsock0", "balloon0", "rng0", "hvc0"):
            require(name in devices and devices[name].get("queues"), f"missing actual retained queues for {name}")
        require(len(devices["vsock0"]["queues"]) == 3, "EVQ was lost at source closure")
        require(any(queue["next_used"] > 0 for queue in devices["rng0"]["queues"]), "no actual RNG DMA/used completion")
        require(len(devices["balloon0"]["queues"]) == 5 and devices["balloon0"]["queues"][4]["next_used"] > 0,
                "allocation churn did not produce actual balloon reporting completions")
        serials = {(member["address"], member["irq"]) for member in state["legacy"] if member["kind"] == "Serial"}
        # This virtio-console profile has no configured COM1; COM2-4 are real sinks.
        require(serials == {(0x2f8, 3), (0x3e8, 4), (0x2e8, 3)},
                "actual implicit sink UART or independent legacy producer missing")
        require(any(member["kind"] == "Cmos" and member["address"] == 0x70 for member in state["legacy"])
                and any(member["kind"] == "I8042" and member["address"] == 0x60 for member in state["legacy"])
                and state["retained_native_controller"] is not None,
                "actual CMOS/i8042/native controller state missing")
        drained_output = self.session.drain_paused_output()
        output = self.console_records(self.session)
        require(bool(output.records), "no actual numbered output before cut")
        directory = self.root / "source-cut"
        self.session.command(f"capture {directory}")
        for sequence in range(16):
            packet = PACKET.pack(MAGIC, network_configuration["token"], (1 << 63) + sequence,
                                 0, 0, ECHO)
            require(self.udp.sendto(packet, peer) == len(packet), "actual netd source ingress send failed")
        self.session.pump(.2)
        self.session.command("resume")
        resume_native, resume_path = self.native("source-resume-controller-baseline")
        continued = self.progress(before)
        retained = self.guest("PROBE {token}")
        require(retained["retained_probes"] > 0 and retained["reset_observed"] == 0,
                "source pause reset/lost an actual retained mux session")
        disk_after = self.guest()
        for _ in range(100):
            if disk_after["injected_rx"] == 16:
                break
            self.pump(.02)
            disk_after = self.guest()
        require(disk_after["injected_rx"] == 16 and disk_after["injected_last"] == (1 << 63) + 15
                and disk_after["injected_faults"] == 0,
                "source lost/duplicated/reordered real netd ingress buffered while paused")
        require(all(disk_after[name] > disk_before[name] for name in ("disk0", "disk1", "disk_checks")),
                "source did not continue actual verified disk work")
        progressed_native, progressed_path = self.native("source-resume-controller-after-progress")
        require(progressed_native["controller"]["writes"] == resume_native["controller"]["writes"]
                and len(progressed_native["controller"]["writes"]) == 5,
                "source controller rewritten after resume and actual continued work")
        require(progressed_native["vsock"]["worker_threads"] == vsock["worker_threads"],
                "source resume replaced actual retained mux/reaper/timesync handles")
        self.attach(("no_post_release_controller_rewrite",), resume_path, progressed_path)
        source_output = self.console_records(self.session)
        require(source_output.data.startswith(output.data), "continued source changed pre-cut console bytes")
        continued_output = output.continued(source_output.data[len(output.data):])
        require(bool(continued_output.records), "source did not complete numbered console output after cut")
        records = save(self.root / "source-resume.json", {"before": before, "after": continued,
                       "disk_before": disk_before, "disk_after": disk_after,
                       "console_last_at_cut": output.records[-1], "console_cut_bytes": len(output.data),
                       "console_cut_records": list(output.records), "console_cut_trailing_hex": output.trailing.hex(),
                       "console_paused_drain_bytes": drained_output,
                       "console_continued_first": continued_output.records[0],
                       "console_continued_last": continued_output.records[-1],
                       "console_continued_bytes": len(source_output.data) - len(output.data),
                       "console_continued_trailing_hex": continued_output.trailing.hex()})
        self.attach(("busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy"), state_path, records)
        return directory, state, before, output

    def request_ownership(self, mode: str) -> None:
        baseline = self.session.samples[-1].copy()
        self.session.command(f"pressure request {mode} disk0")
        observed = None
        path = None
        try:
            for attempt in range(100):
                observed, path = self.native(f"request-{mode}-{attempt}")
                block = next(item for item in observed["block"] if item["id"] == "disk0")
                if (block["owned_head"] is not None if mode == "owned"
                        else block["available_unpopped"] > 0 and block["consumed_kicks"] > 0):
                    break
                self.pump(.01)
            else:
                raise RuntimeError(f"did not observe an actual {mode} request at the scheduling boundary")
            reply = self.session.command("pause", error=True)
            failed, failed_path = self.native(f"request-{mode}-incomplete-pause")
            require("Pausing" in failed["controller"]["state"], "owned work did not retain incomplete pause")
            operation = re.search(r"operation: OperationId\((\d+)\)", failed["controller"]["state"])
            require(operation is not None, "actual failed pause operation missing")
        finally:
            self.session.command("pressure request release disk0")
        self.session.command(f"cancel {operation.group(1)}")
        after = self.progress(baseline)
        record = save(self.root / f"request-{mode}-reconciled.json",
                      {"native_error": reply, "before": baseline, "after": after,
                       "operation": int(operation.group(1)), "ownership": observed["block"]})
        self.attach(("busy_block",), path, failed_path, record)

    def wake_failure(self) -> None:
        self.session.command("pressure wake disk0")
        reply = self.session.command("pause", error=True)
        state, path = self.native("accepted-wake-failure")
        disk = next(item for item in state["block"] if item["id"] == "disk0")
        lifecycle = next(item["lifecycle"] for item in state["devices"] if item["id"] == "disk0")
        require(disk["subscribed_wake_held"] is True and disk["wake_errno"] == errno.EAGAIN,
                "not an actual saturated original subscribed eventfd write failure")
        require(disk["worker_handle_retained"] is True and disk["worker_finished"] is False,
                "accepted failure lost its actual worker owner")
        require(lifecycle["accepted"] is True and lifecycle["failure"] is not None,
                "accepted failed wake disappeared from actual journal")
        require("Paused" not in state["controller"]["state"], "incomplete wake failure issued a token")
        self.session.command("pressure wake-restore disk0")
        process = self.session.process
        self.session.stop()
        require(process.returncode == 0 and self.session.native_reaped is True,
                "accepted failed wake did not complete actual native owner stop/reap")
        record = save(self.root / "accepted-wake-cleanup.json", {"native_error": reply, "pid": state["pid"],
                      "exit_status": process.returncode, "native_stop_acknowledged": self.session.native_reaped,
                      "cleanup": "actual Driver.stop owner reconciliation and process wait"})
        self.attach(("busy_block",), path, record)

    def interrupt_observation(self, label: str, irq: int) -> tuple[int, Path]:
        self.session.observations.pop("interrupts", None)
        os.write(self.session.console, b"O\n")
        self.until(lambda: "interrupts" in self.session.observations, "actual guest shared-GSI interrupt counters")
        raw = self.session.observations["interrupts"]
        path = self.root / f"{label}.guest-interrupts.txt"
        path.write_bytes(raw); path.chmod(0o600)
        matching = []
        for line in raw.decode("ascii").splitlines():
            if re.search(rf"\b{irq}-(?:edge|level|fasteoi)\b", line) and "IO-APIC" in line:
                fields = line.split(":", 1)[1].split()
                counters = []
                for field in fields:
                    if not field.isdecimal():
                        break
                    counters.append(int(field))
                require(bool(counters), "guest IRQ row has no CPU counters")
                matching.append(sum(counters))
        require(len(matching) == 1, "actual shared native GSI has no unique guest interrupt row")
        return matching[0], path

    def shared_irq(self, label: str) -> None:
        self.session.command("pressure irq hold disk0")
        try:
            self.pump(.2)
            before, before_path = self.native(f"{label}-irq-held")
            members = before["irq_members"]
            held = next(member for member in members if member["id"] == "disk0")
            require(held["held_acks"] > 0 and held["ack_hold"] and held["interrupt_status"] != 0,
                    "actual guest ACK was not retained with a pending cause")
            peers = [member for member in members if member["irq"] == held["irq"] and member["id"] != "disk0"]
            require(bool(peers), "no actual shared-line peer")
            delivered_before, guest_before_path = self.interrupt_observation(f"{label}-irq-before", held["irq"])
            self.pump(.2)
            after, after_path = self.native(f"{label}-irq-independent")
            indexed = {member["id"]: member for member in after["irq_members"]}
            require(indexed["disk0"]["interrupt_status"] != 0, "peer ACK cleared held member cause")
            require(any(indexed[peer["id"]]["ack_count"] > peer["ack_count"] for peer in peers),
                    "no actual independent peer ACK/completion")
            routes = [route for route in after["irq_routes"] if route["irq"] == held["irq"]]
            require(len(routes) == 1 and routes[0]["registered"] is True, "shared line not registered exactly once")
            require(type(routes[0]["ioapic_irr"]) is bool and type(routes[0]["ioapic_route"]) is int,
                    "missing actual native GET_IRQCHIP pending/route observation")
            delivered_after, guest_after_path = self.interrupt_observation(f"{label}-irq-after", held["irq"])
            require(delivered_after > delivered_before, "no actual guest shared-GSI delivery during retained pending cause")
            require(not any(member["overflow"] for member in after["irq_members"]), "bounded actual guest ACK retention overflowed")
            record = save(self.root / f"{label}-irq-pending-versus-delivered.json",
                          {"held_transport_pending": indexed["disk0"]["interrupt_status"],
                           "native_ioapic_irr": routes[0]["ioapic_irr"],
                           "native_route_word": routes[0]["ioapic_route"],
                           "guest_deliveries_before": delivered_before, "guest_deliveries_after": delivered_after,
                           "eventfd_signal_success_is_not_delivery": True})
            self.attach(("shared_irq",), before_path, after_path, guest_before_path, guest_after_path, record)
        finally:
            self.session.command("pressure irq release disk0")
        baseline = self.session.samples[-1].copy()
        self.progress(baseline)

    def destination(self, cut: Path, console_cut: ConsoleRecords) -> None:
        parent = self.session
        disks = []
        for index in range(2):
            disk = self.root / f"child-disk{index}.raw"
            shutil.copyfile(cut / f"disk{index}.raw", disk); disks.append(disk)
        child_args = copy.copy(self.args)
        child_args.pressure_socket = self.udp
        child = parent.__class__.create(child_args, self.root / "fresh-child", disks, self.echo, restore=cut)
        self.children.append(child); self.session = child
        try:
            self.destination_work(child, parent, console_cut)
        finally:
            self.children.remove(child); self.session = parent

    def destination_work(self, child: Session, parent: Session, console_cut: ConsoleRecords) -> None:
        with stopped_child(child, self.root):
            child.command("pressure evq hold")
            prepared, prepared_path = self.native("destination-prepared")
            require(prepared["vsock"]["pending_reset"] and prepared["vsock"]["reset_deliveries"] == 0,
                    "destination did not retain actual undelivered transport reset")
            validate_reclaim_status(prepared["balloon"]["reclaim"], "restored-private")
            require({device["id"] for device in prepared["devices"]} == set(self.source_devices),
                    "fresh destination attachment inventory differs from actual source")
            for device in prepared["devices"]:
                source = self.source_devices[device["id"]]
                require(all(device[field] == source[field] for field in
                            ("kind", "avail_features", "acked_features", "interrupt_status", "queues")),
                        f"dormant construction changed saved actual transport/queues for {device['id']}")
            child.pump(2)
            require(not child.samples and not child.pressure_samples, "guest executed before prepared release")
            child.command("release")
            os.write(child.console, b"M\n")
            self.pump(.5)
            starved, starved_path = self.native("destination-reset-starved")
            require(starved["vsock"]["pending_reset"] and starved["vsock"]["reset_deliveries"] == 0
                    and starved["vsock"]["event_queue_held"], "reset lost or delivered through held actual EVQ")
            child.command("pressure evq release")
            child.start_mux()
            delivered, delivered_path = self.native("destination-reset-delivered")
            require(not delivered["vsock"]["pending_reset"] and delivered["vsock"]["reset_deliveries"] == 1,
                    "retained EVQ buffer did not deliver exactly one actual reset")
            reset_guest = self.guest("RESET {token}")
            require(reset_guest["reset_observed"] == 1, "actual guest did not observe old connected stream reset")
            allowed, allowed_path = self.native("destination-control-only")
            denied = child.connect_mux(port=1028, partial=True)
            self.pump(.2)
            try:
                rejected = denied.recv(1) == b""
            except ConnectionResetError:
                rejected = True
            except BlockingIOError:
                rejected = False
            require(rejected, "noncontrol session admitted before activation")
            denied.close()
            packet_start = len(self.packets)
            fenced_configuration = self.guest("NET {token} {port} 1")
            neighbor = child.network_neighbor
            save(self.root / "destination-network-neighbor.json", neighbor)
            require(isinstance(neighbor, dict) and neighbor.get("interface") == "eth0"
                    and neighbor.get("destination") == 1
                    and neighbor.get("ip") == "192.168.127.254"
                    and neighbor.get("mac") == "5a:94:ef:e4:0c:dd"
                    and integer(neighbor.get("flags"), "neighbor flags") & 6 == 6,
                    "destination lacks actual complete permanent netd host neighbor")
            require(isinstance(child.pressure_ingress_peer, tuple), "fresh actual netd ingress mapping absent")
            ingress_sends = []
            for sequence in range(64):
                packet = PACKET.pack(MAGIC, fenced_configuration["token"], sequence, 1, 0, ECHO)
                require(self.udp.sendto(packet, child.pressure_ingress_peer) == len(packet), "actual fenced RX send failed")
                ingress_sends.append({"phase": 1, "sequence": sequence, "bytes": len(packet),
                                      "peer": list(child.pressure_ingress_peer)})
            self.pump(.5)
            require(not any(tuple(packet["peer"]) == child.pressure_ingress_peer
                            for packet in self.packets[packet_start:]),
                    "guest TX crossed actual managed-netd activation fence")
            fenced_guest = self.guest()
            require(fenced_guest["net_rx"][1] == 0, "fenced RX delivered actual tagged traffic")
            open_configuration = self.guest("NET {token} {port} 2")
            save(self.root / "network-phase-acknowledgements.json",
                 {"fenced_configuration": fenced_configuration, "fenced_guest": fenced_guest,
                  "open_configuration": open_configuration, "packet_start": packet_start,
                  "ingress_sends": ingress_sends})
            pre_activate, pre_path = self.native("destination-before-activation")
            child.command("activate")
            for sequence in range(16):
                packet = PACKET.pack(MAGIC, self.token, sequence, 2, 0, ECHO)
                require(self.udp.sendto(packet, child.pressure_ingress_peer) == len(packet), "actual open RX send failed")
                ingress_sends.append({"phase": 2, "sequence": sequence, "bytes": len(packet),
                                      "peer": list(child.pressure_ingress_peer)})
            self.until(lambda: any(packet["phase"] == 2 for packet in self.packets), "new tagged actual netd traffic")
            self.pump(.5)
            require(not any(packet["phase"] == 1 for packet in self.packets[packet_start:]),
                    "queued fence-era TX leaked after activation")
            post_guest = self.guest()
            require(all(post_guest[field] == self.source_guest[field]
                        for field in ("disk_capacity", "disk_readonly", "disk_serial_hex")),
                    "fresh native resource changed actual guest-visible disk identity/geometry")
            require(post_guest["net_rx"][1] == 0 and post_guest["net_rx"][2] > 0,
                    "fenced RX backlog replay or missing fresh bidirectional netd traffic")
            initial = child.samples[-1].copy()
            self.progress(initial)
            fresh = self.guest()
            require(fresh["injected_rx"] == 0 and fresh["injected_faults"] == 0,
                    "fresh destination replayed ephemeral source-host buffered ingress")
            reconnected = self.guest("CONNECT {token} 14567")
            require(reconnected["guest_connects"] > fresh["guest_connects"],
                    "fresh actual guest session failed to reconnect after reset/activation")
            output = self.console_records(child, console_cut)
            require(bool(output.records), "fresh restore did not complete numbered console output")
            self.shared_irq("destination")
            stable, stable_path = self.native("destination-controller-after-progress")
            require(len(stable["controller"]["writes"]) == 5
                    and all(type(value) is int and value >= 0 for value in stable["controller"]["writes"])
                    and stable["controller"]["writes"] == pre_activate["controller"]["writes"],
                    "native controller was rewritten after producers/CPUs released")
            require(stable["vsock"]["reset_deliveries"] == 1, "duplicate transport reset after activation/workload")
            network = save(self.root / "actual-netd-packets.json", {"packets": self.packets, "fenced_guest": fenced_guest,
                           "post_guest": post_guest, "ingress_sends": ingress_sends, "netd_pid": child.netd.pid,
                           "endpoint": str(Path(child.runtime.name) / "guest.sock")})
            record = save(self.root / "fresh-device-continuation.json", {"guest": fresh,
                          "console_first": output.records[0], "console_last": output.records[-1],
                          "console_cut_bytes": len(console_cut.data),
                          "console_cut_trailing_hex": console_cut.trailing.hex(),
                          "console_received_bytes": len(output.data) - len(console_cut.trailing),
                          "console_trailing_hex": output.trailing.hex(), "pid": child.process.pid,
                          "source_pid": parent.process.pid, "control_admitted_before_denial": allowed["vsock"]["admitted"]})
            self.attach(("busy_net",), network, pre_path, stable_path, child.directory / "netd-ingress-resource.json")
            self.attach(("busy_vsock",), prepared_path, starved_path, delivered_path, allowed_path, stable_path)
            self.attach(("busy_vsock",), save(self.root / "guest-reset-and-reconnect.json",
                        {"reset": reset_guest, "reconnected": reconnected}))
            self.attach(("busy_block", "busy_console", "balloon_rng_legacy"), record, stable_path)
            self.attach(("no_post_release_controller_rewrite",), pre_path, stable_path)
            child.profile()
            continued_before_capture = child.samples[-1].copy()
            child.command("pause")
            recaptured, recaptured_path = self.native("destination-device-recapture")
            recaptured_devices = {device["id"]: device for device in recaptured["devices"]}
            for name in ("disk0", "disk1", "rng0", "balloon0", "net0", "vsock0", "hvc0"):
                require(any((new["next_used"] - old["next_used"]) & 0xffff
                            for old, new in zip(self.source_devices[name]["queues"], recaptured_devices[name]["queues"])),
                        f"fresh destination did not publish actual new used entries for {name}")
            validate_reclaim_status(recaptured["balloon"]["reclaim"], "restored-private")
            recapture_directory = self.root / "fresh-child-recapture"
            self.session.command(f"capture {recapture_directory}")
            self.attach(("busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy"),
                        recaptured_path, recapture_directory / "devices.state", recapture_directory / "execution.state")
            child.command("resume")
            self.progress(continued_before_capture)
            self.wake_failure()

    def close(self) -> None:
        for child in self.children:
            child.close()
        for stream in self.accepted:
            stream.close()
        for descriptor in self.control_fds:
            os.close(descriptor)
        self.udp.close()


def run(args, session: Session, echo: socket.socket, cut: Path) -> dict[str, list[Path]]:
    pressure = Pressure(args, session, echo)
    try:
        require(cut.is_dir(), "caller did not supply an actual completed immutable source cut")
        blocked_console = save(pressure.root / "blocked-console-cancel.json",
                               session.blocked_console_cancel())
        pressure.attach(("busy_console",), blocked_console)
        pressure.request_ownership("owned")
        pressure.request_ownership("unpopped")
        pressure.partial_control_pause()
        pressure.mux_pressure()
        pressure.shared_irq("source")
        source_cut, _, _, console_cut = pressure.paused_cut()
        session.command("pause")
        try:
            pressure.pump(.2)
            pressure.destination(source_cut, console_cut)
        finally:
            session.command("resume")
        for name, paths in pressure.artifacts.items():
            require(1 <= len(paths) <= 64 and all(path.is_file() and 0 < path.stat().st_size <= 16 * 1024 * 1024 for path in paths),
                    f"missing bounded real observations for {name}")
        return pressure.artifacts
    except BaseException as error:
        save(pressure.root / "failure.json", {"error": str(error), "type": type(error).__name__,
             "packets": pressure.packets, "control_requests": pressure.control_requests,
             "destination_cleanup": str(pressure.root / "destination-cleanup.json")
             if (pressure.root / "destination-cleanup.json").is_file() else None})
        raise
    finally:
        pressure.close()
