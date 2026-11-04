#!/usr/bin/env python3
"""Run ordinary Linux, real netd and all six native providers in fresh processes.

This is explicit standalone gate machinery, not a Cargo test, public RAM API,
qualification record, or capability grant. Execution-completeness uses the same
real production controller and ordinary kernel with bounded reserved guest code.
"""
import argparse
import array
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import tty

WAIT = 30
COUNTERS = ("disk0", "disk1", "rng", "report", "console_tx", "console_rx", "net_tx", "net_rx", "vsock")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def cpio(path, files):
    # Linux's existing newc format, used only to boot the explicit source fixture.
    with path.open("xb") as output:
        for inode, (name, content, mode) in enumerate(files + [("TRAILER!!!", b"", 0)], 1):
            encoded = name.encode() + b"\0"
            fields = (inode, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(encoded), 0)
            header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
            output.write(header + encoded)
            output.write(b"\0" * (-(len(header) + len(encoded)) % 4))
            output.write(content)
            output.write(b"\0" * (-len(content) % 4))
        output.flush()
        os.fsync(output.fileno())

def prime_netd(endpoint, host, mac, directory):
    """Set up a real new netd UDP ingress route before native FD handoff.

    These caller-generated packets are resource setup, never guest progress.
    """
    source_mac = bytes.fromhex(mac.replace(":", ""))
    gateway_mac = bytes.fromhex("5a94efe40cdd")
    source_ip, target_ip = socket.inet_aton("192.168.127.2"), socket.inet_aton("192.168.127.254")
    arp = (gateway_mac + source_mac + b"\x08\x06"
           + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + source_mac + source_ip
           + bytes(6) + socket.inet_aton("192.168.127.1"))
    payload = b"SILO-CALLER-NETD-PRIME:" + os.urandom(24)
    udp = struct.pack("!HHHH", 34567, host.getsockname()[1], 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, source_ip, target_ip)
    checksum = sum(struct.unpack("!10H", header))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    header = header[:10] + struct.pack("!H", (~checksum) & 65535) + header[12:]
    frame = gateway_mac + source_mac + b"\x08\x00" + header + udp
    endpoint.send(arp); endpoint.send(frame)
    deadline = time.monotonic() + WAIT
    deferred = []
    while time.monotonic() < deadline:
        ready, _, _ = select.select([host], [], [], .01)
        if not ready:
            continue
        observed, peer = host.recvfrom(65536)
        if observed == payload:
            save(directory / "netd-ingress-resource.json", {
                "origin": "caller-generated-resource-setup-not-guest-progress",
                "actual_netd_peer": list(peer), "guest_udp_port": 34567,
                "arp_sha256": hashlib.sha256(arp).hexdigest(),
                "udp_frame_sha256": hashlib.sha256(frame).hexdigest(),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            })
            return peer, deferred
        deferred.append((observed, peer))
        if len(deferred) > 128:
            raise RuntimeError("unbounded unrelated packets during netd resource setup")
    raise RuntimeError("actual new netd did not establish caller-managed ingress route")


class Session:
    @classmethod
    def create(cls, *args, **kwargs):
        session = cls.__new__(cls)
        try:
            session.__init__(*args, **kwargs)
        except BaseException:
            session.close()
            raise
        return session

    def __init__(self, args, directory, disks, echo, restore=None, generic=False, partial=False):
        self.directory = directory
        directory.mkdir(mode=0o700)
        args.sessions.append(self)
        self.args = args
        self.native_reaped = False
        self.cleanup_failures = []
        self.partial = partial
        self.stopping = False
        self.prepared = restore is not None
        self.last_release = None
        self.releases = []
        self.profile_sequence = 0
        self.binding = directory / "binding"
        shutil.copytree(restore / "binding" if restore else args.binding, self.binding)
        for name in ("silo-producer", "profile", "topology", "ram-layout", "source-run", "capture"):
            (self.binding / name).chmod(0o600)
        self.log = (directory / "driver.log").open("wb")
        self.guest_log = (directory / "guest.log").open("wb")
        self.output_log = (directory / "console-output.log").open("wb")
        self.control_buffer = bytearray()
        self.guest_buffer = bytearray()
        self.replies = []
        self.samples = []
        self.device_counter_reply = None
        self.last_device_counter_observation = None
        self.registers = []
        self.clock_brackets = []
        self.pressure_samples = []
        self.network_neighbor = None
        self.observations = {}
        self.observation = None
        self.observation_bytes = bytearray()
        self.drain_output = True
        self.echo = echo
        self.mux_data = None
        self.mux_pending = bytearray()
        self.mux_transmit = bytearray()
        self.mux_input = bytearray()
        self.mux_ack = None
        self.mux_verified = 0
        self.mux_counter = 0
        self.mux_received = 0
        self.mux_eof = False
        self.mux_send_failure = None
        self.network_packets = 0
        self.network_echoed_packets = 0
        self.network_received_bytes = 0
        self.network_echoed_bytes = 0
        self.network_last_packet = None
        self.network_peers = set()
        self.last_send = 0
        self.process = None
        self.netd = None
        self.fds = []
        self.sockets = []
        master, slave = pty.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        self.console = master
        self.fds.extend([master, slave])
        input_host, input_guest = socket.socketpair()
        output_host, output_guest = socket.socketpair()
        output_guest.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        mux_host, mux_guest = socket.socketpair()
        self.input_host, self.output_host, self.mux = input_host, output_host, mux_host
        self.sockets.extend([input_host, input_guest, output_host, output_guest, mux_host, mux_guest])
        self.net = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sockets.append(self.net)
        self.runtime = tempfile.TemporaryDirectory(prefix="silo-provider-")
        endpoint = Path(self.runtime.name) / "netd.sock"
        local = Path(self.runtime.name) / "guest.sock"
        # Both socket names are trusted caller-owned resource inputs, never state bytes.
        self.net.bind(str(local))
        logfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.fds.append(logfd)
        runtimefd = os.open(self.runtime.name, os.O_RDONLY | os.O_DIRECTORY)
        self.fds.append(runtimefd)
        mac = "02:00:00:00:00:02" if restore else "02:00:00:00:00:01"
        netd_command = [str(args.netd), "--listen-vfkit", f"unixgram://{endpoint}", "--subnet", "192.168.127.0/24",
                        "--static-lease", f"192.168.127.2={mac}", "--log-dir-fd", str(logfd), "--runtime-dir-fd", str(runtimefd),
                        "--log-file", "netd.log", "--audit-log-file", "netd-audit.jsonl", "--vm-id", directory.name,
                        "--run-id", directory.name, "--network-id", directory.name]
        with (directory / "netd.stderr").open("wb") as error:
            self.netd = subprocess.Popen(netd_command, pass_fds=(logfd, runtimefd), stdout=subprocess.DEVNULL, stderr=error)
        deadline = time.monotonic() + WAIT
        while not endpoint.exists():
            if self.netd.poll() is not None or time.monotonic() >= deadline:
                self.close()
                raise RuntimeError("actual managed netd did not create its endpoint")
            time.sleep(.01)
        self.net.connect(str(endpoint))
        self.net.send(b"VFKT")
        self.pressure_ingress_peer = None
        self.pressure_deferred_packets = []
        if getattr(args, "pressure_socket", None) is not None:
            self.pressure_ingress_peer, self.pressure_deferred_packets = prime_netd(
                self.net, args.pressure_socket, mac, directory)
        command = [str(args.probe), "--disk0", str(disks[0]), "--disk1", str(disks[1]), "--kernel", str(args.kernel),
                   "--initramfs", str(args.initramfs), "--binding", str(self.binding), "--echo-port", str(echo.getsockname()[1]),
                   "--console-fd", str(slave), "--console-input-fd", str(input_guest.fileno()),
                   "--console-output-fd", str(output_guest.fileno()), "--net-fd", str(self.net.fileno()), "--mux-fd", str(mux_guest.fileno())]
        if restore:
            command += ["--restore", str(restore)]
        if args.execution_completeness:
            command += ["--witness", "1"]
        if partial:
            command += ["--partial-install", str(directory / "partial-install.json")]
        if generic:
            command += ["--net-profile", "generic"]
        save(directory / "command.json", command)
        inherited = (slave, input_guest.fileno(), output_guest.fileno(), self.net.fileno(), mux_guest.fileno())
        error = (directory / "driver.stderr").open("wb")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, pass_fds=inherited)
        error.close()
        save(directory / "process.json", {"native_pid": self.process.pid, "netd_pid": self.netd.pid,
             "restore": str(restore) if restore else None, "partial_install": partial,
             "command_sha256": digest(directory / "command.json")})
        # Drop every parent duplicate of a transferred destination resource.
        input_guest.close(); output_guest.close(); mux_guest.close(); self.net.close(); os.close(slave); self.fds.remove(slave)
        for endpoint_socket in (input_host, output_host, mux_host):
            endpoint_socket.setblocking(False)
        os.set_blocking(master, False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.until(lambda: any(line == ("PARTIAL_REAPED" if partial else "READY whole-machine-production") for line in self.replies), "native driver readiness")
        self.ready_monotonic_ns = time.monotonic_ns()
        if not partial:
            (self.binding / "source-run").write_bytes(os.urandom(16))

    def owns_udp_peer(self, peer):
        if not self.netd or self.netd.poll() is not None:
            return False
        descriptors = Path(f"/proc/{self.netd.pid}/fd")
        inodes = set()
        for descriptor in descriptors.iterdir():
            try:
                target = descriptor.readlink().as_posix()
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
        for family in ("udp", "udp6"):
            rows = Path(f"/proc/{self.netd.pid}/net/{family}").read_text().splitlines()[1:]
            for row in rows:
                fields = row.split()
                if len(fields) >= 10 and fields[9] in inodes and int(fields[1].split(":")[1], 16) == peer[1]:
                    return True
        return False

    @staticmethod
    def parse_mux_ack(buffer: bytearray, acknowledgement: str | None) -> str | None:
        """Consume one bounded ACK in place, retaining incomplete input or payload."""
        if acknowledgement is not None:
            return acknowledgement
        newline = buffer.find(b"\n", 0, 65)
        if newline < 0:
            if len(buffer) > 64:
                raise RuntimeError("oversized native vsock connect acknowledgement")
            return None
        line = bytes(buffer[:newline])
        fields = line.split(b" ")
        if (len(fields) != 2 or fields[0] != b"OK" or not fields[1].isdigit()
                or int(fields[1]) > 0xffffffff):
            raise RuntimeError("malformed native vsock connect acknowledgement")
        del buffer[:newline + 1]
        return line.decode("ascii")

    def mux_read(self, data):
        self.mux_received += len(data)
        self.mux_input.extend(data)
        self.mux_ack = self.parse_mux_ack(self.mux_input, self.mux_ack)
        if self.mux_ack is None:
            return
        if self.mux_input:
            count = len(self.mux_input)
            if not self.mux_pending.startswith(self.mux_input):
                save(self.directory / "vsock-payload-mismatch.json",
                     {"native_ack": self.mux_ack, "received_bytes": self.mux_received,
                      "verified_guest_echo_bytes": self.mux_verified,
                      "expected": self.mux_pending[:count].hex(),
                      "received": self.mux_input.hex()})
                raise RuntimeError("actual guest vsock echo differs from accepted original bytes")
            self.mux_verified += count
            del self.mux_pending[:count]
            self.mux_input.clear()

    def record_network_state(self, event):
        value = {"event": event, "observed_monotonic_ns": time.monotonic_ns(),
                 "native_pid": self.process.pid if self.process else None,
                 "netd_pid": self.netd.pid if self.netd else None,
                 "netd_returncode": self.netd.poll() if self.netd else None,
                 "echo_address": list(self.echo.getsockname()),
                 "host_received_packets": self.network_packets,
                 "host_received_bytes": self.network_received_bytes,
                 "host_echo_send_accepted_packets": self.network_echoed_packets,
                 "host_echo_send_accepted_bytes": self.network_echoed_bytes,
                 "owned_peers": [list(peer) for peer in sorted(self.network_peers)],
                 "last_received_packet": self.network_last_packet,
                 "device_counter_baseline": self.last_device_counter_observation,
                 "guest": self.samples[-1] if self.samples else None}
        save(self.directory / f"network-echo-{value['observed_monotonic_ns']}.json", value)
        with (self.directory / "network-echo-transitions.jsonl").open("a") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")

    def pump(self, duration=.01, peers=True):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            fds = [self.process.stdout.fileno(), self.console, self.echo.fileno()]
            if self.drain_output:
                fds.append(self.output_host.fileno())
            if self.mux_data:
                fds.append(self.mux_data.fileno())
            ready, _, _ = select.select(fds, [], [], min(.01, max(0, deadline - time.monotonic())))
            for fd in ready:
                if fd == self.echo.fileno():
                    packet, peer = self.echo.recvfrom(65536)
                    owners = [session for session in self.args.sessions
                              if getattr(session, "process", None) is not None and peer in session.network_peers]
                    if not owners:
                        owners = [session for session in self.args.sessions
                                  if getattr(session, "netd", None) and session.owns_udp_peer(peer)]
                    if len(owners) != 1:
                        raise RuntimeError("UDP reply lacks one actual owned netd process")
                    owner = owners[0]
                    owner.network_peers.add(peer)
                    owner.network_packets += 1
                    owner.network_received_bytes += len(packet)
                    owner.network_last_packet = {"peer": list(peer), "bytes": len(packet),
                        "prefix_hex": packet[:64].hex(), "observed_monotonic_ns": time.monotonic_ns()}
                    accepted = self.echo.sendto(packet, peer)
                    if accepted != len(packet):
                        owner.record_network_state("echo-send-short")
                        raise RuntimeError("actual host UDP echo send was short")
                    owner.network_echoed_packets += 1
                    owner.network_echoed_bytes += accepted
                    continue
                try:
                    data = os.read(fd, 65536)
                except (BlockingIOError, OSError):
                    continue
                if fd == self.process.stdout.fileno():
                    self.log.write(data); self.log.flush()
                    self.control_buffer.extend(data)
                    while b"\n" in self.control_buffer:
                        line, _, self.control_buffer = self.control_buffer.partition(b"\n")
                        self.replies.append(line.decode(errors="strict"))
                elif fd == self.console:
                    self.guest_log.write(data); self.guest_log.flush()
                    self.guest_buffer.extend(data)
                    while b"\n" in self.guest_buffer:
                        line, _, self.guest_buffer = self.guest_buffer.partition(b"\n")
                        self.guest_line(line.rstrip(b"\r"))
                elif fd == self.output_host.fileno():
                    self.output_log.write(data); self.output_log.flush()
                elif self.mux_data and fd == self.mux_data.fileno():
                    self.mux_read(data)
                    if not data:
                        self.mux_eof = True
            if not self.stopping and not self.partial and time.monotonic() - self.last_send >= .02:
                try:
                    self.input_host.send(b"INPUT\n" * 64)
                except BlockingIOError:
                    pass
                if self.mux_data:
                    try:
                        if not self.mux_transmit and len(self.mux_pending) < 65536:
                            self.mux_transmit.extend(struct.pack("<QQ", 0x53494c4f, self.mux_counter))
                            self.mux_counter += 1
                        if self.mux_transmit:
                            written = self.mux_data.send(self.mux_transmit)
                            self.mux_pending.extend(self.mux_transmit[:written])
                            del self.mux_transmit[:written]
                            if written == 0:
                                self.mux_send_failure = "actual native stream send returned zero"
                    except BlockingIOError:
                        pass
                    except BrokenPipeError as error:
                        self.mux_send_failure = str(error)
                self.last_send = time.monotonic()
            if peers:
                for session in self.args.sessions:
                    if session is not self and getattr(session, "process", None) is not None and session.process.poll() is None:
                        session.pump(.001, peers=False)
            if self.process.poll() is not None:
                if self.partial and self.process.returncode == 0 and "PARTIAL_REAPED" in self.replies:
                    return
                if self.stopping and self.process.returncode == 0:
                    return
                raise RuntimeError(f"native process exited before stop: {self.process.returncode}")

    def drain_paused_output(self) -> int:
        """Drain the frozen source output endpoint to EAGAIN without pumping peers."""
        drained = 0
        while True:
            try:
                data = self.output_host.recv(65536)
            except BlockingIOError:
                self.output_log.flush()
                return drained
            if not data:
                raise RuntimeError("paused actual console output endpoint closed")
            self.output_log.write(data)
            drained += len(data)

    def guest_line(self, line):
        if line.startswith(b"FAIL "):
            raise RuntimeError(line.decode())
        if line.startswith(b"OBS-BEGIN "):
            self.observation = line.split(b" ", 1)[1].decode(); self.observation_bytes.clear(); return
        if line.startswith(b"OBS-END "):
            if line.split(b" ", 1)[1].decode() != self.observation:
                raise RuntimeError("mismatched ordinary guest observation")
            self.observations[self.observation] = bytes(self.observation_bytes)
            self.observation = None; return
        if line.startswith(b"{"):
            try:
                sample = json.loads(line)
            except json.JSONDecodeError:
                if self.observation:
                    self.observation_bytes.extend(line + b"\n")
                return
            if sample.get("fixture") == "production-linux-devices":
                if sample["failed"]:
                    raise RuntimeError("actual guest device workload fault")
                self.samples.append(sample)
                if sample.get("request_token"):
                    self.device_counter_reply = sample
            elif sample.get("fixture") == "production-linux-live-registers":
                if len(sample["cpus"]) != 2 or any(cpu["failed"] for cpu in sample["cpus"]):
                    raise RuntimeError("actual live GPR/SIMD/x87 workload fault")
                self.registers.append(sample)
            elif sample.get("fixture") == "production-linux-clock-bracket":
                self.clock_brackets.append(sample)
            elif sample.get("fixture") == "production-linux-pressure":
                if sample.get("failed"):
                    raise RuntimeError("actual guest device-pressure workload fault")
                self.pressure_samples.append(sample)
            elif sample.get("fixture") == "production-linux-neighbor":
                self.network_neighbor = sample
            elif self.observation:
                self.observation_bytes.extend(line + b"\n")
            return
        if self.observation:
            self.observation_bytes.extend(line + b"\n")

    def until(self, predicate, label, timeout=WAIT):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.record_network_state(f"timeout:{label}")
                raise RuntimeError(f"timeout observing {label}")
            self.pump()

    def command(self, command, error=False, timeout=WAIT):
        start = len(self.replies)
        name = command.split(" ", 1)[0]
        if name in ("pause", "resume", "release", "activate", "capture", "stop"):
            self.record_network_state(f"before:{name}")
        started = time.monotonic_ns()
        self.process.stdin.write((command + "\n").encode()); self.process.stdin.flush()
        self.until(lambda: any(line.startswith((f"OK {name}", f"ERROR {name}")) for line in self.replies[start:]), command, timeout=timeout)
        result = next(line for line in self.replies[start:] if line.startswith((f"OK {name}", f"ERROR {name}")))
        if result.startswith("ERROR") != error:
            raise RuntimeError(f"unexpected native command result: {result}")
        if not error and name in ("resume", "release"):
            finished = time.monotonic_ns()
            self.last_release = {"native_pid": self.process.pid, "command": name, "result": result,
                "started_ns": started, "finished_ns": finished, "duration_ns": finished - started,
                "prepared_dwell_ns": started - self.ready_monotonic_ns if self.prepared and name == "release" else None}
            self.releases.append(self.last_release)
            save(self.directory / f"release-{len(self.releases)}.json", self.last_release)
        if not error and name == "pause":
            (self.binding / "capture").write_bytes(os.urandom(16))
        if not error and name == "capture":
            shutil.copytree(self.binding, Path(command.split(" ", 1)[1]) / "binding")
        if name in ("pause", "resume", "release", "activate", "capture", "stop"):
            self.record_network_state(f"after:{result}")
        return result

    def connect_mux(self, port=1027, partial=False):
        local, remote = socket.socketpair()
        frame = f"CONNECT {port}\n".encode()
        rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [remote.fileno()]))]
        self.mux.sendmsg([frame[:4] if partial else frame], rights)
        if partial:
            self.pump(.01)
            self.mux.send(frame[4:])
        remote.close(); local.setblocking(False)
        self.sockets.append(local)
        return local

    def start_mux(self):
        self.until(lambda: self.samples and self.samples[-1].get("vsock_listeners") == 3,
                   "actual guest vsock listeners")
        self.mux_eof = False
        self.mux_send_failure = None
        save(self.directory / "vsock-connect.json",
             {"pid": self.process.pid, "guest": self.samples[-1],
              "port": 1027, "split_control_frame": True})
        self.mux_pending.clear()
        self.mux_transmit.clear()
        self.mux_input.clear()
        self.mux_ack = None
        self.mux_received = 0
        self.mux_verified = 0
        guest_vsock_before = self.samples[-1]["vsock"]
        def echoed():
            if self.mux_eof or self.mux_send_failure:
                raise RuntimeError("actual vsock stream closed before guest echo")
            return (self.mux_ack is not None and self.mux_verified > 0
                    and self.samples[-1]["vsock"] > guest_vsock_before)
        try:
            self.mux_data = self.connect_mux(partial=True)
            self.until(echoed, "actual vsock stream echo")
            save(self.directory / "vsock-echo.json",
                 {"pid": self.process.pid, "native_ack": self.mux_ack,
                  "received_bytes": self.mux_received,
                  "verified_guest_echo_bytes": self.mux_verified,
                  "guest": self.samples[-1]})
        except BaseException as error:
            diagnostic_error = None
            if self.args.execution_completeness:
                try:
                    self.command(f"pressure snapshot {self.directory / 'vsock-startup.native.json'}")
                except Exception as observed_error:
                    diagnostic_error = str(observed_error)
            save(self.directory / "vsock-startup-error.json",
                 {"error": str(error), "pid": self.process.pid,
                  "received_bytes": self.mux_received, "eof": self.mux_eof,
                  "native_ack": self.mux_ack, "verified_guest_echo_bytes": self.mux_verified,
                  "send_failure": self.mux_send_failure,
                  "native_snapshot_error": diagnostic_error,
                  "guest": self.samples[-1] if self.samples else None})
            raise

    def observe_device_counters(self, timeout=WAIT):
        token = os.urandom(16).hex()
        self.device_counter_reply = None
        proof = {"request_token": token, "native_pid": self.process.pid,
                 "requested_host_monotonic_ns": time.monotonic_ns(),
                 "reply_host_monotonic_ns": None, "sample": None}
        self.last_device_counter_observation = proof
        request = b"C" + token.encode("ascii") + b"\n"
        if os.write(self.console, request) != len(request):
            raise RuntimeError("actual guest counter request write was short")
        self.until(lambda: self.device_counter_reply is not None
                   and self.device_counter_reply.get("request_token") == token,
                   "nonce-correlated actual guest device counters", timeout=timeout)
        proof["reply_host_monotonic_ns"] = time.monotonic_ns()
        proof["sample"] = self.device_counter_reply.copy()
        return proof["sample"]

    def progress(self, previous=None):
        deadline = time.monotonic() + 60
        baseline = self.observe_device_counters(timeout=max(0, deadline - time.monotonic()))
        if previous is not None and any(baseline[key] < previous[key] for key in COUNTERS):
            raise RuntimeError("original guest device counters regressed")
        self.until(lambda: self.samples and self.registers
                   and all(self.samples[-1][key] > baseline[key] for key in COUNTERS),
                   "continued numbered work without renegotiation", timeout=max(0, deadline - time.monotonic()))
        return self.samples[-1].copy()

    @staticmethod
    def blocked_console_owner(snapshot):
        ports = [port for console in snapshot["consoles"] if console["id"] == "hvc0"
                 for port in console["ports"] if port["port_id"] == 2]
        if len(ports) != 1:
            raise RuntimeError("missing unique actual console output owner")
        port = ports[0]
        return (port if port["worker_handle_retained"] and not port["worker_finished"]
                and not port["admission_closed"] and port["blocked_head"] is not None
                and port["write_remaining"] > 0 else None)

    def prepare_blocked_console(self):
        started = time.monotonic_ns()
        deadline = time.monotonic() + WAIT
        proof = {"native_pid": self.process.pid, "started_monotonic_ns": started,
                 "finished_monotonic_ns": None, "deadline_seconds": WAIT,
                 "output_bytes_before": self.output_log.tell(),
                 "sample_before": self.samples[-1].copy(), "sample_after": None,
                 "native_snapshot": None, "observations": 0,
                 "owner": None, "ready": False}
        try:
            if os.write(self.console, b"B\n") != 2:
                raise RuntimeError("actual guest console burst request write was short")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("timeout observing actual blocked console writer")
                native_path = self.directory / f"blocked-console-readiness-{proof['observations']:04}.native.json"
                self.command(f"pressure snapshot {native_path}", timeout=remaining)
                proof["native_snapshot"] = str(native_path)
                proof["observations"] += 1
                snapshot = json.loads(native_path.read_text())
                proof["owner"] = self.blocked_console_owner(snapshot)
                if proof["owner"] is not None:
                    pending = self.output_host.recv(65536, socket.MSG_PEEK)
                    proof["undrained_peek_bytes"] = len(pending)
                    proof["undrained_peek_sha256"] = hashlib.sha256(pending).hexdigest()
                    if not pending or self.output_log.tell() != proof["output_bytes_before"]:
                        raise RuntimeError("console readiness closed or drained actual output")
                    proof["ready"] = True
                    return proof
                self.pump(min(.01, max(0, deadline - time.monotonic())))
        except BaseException as error:
            proof["error"] = str(error)
            raise
        finally:
            proof["finished_monotonic_ns"] = time.monotonic_ns()
            proof["sample_after"] = self.samples[-1].copy()
            save(self.directory / "blocked-console-readiness.json", proof)

    def blocked_console_cancel(self) -> dict:
        output_before = self.output_log.tell()
        try:
            self.drain_output = False
            preparation = self.prepare_blocked_console()
            before = self.samples[-1].copy()
            pause_started = time.monotonic_ns()
            response = self.command("pause", error=True)
            pause_finished = time.monotonic_ns()
            start = len(self.replies)
            self.command("status")
            status = self.replies[start:].copy()
            if (not response.startswith("ERROR pause ")
                    or len(response.encode()) > 65536
                    or len(status) > 128
                    or sum(len(line.encode()) + 1 for line in status) > 65536):
                raise RuntimeError("missing/oversized original blocked-console pause/status evidence")
            states = [line for line in status if line.startswith("CONTROL ")]
            if len(states) != 1 or not states[0].startswith("CONTROL Pausing "):
                raise RuntimeError("blocked real output did not retain current failed Pausing")
            key = re.search(
                r"key: (BarrierKey \{ operation: OperationId\((\d+)\), generation: BarrierGeneration\((\d+)\) \})",
                states[0])
            if key is None or "failed: true" not in states[0]:
                raise RuntimeError("missing actual failed-pause operation/generation identity")
            participants = [line for line in status if line.startswith("PARTICIPANT ")]
            consoles = [line for line in participants
                        if 'device_type: Virtio(3), configured_id: "hvc0",' in line]
            if len(consoles) != 1:
                raise RuntimeError("current status lacks one actual console participant")
            for participant in participants:
                stage = "Quiescing" if participant == consoles[0] else "Quiesced"
                if (f"quiesce_request: Some(BarrierRequest {{ key: {key.group(1)},"
                        not in participant
                        or f"quiesce_accepted: true, stage: {stage}, accepted: true,"
                        not in participant):
                    raise RuntimeError("console was not the retained incomplete owner of this pause")
            failure = re.search(
                r"failure: (None|Some\(LifecycleError \{ key: "
                + re.escape(key.group(1))
                + r", stage: Quiescing, accepted: true, fault: Deadline \}\)), previous_failure:",
                consoles[0])
            if failure is None:
                raise RuntimeError("blocked console retained a non-drain provider fault")
            try:
                pending = self.output_host.recv(65536, socket.MSG_PEEK)
            except BlockingIOError as error:
                raise RuntimeError("blocked console has no actual undrained output") from error
            output_blocked = self.output_log.tell()
            if not pending or output_blocked != output_before:
                raise RuntimeError("console output was closed or drained during backpressure")
        finally:
            self.drain_output = True
        self.pump(.2)
        output_drained = self.output_log.tell()
        if output_drained <= output_blocked:
            raise RuntimeError("restored draining did not consume actual blocked console bytes")
        cancellation = self.command(f"cancel {key.group(2)}")
        after = self.progress(before)
        return {"native_pid": self.process.pid, "pause_response": response,
                "preparation": preparation,
                "pause_started_monotonic_ns": pause_started,
                "pause_finished_monotonic_ns": pause_finished,
                "status": status, "operation": int(key.group(2)),
                "generation": int(key.group(3)), "console_participant": consoles[0],
                "undrained_peek_bytes": len(pending),
                "undrained_peek_hex": pending.hex(),
                "undrained_peek_sha256": hashlib.sha256(pending).hexdigest(),
                "output_bytes_before": output_before, "output_bytes_blocked": output_blocked,
                "output_bytes_after_drain": output_drained,
                "cancel_response": cancellation, "before": before, "after": after,
                "progress_observation": self.last_device_counter_observation}

    def profile(self):
        names = ("kernel-identity", "boot-identity", "clocksource", "clockevent0", "clockevent1", "broadcast-clockevent", "broadcast-clockevent-state", "speaker-consumers", "interrupts", "modules",
                 "rng-initial", "rng-current", "rng-available", "rng-selected", "rng-node", "rng-virtio-device")
        for name in names:
            self.observations.pop(name, None)
        os.write(self.console, b"O\n")
        self.until(lambda: all(name in self.observations for name in names), "same-boot ordinary Linux clock/PIT observations")
        self.profile_sequence += 1
        directory = self.directory / ("profile" if self.profile_sequence == 1 else f"profile-{self.profile_sequence}")
        directory.mkdir(mode=0o700)
        for name in names:
            (directory / name).write_bytes(self.observations[name])
        (directory / "clockevents").write_bytes(self.observations["clockevent0"].strip() + b"\n" + self.observations["clockevent1"].strip() + b"\n")
        modules = self.observations["modules"].strip()
        admission = {"path": "/proc/modules", "status": "present",
                     "config_modules": self.args.kernel_modules}
        if modules.startswith(b"{"):
            absence = json.loads(modules)
            if absence != {"path": "/proc/modules", "status": "absent", "errno": errno.ENOENT}:
                raise RuntimeError("malformed actual kernel module absence observation")
            if self.args.kernel_modules is not False:
                raise RuntimeError("absent /proc/modules requires the actual emitted CONFIG_MODULES=n kernel config")
            admission = {**absence, "config_modules": False,
                         "kernel_config": str(self.args.kernel_config),
                         "kernel_config_sha256": digest(self.args.kernel_config)}
        elif self.args.kernel_modules is False:
            raise RuntimeError("present /proc/modules contradicts the emitted CONFIG_MODULES=n kernel config")
        save(directory / "modules-admission.json", admission)
        if b"pcspkr" in self.observations["modules"]:
            raise RuntimeError("ordinary kernel has a speaker module consumer")
        self.command(f"profile {directory}")

    def blocked_console_stop(self):
        proof = {"native_pid": self.process.pid, "preparation": None,
                 "output_bytes_before": self.output_log.tell(),
                 "stop_started_monotonic_ns": None, "stop_finished_monotonic_ns": None,
                 "native_stop": None, "completed": False}
        self.drain_output = False
        try:
            proof["preparation"] = self.prepare_blocked_console()
            proof["stop_started_monotonic_ns"] = time.monotonic_ns()
            self.stop()
            proof["stop_finished_monotonic_ns"] = time.monotonic_ns()
            proof["native_stop"] = json.loads((self.directory / "native-stop.json").read_text())
            if not self.native_reaped or self.output_log.tell() != proof["output_bytes_before"]:
                raise RuntimeError("terminal blocked-console stop did not reap without draining")
            pending = self.output_host.recv(65536, socket.MSG_PEEK)
            if not pending:
                raise RuntimeError("terminal blocked-console stop lost unread output evidence")
            proof["undrained_peek_bytes_after_stop"] = len(pending)
            proof["undrained_peek_sha256_after_stop"] = hashlib.sha256(pending).hexdigest()
            proof["completed"] = True
            return proof
        except BaseException as error:
            proof["error"] = str(error)
            raise
        finally:
            proof["finished_monotonic_ns"] = time.monotonic_ns()
            proof["output_bytes_after"] = self.output_log.tell()
            proof["native_reaped"] = self.native_reaped
            save(self.directory / "blocked-console-stop.json", proof)

    def stop(self):
        if self.process is None:
            if self.native_reaped:
                return
            raise RuntimeError("stop has no retained native process")
        self.stopping = True
        self.process.stdin.write(b"stop\n"); self.process.stdin.flush()
        deadline = time.monotonic() + 10
        while self.process.poll() is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("native stop/reap deadline, actual owners not acknowledged")
            self.pump()
        result = self.process.wait(timeout=1)
        if result:
            raise RuntimeError(f"native stop/reap failed: {result}")
        save(self.directory / "native-stop.json", {"native_pid": self.process.pid, "exit_status": result,
             "explicit_stop_requested": True, "native_driver_stop_completed": True})
        self.process = None
        self.native_reaped = True

    def close(self):
        failures = []
        if getattr(self, "process", None):
            if self.process.poll() is None:
                failures.append("native driver required forced process reap, no native stop acknowledgement")
                self.process.kill()
            self.process.wait(timeout=10)
            self.process = None
        if getattr(self, "netd", None):
            if self.netd.poll() is None:
                self.netd.terminate()
            try:
                self.netd.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.netd.kill(); self.netd.wait(timeout=5)
                failures.append("netd required forced stop")
            self.netd = None
        for value in getattr(self, "sockets", []):
            value.close()
        self.sockets = []
        for fd in getattr(self, "fds", []):
            os.close(fd)
        self.fds = []
        for name in ("log", "guest_log", "output_log"):
            if hasattr(self, name):
                getattr(self, name).close()
        if hasattr(self, "runtime"):
            self.runtime.cleanup()
        self.cleanup_failures = getattr(self, "cleanup_failures", []) + failures
        return failures


def seal_cut(directory):
    manifest = {}
    names = ["execution.state", "devices.state", "memory.ram", "disk0.raw", "disk1.raw"]
    names.extend(f"binding/{name}" for name in ("silo-producer", "profile", "topology", "ram-layout", "source-run", "capture"))
    for name in names:
        path = directory / name
        manifest[name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        path.chmod(0o400)
        with path.open("rb") as source:
            os.fsync(source.fileno())
    save(directory / "manifest.json", manifest)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest


def source_and_children(args, echo):
    disks = []
    for index in range(2):
        path = args.evidence / f"source-disk{index}.raw"
        with path.open("xb") as output:
            output.truncate(128 * 1024 * 1024)
        with path.with_suffix(".mkfs.log").open("xb") as log:
            subprocess.run(["mkfs.ext4", "-F", "-q", str(path)], check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT)
        disks.append(path)
    source = Session.create(args, args.evidence / "source", disks, echo)
    records = []
    try:
        source.start_mux(); previous = source.progress(); source.profile()
        source.command("pause"); source.command("status"); source.command("state")
        cut = args.evidence / "source-cut"
        source.command(f"capture {cut}")
        sealed = seal_cut(cut)
        source.pump(2)
        os.kill(source.process.pid, signal.SIGWINCH)
        source.pump(.1)
        repeated = args.evidence / "source-cut-repeated"
        source.command(f"capture {repeated}")
        seal_cut(repeated)
        for name in ("memory.ram", "execution.state", "devices.state", "disk0.raw", "disk1.raw"):
            if digest(cut / name) != digest(repeated / name):
                raise RuntimeError(f"post-token mutation under real endpoint/resize stimulation: {name}")
        source.command("resume"); source.progress(previous)
        source.command("resume", error=True)
        blocked_console = source.blocked_console_cancel()
        source.stop()
        for name, observation in sealed.items():
            if digest(cut / name) != observation["sha256"]:
                raise RuntimeError(f"source continuation mutated sealed input {name}")
        records.append({"generation": 0, "cut": str(cut), "source_resume": True,
                        "reversible_blocked_output_cancel": blocked_console})
    finally:
        source.close()
    for generation in range(1, 4):
        children = []
        for index in range(2):
            path = args.evidence / f"generation{generation}-disk{index}.raw"
            shutil.copyfile(cut / f"disk{index}.raw", path)
            children.append(path)
        child = Session.create(args, args.evidence / f"generation{generation}", children, echo, restore=cut)
        try:
            child.command("status")
            child.pump(2)
            if child.samples or child.registers:
                raise RuntimeError("guest instruction/output before explicit prepared release")
            child.command("release")
            os.write(child.console, b"M\n")
            child.start_mux()
            child.pump(.5)
            # Already-captured guest socket buffers may be consumed after
            # release. The external oracle instead counts actual new outbound
            # datagrams arriving through the fresh managed netd reservation.
            before_packets = child.network_packets
            child.pump(.5)
            if child.network_packets != before_packets:
                raise RuntimeError("destination sent through netd before activation release")
            child.until(lambda: bool(child.samples), "restored ordinary workload")
            before = child.samples[-1].copy()
            child.command("activate")
            child.progress(before)
            child.profile()
            baseline = child.samples[-1].copy()
            child.command("pause"); child.command("state")
            next_cut = args.evidence / f"generation{generation}-cut"
            child.command(f"capture {next_cut}")
            seal_cut(next_cut)
            child.command("resume"); child.progress(baseline)
            child.stop()
            records.append({"generation": generation, "cut": str(next_cut), "fresh_process": True,
                            "prepared_dwell_seconds": 2, "continued": True})
            cut = next_cut
        finally:
            child.close()
    negative_disks = []
    for index in range(2):
        path = args.evidence / f"negative-disk{index}.raw"
        shutil.copyfile(cut / f"disk{index}.raw", path)
        negative_disks.append(path)
    negative = Session.create(args, args.evidence / "unsupported-generic-net", negative_disks, echo, generic=True)
    try:
        negative.start_mux()
        previous = negative.progress()
        negative.profile()
        negative.command("status")
        before = [line for line in negative.replies if line.startswith("CONTROL ")][-1]
        refusal = negative.command("pause", error=True)
        if "net0" not in refusal or "Unsupported" not in refusal:
            raise RuntimeError(f"unsupported backend refusal lost actual participant: {refusal}")
        negative.command("status")
        after = [line for line in negative.replies if line.startswith("CONTROL ")][-1]
        if before != after:
            raise RuntimeError("unsupported preflight submitted a CPU/lifecycle transition")
        continued = negative.progress(previous)
        save(negative.directory / "named-refusal.json",
             {"before": before, "refusal": refusal, "after": after, "progress": continued})
        terminal_stop = negative.blocked_console_stop()
        records.append({"unsupported_participant": "net0", "refusal": refusal,
                        "unchanged_native_control": True, "before": before, "after": after,
                        "progress": continued, "terminal_stop": terminal_stop,
                        "terminal_stop_evidence": str(negative.directory / "blocked-console-stop.json")})
    finally:
        negative.close()
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[3]
    parser.add_argument("--probe", type=Path, default=root / "target/debug/examples/native-device-probe")
    parser.add_argument("--netd", type=Path, default=os.environ.get("NETD_BIN") or shutil.which("silo-netd"))
    parser.add_argument("--guest-init", type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--register-fixture", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--execution-completeness", action="store_true")
    parser.add_argument("--busy-devices", action="store_true")
    parser.add_argument("--witness-dir", type=Path)
    parser.add_argument("--device-pressure", type=Path)
    args = parser.parse_args()
    if args.execution_completeness != args.busy_devices:
        parser.error("closed production extension requires both --execution-completeness and --busy-devices")
    if args.netd is None:
        parser.error("supply actual netd with NETD_BIN or --netd")
    args.guest_init = args.guest_init or args.register_fixture.parent / "native-device-linux"
    args.witness_dir = args.witness_dir or args.register_fixture.parent / "native-device-witness"
    args.device_pressure = args.device_pressure or args.register_fixture.parent / "native-device-pressure"
    args.sessions = []
    args.evidence = args.evidence.resolve()
    args.evidence.mkdir(mode=0o700)
    for name in ("probe", "netd", "guest_init", "kernel", "register_fixture"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.kernel_config_source = args.kernel.parent / ".config"
    args.kernel_config = None
    args.kernel_modules = None
    if args.kernel_config_source.exists():
        if not 0 < args.kernel_config_source.stat().st_size <= 1024 * 1024:
            raise RuntimeError("emitted kernel configuration is empty or oversized")
        config = args.kernel_config_source.read_bytes()
        module_lines = [line for line in config.decode("ascii").splitlines()
                        if line.startswith("CONFIG_MODULES=") or line == "# CONFIG_MODULES is not set"]
        if module_lines == ["CONFIG_MODULES=y"]:
            args.kernel_modules = True
        elif module_lines == ["# CONFIG_MODULES is not set"]:
            args.kernel_modules = False
        else:
            raise RuntimeError("emitted kernel configuration has no unambiguous CONFIG_MODULES setting")
        args.kernel_config = args.evidence / "kernel.config"
        args.kernel_config.write_bytes(config)
    args.initramfs = args.evidence / "initramfs.cpio"
    files = [("init", args.guest_init.read_bytes(), 0o100755),
             ("register-fixture", args.register_fixture.read_bytes(), 0o100755)]
    if args.execution_completeness:
        args.witness_dir = args.witness_dir.resolve(strict=True)
        args.device_pressure = args.device_pressure.resolve(strict=True)
        files.append(("device-pressure", args.device_pressure.read_bytes(), 0o100755))
    cpio(args.initramfs, files)
    args.binding = args.evidence / "binding"; args.binding.mkdir(mode=0o700)
    identity = {name: digest(getattr(args, name)) for name in ("probe", "netd", "guest_init", "kernel", "register_fixture")}
    identity["initramfs"] = digest(args.initramfs)
    if args.kernel_config is not None:
        identity["kernel_config"] = digest(args.kernel_config)
    if args.execution_completeness:
        identity.update(device_pressure=digest(args.device_pressure),
                        witness_code=digest(args.witness_dir / "witness.bin"),
                        witness_symbols=digest(args.witness_dir / "witness.nm"))
    material = json.dumps(identity, sort_keys=True).encode()
    for name in ("silo-producer", "profile", "topology", "ram-layout"):
        (args.binding / name).write_bytes(hashlib.sha256(name.encode() + material).digest())
    for name in ("source-run", "capture"):
        (args.binding / name).write_bytes(os.urandom(16))
    host_mode = {}
    for name in ("kvm_amd/avic", "kvm/pi_inject_timer", "kvm/lapic_timer_advance"):
        module, parameter = name.split("/")
        path = Path("/sys/module") / module / "parameters" / parameter
        host_mode[name] = path.read_text().strip() if path.exists() else None
    save(args.evidence / "inputs.json", {"command": os.sys.argv, "identities": identity,
         "paths": {name: str(getattr(args, name)) for name in ("probe", "netd", "guest_init", "kernel", "register_fixture", "device_pressure", "witness_dir")},
         "host": dict(zip(("system", "node", "release", "version", "machine"), os.uname())), "host_mode": host_mode,
         "kernel_config": {"source": str(args.kernel_config_source),
                           "retained": str(args.kernel_config) if args.kernel_config else None,
                           "config_modules": args.kernel_modules},
         "ram_transfer": "bounded-standalone-only", "native_pause": False, "pending_lanes": ["kvm-arm64", "hvf-arm64"]})
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0)); echo.setblocking(False)
    report = {"schema": 1, "scope": "whole-machine-production", "native_pause": False, "pid": os.getpid(),
              "qualification_granted": False, "qualification_eligible": False}
    try:
        if args.execution_completeness:
            from native_device_execution import run
            observations = run(args, Session, seal_cut, save, digest, echo)
            report["absolute_no_early_requirement"] = "not-gating"
            required = {"normal_kernel_profile", "native_pit_predicate", "source_resume", "three_fresh_generations",
                "original_due_no_irr", "original_pending", "pending_plus_future", "masked_unmask", "in_service_eoi",
                "offline_start", "halted_wake", "live_xstate", "io_mmio_exact_once", "long_prepared_dwell",
                "contemporary_clock_bracket", "partial_install_reaped", "unsupported_participant_named",
                "busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy", "shared_irq",
                "no_post_release_controller_rewrite", "absolute_timer_delivery"}
            if set(observations) != required:
                raise RuntimeError(f"closed whole-machine witnesses differ: {set(observations) ^ required}")
            root = args.evidence.resolve(strict=True)
            objects = {}
            report["witnesses"] = {}
            for name, paths in observations.items():
                if not 1 <= len(paths) <= 64:
                    raise RuntimeError("observation count bound")
                records = []
                for path in paths:
                    path = Path(path).resolve(strict=True)
                    size = path.stat().st_size
                    if not path.is_relative_to(root) or not path.is_file() or not 0 < size <= 16 * 1024 * 1024:
                        raise RuntimeError("observation regular-file/path/byte bound")
                    objects[path] = size
                    if sum(objects.values()) > 64 * 1024 * 1024:
                        raise RuntimeError("whole-machine observation budget")
                    records.append({"path": str(path.relative_to(root)), "bytes": size, "sha256": digest(path)})
                report["witnesses"][name] = {
                    "status": "observed-not-gating" if name == "absolute_timer_delivery" else "passed",
                    "observations": records}
        else:
            report["absolute_no_early_requirement"] = "not-measured"
            report["generations"] = source_and_children(args, echo)
        if not args.sessions or any(not session.native_reaped or session.cleanup_failures for session in args.sessions):
            raise RuntimeError("native owner stop/reap acknowledgement or resource cleanup missing")
        report["all_reaped"] = True
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        echo.close()
        save(args.evidence / "provider-report.json", report)
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
