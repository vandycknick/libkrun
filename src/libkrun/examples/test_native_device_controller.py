"""Bounded framing, readiness and real subprocess/socket pump regressions.

The subprocess cases exercise controller cleanup, not native-owner acknowledgement.
"""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from native_device_controller import Session


class MuxAcknowledgementTests(unittest.TestCase):
    @staticmethod
    def parse_chunks(chunks):
        buffered = bytearray()
        payload = bytearray()
        acknowledgement = None
        for chunk in chunks:
            buffered.extend(chunk)
            acknowledgement = Session.parse_mux_ack(buffered, acknowledgement)
            if acknowledgement is not None:
                payload.extend(buffered)
                buffered.clear()
        return acknowledgement, buffered, payload

    def test_every_fragment_boundary_and_bytewise_stream_preserve_payload(self):
        acknowledgement = b"OK 4294967295\n"
        payload = bytes(range(256)) + b"OK 17\n\x00\n"
        stream = acknowledgement + payload
        for split in range(len(stream) + 1):
            with self.subTest(split=split):
                ack, buffered, received = self.parse_chunks((stream[:split], stream[split:]))
                self.assertEqual(ack, "OK 4294967295")
                self.assertEqual(buffered, b"")
                self.assertEqual(received, payload)
        ack, buffered, received = self.parse_chunks(bytes([byte]) for byte in stream)
        self.assertEqual(ack, "OK 4294967295")
        self.assertEqual(buffered, b"")
        self.assertEqual(received, payload)

    def test_incomplete_ack_remains_buffered_until_newline(self):
        for prefix in (b"", b"O", b"OK", b"OK ", b"OK 1028"):
            with self.subTest(prefix=prefix):
                buffered = bytearray(prefix)
                self.assertIsNone(Session.parse_mux_ack(buffered, None))
                self.assertEqual(buffered, prefix)
        buffered = bytearray(b"OK 1028")
        buffered.extend(b"\npayload\n")
        self.assertEqual(Session.parse_mux_ack(buffered, None), "OK 1028")
        self.assertEqual(buffered, b"payload\n")

    def test_coalesced_payload_is_not_part_of_line_bound_or_reparsed(self):
        payload = b"OK invalid\n" + bytes(range(256)) * 4
        buffered = bytearray(b"OK 0\n" + payload)
        acknowledgement = Session.parse_mux_ack(buffered, None)
        self.assertEqual(acknowledgement, "OK 0")
        self.assertEqual(buffered, payload)
        self.assertEqual(Session.parse_mux_ack(buffered, acknowledgement), acknowledgement)
        self.assertEqual(buffered, payload)

    def test_maximum_line_can_be_fragmented_before_newline(self):
        line = b"OK " + b"0" * 60 + b"1"
        buffered = bytearray(line)
        self.assertIsNone(Session.parse_mux_ack(buffered, None))
        self.assertEqual(buffered, line)
        buffered.extend(b"\n\x00payload")
        self.assertEqual(Session.parse_mux_ack(buffered, None), line.decode("ascii"))
        self.assertEqual(buffered, b"\x00payload")

    def test_oversized_line_fails_with_or_without_newline(self):
        line = b"OK " + b"0" * 61 + b"1"
        for suffix in (b"", b"\n", b"\npayload"):
            with self.subTest(suffix=suffix):
                buffered = bytearray(line[:64])
                self.assertIsNone(Session.parse_mux_ack(buffered, None))
                buffered.extend(line[64:] + suffix)
                with self.assertRaises(RuntimeError):
                    Session.parse_mux_ack(buffered, None)
                self.assertEqual(buffered, line + suffix)

    def test_malformed_ack_and_out_of_range_port_fail_without_consuming(self):
        lines = (b"", b"OK", b"OK ", b"NO 1028", b"OK -1", b"OK +1",
                 b"OK 4294967296", b"OK 0004294967296", b"OK 1 extra",
                 b"OK  1", b"OK\t1", b"OK 1\r", b"OK \xff")
        for line in lines:
            with self.subTest(line=line):
                framed = line + b"\npayload"
                buffered = bytearray(framed)
                with self.assertRaises(RuntimeError):
                    Session.parse_mux_ack(buffered, None)
                self.assertEqual(buffered, framed)


class ConsoleOwnerReadinessTests(unittest.TestCase):
    @staticmethod
    def snapshot(**changes):
        port = {"port_id": 2, "worker_handle_retained": True,
                "worker_finished": False, "admission_closed": False,
                "blocked_head": 0, "bytes_written": 3, "write_remaining": 9}
        port.update(changes)
        return {"consoles": [{"id": "hvc0", "ports": [port]}]}

    def test_actual_blocked_head_zero_is_ready(self):
        snapshot = self.snapshot()
        self.assertIs(Session.blocked_console_owner(snapshot),
                      snapshot["consoles"][0]["ports"][0])

    def test_endpoint_bytes_or_guest_progress_cannot_replace_owner(self):
        for changes in ({"blocked_head": None}, {"write_remaining": 0},
                        {"worker_handle_retained": False}, {"worker_finished": True},
                        {"admission_closed": True}):
            with self.subTest(changes=changes):
                self.assertIsNone(Session.blocked_console_owner(self.snapshot(**changes)))

    def test_other_ports_cannot_satisfy_output_owner(self):
        for changes in ({"port_id": 0}, {"port_id": 1}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(RuntimeError, "unique actual console"):
                    Session.blocked_console_owner(self.snapshot(**changes))

    def test_missing_or_duplicate_console_owner_fails(self):
        snapshot = self.snapshot()
        for consoles in ([], snapshot["consoles"] * 2,
                         [{"id": "unrelated", "ports": snapshot["consoles"][0]["ports"]}]):
            with self.subTest(consoles=consoles):
                with self.assertRaisesRegex(RuntimeError, "unique actual console"):
                    Session.blocked_console_owner({"consoles": consoles})


class StopIsolationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-stop-unit-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.args = SimpleNamespace(sessions=[])

    def session(self, name, exit_status=0):
        session = Session.__new__(Session)
        session.directory = self.directory / name
        session.directory.mkdir()
        session.args = self.args
        session.native_reaped = False
        session.cleanup_failures = []
        session.stopping = False
        session.partial = False
        session.drain_output = True
        session.last_send = time.monotonic()
        session.mux_data = None
        session.netd = None
        session.process = None
        session.sockets = []
        session.fds = []
        self.addCleanup(session.close)
        for name in ("log", "guest_log", "output_log"):
            setattr(session, name, (session.directory / name).open("wb"))
        session.control_buffer = bytearray()
        session.guest_buffer = bytearray()
        session.replies = []
        console, guest = socket.socketpair()
        session.console = console.fileno()
        session.sockets.extend((console, guest))
        session.input_host, input_guest = socket.socketpair()
        session.output_host, output_guest = socket.socketpair()
        session.sockets.extend((session.input_host, input_guest, session.output_host, output_guest))
        session.echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        session.echo.bind(("127.0.0.1", 0))
        session.sockets.append(session.echo)
        session.network_peers = set()
        for endpoint in session.sockets:
            endpoint.setblocking(False)
        child = """
import os
from pathlib import Path
import sys

print("ready", flush=True)
Path(sys.argv[1]).write_bytes(sys.stdin.buffer.readline())
# Exceed pipe capacity so stop must pump real descriptors before this exits.
remaining = b"draining\\n" * 32768
while remaining:
    remaining = remaining[os.write(sys.stdout.fileno(), remaining):]
if sys.argv[2] == "stall":
    sys.stdin.buffer.read()
sys.exit(int(sys.argv[2]))
"""
        process = subprocess.Popen(
            [sys.executable, "-c", child, str(session.directory / "received-stop"), str(exit_status)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        session.process = process
        self.addCleanup(process.stdin.close)
        self.addCleanup(process.stdout.close)
        # Reap before closing the pipes, including if an assertion fails.
        self.addCleanup(session.close)
        ready, _, _ = select.select([process.stdout], [], [], 5)
        self.assertTrue(ready, "subprocess readiness deadline")
        self.assertEqual(process.stdout.readline(), b"ready\n")
        os.set_blocking(process.stdout.fileno(), False)
        self.args.sessions.append(session)
        return session, process, guest

    def test_peer_guest_failure_cannot_interrupt_another_owner_stop(self):
        primary, primary_process, primary_console = self.session("primary")
        sibling, sibling_process, _ = self.session("sibling")
        primary_console.sendall(b"FAIL memory-reclaim errno=2\n")

        sibling.stop()
        self.assertTrue(sibling.native_reaped)
        self.assertEqual(sibling_process.returncode, 0)
        self.assertEqual((sibling.directory / "received-stop").read_bytes(), b"stop\n")
        self.assertEqual((sibling.directory / "guest_log").read_bytes(), b"")
        self.assertIsNone(primary_process.poll())
        self.assertEqual(primary.guest_buffer, b"")

        with self.assertRaisesRegex(RuntimeError, "FAIL memory-reclaim errno=2"):
            primary.stop()
        self.assertTrue(primary.native_reaped)
        self.assertEqual(primary_process.returncode, 0)
        self.assertEqual((primary.directory / "received-stop").read_bytes(), b"stop\n")
        proof = json.loads((primary.directory / "native-stop.json").read_text())
        self.assertEqual(proof["pump_failures"], ["FAIL memory-reclaim errno=2"])
        self.assertTrue(proof["native_driver_stop_completed"])
        self.assertIn(b"FAIL memory-reclaim errno=2\n", (primary.directory / "guest_log").read_bytes())
        self.assertEqual(primary.close(), [])
        self.assertEqual(sibling.close(), [])

    def test_ordinary_pump_still_propagates_peer_guest_failure(self):
        primary, _, primary_console = self.session("primary")
        sibling, _, _ = self.session("sibling")
        primary_console.sendall(b"FAIL memory-reclaim errno=2\n")
        with self.assertRaisesRegex(RuntimeError, "FAIL memory-reclaim errno=2"):
            sibling.pump(.1)
        self.assertFalse(primary.stopping)
        self.assertFalse(sibling.stopping)
        primary.stop()
        sibling.stop()

    def test_nonzero_exit_cannot_become_acknowledged_stop(self):
        session, process, console = self.session("nonzero", exit_status=7)
        console.sendall(b"FAIL memory-reclaim errno=2\n")
        with self.assertRaises(RuntimeError) as raised:
            session.stop()
        self.assertEqual(str(raised.exception.__cause__), "FAIL memory-reclaim errno=2")
        self.assertFalse(session.native_reaped)
        self.assertEqual(process.returncode, 7)
        self.assertFalse((session.directory / "native-stop.json").exists())
        self.assertIn(b"FAIL memory-reclaim errno=2\n", (session.directory / "guest_log").read_bytes())

    def test_unacknowledged_stop_keeps_deadline_and_original_guest_failure(self):
        session, process, console = self.session("deadline", exit_status="stall")
        console.sendall(b"FAIL memory-reclaim errno=2\n")
        started = time.monotonic()
        with self.assertRaises(RuntimeError) as raised:
            session.stop()
        self.assertGreaterEqual(time.monotonic() - started, 10)
        self.assertEqual(str(raised.exception.__cause__), "FAIL memory-reclaim errno=2")
        self.assertIsNone(process.poll())
        self.assertFalse(session.native_reaped)
        self.assertFalse((session.directory / "native-stop.json").exists())
        self.assertEqual(session.close(), [
            "native driver required forced process reap, no native stop acknowledgement"])

    def test_forced_reap_remains_a_cleanup_failure(self):
        session, process, _ = self.session("forced")
        self.assertEqual(session.close(), [
            "native driver required forced process reap, no native stop acknowledgement"])
        self.assertIsNotNone(process.returncode)
        self.assertFalse(session.native_reaped)
        self.assertFalse((session.directory / "native-stop.json").exists())


if __name__ == "__main__":
    unittest.main()
