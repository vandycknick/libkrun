"""Pure bounded native-mux framing and console-owner readiness regressions."""
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


if __name__ == "__main__":
    unittest.main()
