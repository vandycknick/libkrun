"""Pure evidence-validation units. These never boot a guest or open KVM."""
import struct
import unittest

from native_generation_controller import fields, validate_ack, validate_capture, validate_pending


class GenerationEvidenceTests(unittest.TestCase):
    def test_duplicate_guest_fields_are_not_coherent_evidence(self):
        with self.assertRaises(ValueError):
            fields(b"request_sequence=1 request_sequence=2\n")
        with self.assertRaises(ValueError):
            fields(b"")

    def test_pending_requires_exact_original_deadline_and_raw_rejection(self):
        original = {"sequence": 2, "id": list(range(16)), "flags": 1, "deadline": "immutable", "config_generation": 2}
        prior = {"sequence": 1, "id": [17] * 16}
        native = {**original, "outcome": "pending", "committed_sequence": 1,
                  "processed_sequence": 3, "processed_id": original["id"].copy()}
        validate_pending(native, original, 1, prior)
        with self.assertRaises(ValueError):
            validate_pending({**native, "deadline": "renewed"}, original, 1, prior)
        with self.assertRaises(ValueError):
            validate_pending({**native, "outcome": "acknowledged"}, original, 1, prior)
        wrong = original["id"].copy()
        wrong[0] ^= 1
        validate_pending({**native, "processed_sequence": 2, "processed_id": wrong}, original, 2, prior)
        with self.assertRaises(ValueError):
            validate_pending({**native, "processed_sequence": 2}, original, 2, prior)
        validate_pending({**native, "processed_sequence": 1, "processed_id": prior["id"]}, original, 3, prior)

    def test_receipt_requires_real_driver_reseed_clock_and_low_write_order(self):
        native = {"sequence": 7, "id": list(range(16)), "flags": 1, "outcome": "acknowledged",
                  "timely": True, "committed_sequence": 7, "processed_sequence": 7,
                  "processed_id": list(range(16)), "driver_status": 13}
        identity = bytes(native["id"]).hex()
        guest = {"request_id": identity, "completed_id": identity, "ack_id": identity,
                 "request_sequence": "7", "completed_sequence": "7", "ack_sequence": "7",
                 "request_flags": "1", "error": "0", "ack_accessor_returned": "1",
                 "clock_complete_order": "3", "ack_write_order": "4", "ack_return_order": "5",
                 "reseed_count": "1", "rng_ready_before_call": "1", "reseed_return_order": "2"}
        validate_ack(native, guest, 0, clock=False)
        for key, value in (("reseed_return_order", "4"), ("rng_ready_before_call", "0"),
                           ("clock_complete_order", "5"), ("ack_accessor_returned", "0")):
            with self.assertRaises(ValueError):
                validate_ack(native, {**guest, key: value}, 0, clock=False)
        with self.assertRaises(ValueError):
            validate_ack({**native, "timely": False}, guest, 0, clock=False)
        with self.assertRaises(ValueError):
            validate_ack(native, guest, 0, clock=True)

    @staticmethod
    def capture_case():
        prior = {"sequence": 0x0102030411223342, "id": [37] * 16, "flags": 1}
        native = {
            "sequence": prior["sequence"] + 1, "id": list(range(16)), "flags": 1,
            "deadline": "original-absolute-deadline", "config_generation": 0xffffffff,
            "outcome": "pending", "committed_sequence": prior["sequence"],
            "processed_sequence": 0xfedcba9876543210, "processed_id": [19] * 16,
            "driver_status": 13, "clock_latch": 0x18273645ffeeddcc,
        }
        prefix = struct.pack("<HIQQ", 1, 0x5347, 1 << 32, 1 << 32)
        config = (struct.pack("<IIQ", 1, native["driver_status"], native["sequence"])
                  + bytes(native["id"])
                  + struct.pack("<Q", native["processed_sequence"]) + bytes(native["processed_id"])
                  + struct.pack("<IQ", native["flags"], native["clock_latch"]))
        receipt = b"\x01" + struct.pack("<Q", prior["sequence"]) + bytes(prior["id"]) + struct.pack("<I", prior["flags"])
        payload = prefix + config + receipt + b"\x01"
        transport = {
            "bytes": len(payload), "config_generation": native["config_generation"],
            "interrupt_status": 0, "avail_features": 1 << 32, "acked_features": 1 << 32,
            "before_config_generation": native["config_generation"], "before_interrupt_status": 0,
            "after_config_generation": native["config_generation"], "after_interrupt_status": 0,
        }
        return native, prior, payload, transport

    @staticmethod
    def metadata(transport):
        return " ".join(f"{key}={value}" for key, value in transport.items()).encode("ascii")

    def test_pending_capture_reports_actual_serialized_tuple_raw_receipt_and_latch(self):
        native, prior, payload, transport = self.capture_case()
        evidence = validate_capture(payload, self.metadata(transport), native, native.copy(), prior)
        self.assertEqual(evidence["payload_bytes"], 120)
        self.assertEqual(evidence["serialized"]["sequence"], native["sequence"])
        self.assertEqual(evidence["serialized"]["processed_sequence"], native["processed_sequence"])
        self.assertEqual(evidence["serialized"]["processed_id"], native["processed_id"])
        self.assertEqual(evidence["serialized"]["committed_id"], prior["id"])
        self.assertEqual(evidence["serialized"]["committed_flags"], prior["flags"])
        self.assertEqual(evidence["serialized"]["clock_latch"], native["clock_latch"])
        self.assertEqual(evidence["serialized"]["history"], 1)
        self.assertEqual(evidence["transport"], transport)
        # Partial raw ID/high staging is valid captured evidence, not a receipt.
        for words in range(5):
            with self.subTest(staged_id_words=words):
                raw = bytes(native["id"][:words * 4] + prior["id"][words * 4:])
                partial = {**native, "processed_id": list(raw)}
                changed = payload[:62] + raw + payload[78:]
                validate_capture(changed, self.metadata(transport), partial, partial.copy(), prior)
        asserted = {key: 2 if "interrupt_status" in key else value for key, value in transport.items()}
        validate_capture(payload, self.metadata(asserted), native, native.copy(), prior)

    def test_capture_rejects_every_altered_byte_even_when_codec_shape_stays_valid(self):
        native, prior, payload, transport = self.capture_case()
        for index in range(len(payload)):
            with self.subTest(offset=index):
                altered = bytearray(payload)
                altered[index] ^= 1
                with self.assertRaises(ValueError):
                    validate_capture(bytes(altered), self.metadata(transport), native, native.copy(), prior)

    def test_capture_rejects_missing_truncated_and_trailing_payloads(self):
        native, prior, payload, transport = self.capture_case()
        for length in range(len(payload)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                validate_capture(payload[:length], self.metadata(transport), native, native.copy(), prior)
        for suffix in (b"\x00", bytes(137)):
            with self.subTest(extra=len(suffix)), self.assertRaises(ValueError):
                validate_capture(payload + suffix, self.metadata(transport), native, native.copy(), prior)
        without_receipt = payload[:90] + b"\x00\x01"
        with self.assertRaises(ValueError):
            validate_capture(without_receipt, self.metadata(transport), native, native.copy(), prior)

    def test_capture_requires_exact_transport_metadata_and_before_after_state(self):
        native, prior, payload, transport = self.capture_case()
        for key in transport:
            with self.subTest(changed=key), self.assertRaises(ValueError):
                validate_capture(payload, self.metadata({**transport, key: transport[key] ^ 1}), native, native.copy(), prior)
            missing = {name: value for name, value in transport.items() if name != key}
            with self.subTest(missing=key), self.assertRaises(ValueError):
                validate_capture(payload, self.metadata(missing), native, native.copy(), prior)
        for metadata in (b"", b"bytes=120 bytes=120", b"bytes=invalid"):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                validate_capture(payload, metadata, native, native.copy(), prior)
        for key, value in (("deadline", "renewed"), ("outcome", "deadline"),
                           ("config_generation", 0), ("clock_latch", 0),
                           ("processed_sequence", native["sequence"])):
            with self.subTest(after=key), self.assertRaises(ValueError):
                validate_capture(payload, self.metadata(transport), native, {**native, key: value}, prior)
        for key, value in (("sequence", prior["sequence"] - 1), ("id", [55] * 16), ("flags", 0)):
            with self.subTest(prior=key), self.assertRaises(ValueError):
                validate_capture(payload, self.metadata(transport), native, native.copy(), {**prior, key: value})


if __name__ == "__main__":
    unittest.main()
