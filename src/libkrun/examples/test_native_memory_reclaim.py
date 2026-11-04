"""Pure fail-closed gate oracles over real saved RAM files, never mocked VMs.

Main runs: python3 -m unittest discover -s src/libkrun/examples -p test_native_memory_reclaim.py
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from native_memory_reclaim import (
    A_BYTE, B_BYTE, LEDGER_SCOPE, PAGE, c_page, check_page,
    check_publication, compare_coverage, fnv64, require_reaped, unchanged_baseline,
    validate_backing, validate_guest, validate_report, validate_witness,
)
from native_ram_image import authenticate_image, layout_digest


class ReclaimOracleTests(unittest.TestCase):
    TOKEN = "0123456789abcdef" * 2

    @staticmethod
    def status(restored=True):
        return {"backing": "restored-private" if restored else "boot",
                "reason": "restored-private-mapping" if restored else "tracked-capture",
                "requested": False, "qualification": "not-run", "effective": False,
                "released_bytes": 0, "released_extents": 0, "retried_faults": 0,
                "skipped_reports": 1 if restored else 0, "failed_operations": 0}

    @staticmethod
    def identity():
        return {"head": 3, "next_avail": 65535, "next_used": 65535,
                "avail_idx": 0, "used_idx": 65535, "gpa": PAGE,
                "desc_table": 3 * PAGE, "avail_ring": 3 * PAGE + 256,
                "used_ring": 3 * PAGE + 512,
                "descriptors": [{"addr": PAGE, "len": PAGE, "flags": 2, "next": 0}]}

    @classmethod
    def boundary(cls, restored):
        return {"schema": 1, "native_pid": 100 if restored else 99,
                "state": "child-completed" if restored else "source-seeded",
                "report": cls.identity(), "seed": B_BYTE if restored else A_BYTE,
                "verified_bytes": PAGE, "used_after": 0 if restored else None,
                "barrier": {"operation": 4, "generation": 2 if restored else 1},
                "parked_cpus": 2, "failure": None, "reclaim": cls.status(restored),
                "remapper_present": False}

    @classmethod
    def guest(cls, operation="reuse", token=None):
        token = cls.TOKEN if token is None else token
        verified = operation in ("reuse", "verify")
        return {"schema": 1, "ownership": "kernel-order0-retained", "request_token": token,
                "operation": operation, "success": True, "target_gpa": PAGE,
                "gpa_before": 0 if operation == "prepare" else PAGE, "gpa_after": PAGE,
                "sysfs_attribute": "/sys/bus/virtio/devices/virtio4/silo_reclaim",
                "kernel": {"abi": 1, "state": "owned" if operation == "prepare" else
                           "inflight" if operation == "donate" else "c-ready",
                           "operation": operation, "token": token, "gpa": PAGE, "bytes": PAGE,
                           "submitted": 0 if operation == "prepare" else 1,
                           "used_seen": 1 if verified else 0, "verified_bytes": PAGE if verified else 0,
                           "mismatches": 0, "checksum": fnv64(c_page()) if verified else "0" * 16,
                           "error": 0}}

    @staticmethod
    def layout():
        return {"schema": 1, "kind": "ram-layout", "architecture": "x86_64", "pageGranule": PAGE,
                "packedLength": 4 * PAGE, "regions": [
                    {"guestPhysicalAddress": 0, "length": 4 * PAGE, "streamOffset": 0}],
                "topology": {key: 0 for key in ("firmwareAddress", "initrdAddress", "ramAboveGap",
                                               "ramBelowGap", "ramLastAddress", "shmStartAddress")}}

    def cut(self, root, name, data, bits=15):
        path = root / name
        path.mkdir()
        (path / "memory.ram").write_bytes(data)
        (path / "memory-layout.json").write_bytes(json.dumps(
            self.layout(), sort_keys=True, separators=(",", ":")).encode("ascii"))
        metadata = {"schema": 1, "scope": LEDGER_SCOPE, "bitmap_encoding": "u64-le-lsb0-dense",
                    "granule": PAGE, "packed_len": len(data), "page_count": len(data) // PAGE,
                    "dirty_pages": bits.bit_count(), "bitmap_bytes": 8, "pause_generation": 2,
                    "regions": [{"id": 0, "gpa": 0, "byte_len": len(data), "stream_offset": 0, "first_page": 0}]}
        (path / "memory-dirty.json").write_text(json.dumps(metadata))
        (path / "memory-dirty.bitmap").write_bytes(bits.to_bytes(8, "little"))
        return path

    def test_real_saved_used_entry_wraparound_and_dirty_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = bytearray(4 * PAGE)
            boundary = self.boundary(True)
            identity = boundary["report"]
            entry = identity["used_ring"] + 4 + 7 * 8
            data[entry:entry + 4] = identity["head"].to_bytes(4, "little")
            cut = self.cut(Path(temporary), "used", data)
            queue = {**identity, "ready": True, "size": 8, "next_avail": 0, "next_used": 0, "used_idx": 0}
            snapshot = {"transport": {"queues": [None] * 4 + [queue]}}
            actual = check_publication(cut, boundary, snapshot)
            self.assertEqual(actual["head"], 3)
            self.assertTrue(actual["used_index_and_element_dirty"])
            data[entry] = 4
            (cut / "memory.ram").write_bytes(data)
            with self.assertRaisesRegex(ValueError, "inherited report head"):
                check_publication(cut, boundary, snapshot)
            data[entry] = 3
            (cut / "memory.ram").write_bytes(data)
            for field in ("next_used", "used_idx", "next_avail"):
                bad = copy.deepcopy(snapshot)
                bad["transport"]["queues"][4][field] = 65535
                with self.subTest(field=field), self.assertRaises(ValueError):
                    check_publication(cut, boundary, bad)
            missing = self.cut(Path(temporary), "missing-used-dirty", data, 7)
            with self.assertRaisesRegex(ValueError, "dirty coverage"):
                check_publication(missing, boundary, snapshot)

    def test_full_image_coverage_rejects_missing_dirty_outside_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.cut(root, "A", bytes([A_BYTE]) * (4 * PAGE))
            changed = bytearray((baseline / "memory.ram").read_bytes())
            changed[PAGE:2 * PAGE] = bytes([B_BYTE]) * PAGE
            changed[-1] ^= 1
            incomplete = self.cut(root, "incomplete", changed, 2)
            with self.assertRaisesRegex(ValueError, "changed pages lack"):
                compare_coverage(baseline, incomplete)
            complete = self.cut(root, "complete", changed, 10)
            proof = compare_coverage(baseline, complete)
            self.assertEqual(proof["scanned_bytes"], 4 * PAGE)
            self.assertEqual(proof["changed_pages"], 2)
            (complete / "memory.ram").write_bytes(changed[:-1])
            with self.assertRaises(ValueError):
                compare_coverage(baseline, complete)

    def test_exact_B_checks_last_byte_and_cannot_be_repaired_by_C(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = bytearray(4 * PAGE)
            data[PAGE:2 * PAGE] = bytes([B_BYTE]) * PAGE
            data[2 * PAGE - 1] = A_BYTE
            path = self.cut(Path(temporary), "missing-B", data)
            with self.assertRaisesRegex(ValueError, "full report page/layout"):
                check_page(path, self.layout(), PAGE, bytes([B_BYTE]) * PAGE)
            data[PAGE:2 * PAGE] = c_page()
            (path / "memory.ram").write_bytes(data)
            check_page(path, self.layout(), PAGE, c_page())
            with self.assertRaises(ValueError):
                check_page(path, self.layout(), PAGE, bytes([B_BYTE]) * PAGE)
            wrong_layout = self.layout()
            wrong_layout["regions"][0]["guestPhysicalAddress"] = PAGE
            with self.assertRaisesRegex(ValueError, "layout"):
                check_page(path, wrong_layout, PAGE, c_page())

    def test_witness_requires_park_actual_used_and_exact_inherited_chain(self):
        source, child = self.boundary(False), self.boundary(True)
        validate_witness(source, 99, "source-seeded", False)
        validate_witness(child, 100, "child-completed", True, source)
        bad_values = ({"parked_cpus": 1}, {"verified_bytes": PAGE - 1}, {"barrier": None},
                      {"used_after": 65535}, {"failure": "deadline"}, {"native_pid": 99},
                      {"seed": A_BYTE}, {"remapper_present": True})
        for change in bad_values:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_witness({**child, **change}, 100, "child-completed", True, source)
        for field in ("gpa", "head", "next_avail", "used_ring"):
            bad = copy.deepcopy(child)
            bad["report"][field] += PAGE if field in ("gpa", "used_ring") else 1
            with self.subTest(identity=field), self.assertRaises(ValueError):
                validate_witness(bad, 100, "child-completed", True, source)
        for field in ("requested", "effective", "released_bytes", "released_extents", "failed_operations"):
            bad = copy.deepcopy(child)
            bad["reclaim"][field] = True if field in ("requested", "effective") else 1
            with self.subTest(status=field), self.assertRaises(ValueError):
                validate_witness(bad, 100, "child-completed", True, source)
        bad = copy.deepcopy(child)
        del bad["reclaim"]["reason"]
        with self.assertRaises(ValueError):
            validate_witness(bad, 100, "child-completed", True, source)

    def test_guest_retained_ownership_nonce_GPA_and_full_readback(self):
        record = self.guest()
        validate_guest(record, self.TOKEN, "reuse", PAGE)
        continued = self.guest("verify", "f" * 32)
        validate_guest(continued, "f" * 32, "verify", PAGE, record)
        for malformed in (None, 123, "", "A" * 32, "f" * 31, "f" * 33):
            with self.subTest(token=malformed), self.assertRaises(ValueError):
                validate_guest(record, malformed, "reuse", PAGE)
        bad_values = ({"request_token": "0" * 32}, {"gpa_after": 2 * PAGE}, {"gpa_before": 2 * PAGE},
                      {"gpa_after": True}, {"target_gpa": PAGE + 1}, {"schema": True},
                      {"ownership": "userspace-allocator"}, {"mlocked": True},
                      {"sysfs_attribute": "/sys/kernel/silo_reclaim"},
                      {"success": False, "error": "pending-completion"})
        for change in bad_values:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_guest({**record, **change}, self.TOKEN, "reuse", PAGE)
        kernel_changes = ({"state": "inflight"}, {"state": "acked"}, {"submitted": 0},
                          {"used_seen": 0}, {"used_seen": True}, {"operation": "verify"},
                          {"token": "f" * 32}, {"gpa": 2 * PAGE}, {"abi": 2}, {"error": 5},
                          {"verified_bytes": PAGE - 1}, {"checksum": "0" * 16}, {"mismatches": 1},
                          {"bytes": PAGE - 1}, {"unexpected": 0})
        for change in kernel_changes:
            bad = {**record, "kernel": {**record["kernel"], **change}}
            with self.subTest(kernel=change), self.assertRaises(ValueError):
                validate_guest(bad, self.TOKEN, "reuse", PAGE)
        for key in record["kernel"]:
            bad = copy.deepcopy(record)
            del bad["kernel"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                validate_guest(bad, self.TOKEN, "reuse", PAGE)
        with self.assertRaises(ValueError):
            validate_guest(self.guest("verify"), self.TOKEN, "verify", PAGE, record)
        bad = copy.deepcopy(continued)
        bad["sysfs_attribute"] = "/sys/bus/virtio/devices/virtio5/silo_reclaim"
        with self.assertRaises(ValueError):
            validate_guest(bad, "f" * 32, "verify", PAGE, record)

    def test_prepare_donate_and_completion_state_transitions(self):
        prepared = self.guest("prepare", "1" * 32)
        donated = self.guest("donate", "2" * 32)
        reused = self.guest("reuse", "3" * 32)
        validate_guest(prepared, "1" * 32, "prepare", None)
        validate_guest(donated, "2" * 32, "donate", PAGE, prepared)
        validate_guest(reused, "3" * 32, "reuse", PAGE, donated)
        acked = copy.deepcopy(donated)
        acked["kernel"].update(state="acked", used_seen=1)
        validate_guest(acked, "2" * 32, "donate", PAGE, prepared)
        validate_guest(reused, "3" * 32, "reuse", PAGE, acked)
        for original, operation, gpa, token, changes in (
                (prepared, "prepare", None, "1" * 32,
                 ({"state": "inflight"}, {"submitted": 1}, {"used_seen": 1})),
                (donated, "donate", PAGE, "2" * 32,
                 ({"state": "owned"}, {"state": "acked"}, {"used_seen": 1},
                  {"verified_bytes": PAGE}, {"checksum": fnv64(c_page())}))):
            for change in changes:
                bad = {**original, "kernel": {**original["kernel"], **change}}
                with self.subTest(operation=operation, change=change), self.assertRaises(ValueError):
                    validate_guest(bad, token, operation, gpa)
        with self.assertRaises(ValueError):
            validate_guest(reused, "3" * 32, "reuse", PAGE, prepared)
        with self.assertRaises(ValueError):
            validate_guest(self.guest("verify", "4" * 32), "4" * 32, "verify", PAGE, donated)
        with self.assertRaises(ValueError):
            validate_guest(prepared, "1" * 32, "prepare", PAGE)
        with self.assertRaises(ValueError):
            validate_guest(donated, "2" * 32, "donate", 2 * PAGE, prepared)

    def test_authentication_rejects_same_bytes_wrong_inode_and_private_baseline_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.cut(root, "baseline", bytes([A_BYTE]) * (4 * PAGE))
            binding = path / "binding"
            binding.mkdir()
            expected = layout_digest((path / "memory-layout.json").read_bytes())
            (binding / "ram-layout").write_bytes(expected)
            auth = authenticate_image(path / "memory.ram", path / "memory-layout.json", expected)
            prepared = {"backing": dict(zip(("device", "inode"), auth["ram_inode"])), "baseline_generation": 1}
            validate_backing(prepared, auth, self.layout(), PAGE)
            wrong = copy.deepcopy(prepared)
            wrong["backing"]["inode"] += 1
            with self.assertRaisesRegex(ValueError, "inode"):
                validate_backing(wrong, auth, self.layout(), PAGE)
            with self.assertRaisesRegex(ValueError, "generation"):
                validate_backing({**prepared, "baseline_generation": 2}, auth, self.layout(), PAGE)
            unchanged_baseline(path, auth)
            (path / "memory.ram").write_bytes(bytes([B_BYTE]) * (4 * PAGE))
            with self.assertRaisesRegex(ValueError, "baseline"):
                unchanged_baseline(path, auth)

    def test_completed_body_cannot_hide_any_owner_or_pressure_cleanup_error(self):
        records = [{"native_reaped": True, "netd_exit_status": 0, "cleanup_failures": []}]
        pressure = {"helper_reaped": True, "helper_exit_status": 0, "cleanup_failures": []}
        require_reaped(records, pressure)
        for bad in ({"native_reaped": False}, {"netd_exit_status": None},
                    {"cleanup_failures": ["stop deadline before forced reap"]}):
            with self.subTest(owner=bad), self.assertRaises(RuntimeError):
                require_reaped([{**records[0], **bad}], pressure)
        for bad in ({"helper_reaped": False}, {"helper_exit_status": 9},
                    {"cleanup_failures": ["original high not restored"]}):
            with self.subTest(helper=bad), self.assertRaises(RuntimeError):
                require_reaped(records, {**pressure, **bad})
        with self.assertRaises(RuntimeError):
            require_reaped([], pressure)

    def test_report_rejects_nonexact_or_unprepared_donation(self):
        report = self.identity()
        validate_report(report, PAGE)
        terminal_next = copy.deepcopy(report)
        terminal_next["descriptors"][0]["next"] = 7
        validate_report(terminal_next, PAGE)
        for changed in ({"flags": 0}, {"flags": 3}, {"flags": 6}, {"len": PAGE - 1},
                        {"len": 2 * PAGE}, {"addr": 2 * PAGE}, {"next": 65536}, {"len": True}):
            bad = copy.deepcopy(report)
            bad["descriptors"][0].update(changed)
            with self.subTest(descriptor=changed), self.assertRaises(ValueError):
                validate_report(bad, PAGE)
        with self.assertRaises(ValueError):
            validate_report(report, 2 * PAGE)
        bad = copy.deepcopy(report)
        bad["descriptors"].append(copy.deepcopy(bad["descriptors"][0]))
        with self.assertRaises(ValueError):
            validate_report(bad, PAGE)
        for indices in ({"avail_idx": 1}, {"avail_idx": 65535}, {"used_idx": 0}):
            with self.subTest(indices=indices), self.assertRaises(ValueError):
                validate_report({**report, **indices}, PAGE)


if __name__ == "__main__":
    unittest.main()
