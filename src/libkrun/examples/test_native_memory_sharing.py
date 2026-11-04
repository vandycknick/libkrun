"""Pure measurement/nonce boundaries and actual Linux file-private VMA ownership.

No VM, pressure generator, mocked process, or reclaim qualification runs here.
Main runs: python3 -m unittest discover -s src/libkrun/examples -p test_native_memory_sharing.py
"""
import copy
import ctypes
import mmap
import os
from pathlib import Path
import tempfile
import unittest

from native_memory_sharing import (
    MIB, PAGE, SET_BYTES, check_saved_first_page, evaluate_measurements,
    first_page, key_values, measurement_totals, parse_smaps, pressure_delta,
    pressure_totals, ram_measurement, readonly_owners, real_pressure, reporting_advanced,
    validate_observation, validate_unit_binding,
)


class SharingObservationTests(unittest.TestCase):
    @staticmethod
    def observation(slot=None):
        return {"schema": 1, "request_token": "0123456789abcdef" * 2,
                "bytes": SET_BYTES, "page_size": PAGE, "pages": SET_BYTES // PAGE,
                "write_slot": slot, "verified_bytes": SET_BYTES, "mismatches": 0,
                "checksum": "0123456789abcdef" if slot is None else "fedcba9876543210",
                "baseline_checksum": "0123456789abcdef", "first_gpa": 0x100000, "mlocked": True}

    def test_exact_clean_dirty_and_repeated_content_identity(self):
        clean = self.observation()
        dirty = self.observation(2)
        validate_observation(clean, clean["request_token"], None)
        validate_observation(dirty, dirty["request_token"], 2, clean)
        validate_observation(dirty, dirty["request_token"], 2, clean, dirty)

    def test_nonce_count_slot_checksum_and_identity_fail_closed(self):
        clean = self.observation()
        changes = ({"request_token": "0" * 32}, {"schema": True}, {"pages": True},
                   {"verified_bytes": SET_BYTES - PAGE}, {"mismatches": 1}, {"write_slot": False},
                   {"write_slot": 0}, {"mlocked": 1}, {"checksum": "0123456789ABCDEf"},
                   {"baseline_checksum": "0" * 16}, {"first_gpa": 0x100001}, {"extra": 1})
        for change in changes:
            with self.subTest(change=change):
                record = {**clean, **change}
                with self.assertRaises(ValueError):
                    validate_observation(record, clean["request_token"], None, clean)
        dirty = self.observation(2)
        for field, value in (("checksum", "0" * 16), ("first_gpa", 0x200000),
                             ("baseline_checksum", "1" * 16), ("write_slot", 3)):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    validate_observation({**dirty, field: value}, dirty["request_token"], 2, clean, dirty)



class SharingMeasurementPolicyTests(unittest.TestCase):
    @staticmethod
    def totals(file_bytes, anonymous, private_dirty):
        return {"ram_vma_pss_bytes": file_bytes + anonymous,
                "ram_vma_file_pss_bytes": file_bytes,
                "ram_vma_anonymous_bytes": anonymous,
                "ram_vma_private_dirty_bytes": private_dirty}

    def test_single_child_cow_replacement_does_not_require_pss_growth(self):
        clean = self.totals(80 * MIB, 16 * MIB, 96 * MIB)
        dirty = self.totals(64 * MIB, 32 * MIB, 96 * MIB)
        result = evaluate_measurements(1, clean, dirty, None)
        self.assertEqual(result["expected_pss_growth_bytes"], 0)
        self.assertEqual(result["delta_bytes"]["ram_vma_pss_bytes"], 0)
        self.assertEqual(result["delta_bytes"]["ram_vma_private_dirty_bytes"], 0)

    def test_two_and_four_children_count_shared_common_page_once(self):
        control = self.totals(80 * MIB, 16 * MIB, 16 * MIB)
        for n in (2, 4):
            with self.subTest(n=n):
                clean = self.totals(80 * MIB, n * 16 * MIB, n * 16 * MIB)
                private = n * 16 * MIB + (n - 1) * PAGE
                dirty = self.totals(80 * MIB - PAGE, n * 16 * MIB + private,
                                    n * 16 * MIB + private)
                result = evaluate_measurements(n, clean, dirty, control)
                self.assertEqual(result["expected_pss_growth_bytes"], n * 16 * MIB + (n - 2) * PAGE)
                self.assertEqual(result["delta_bytes"]["ram_vma_pss_bytes"], result["expected_pss_growth_bytes"])

    def test_copy_per_child_missing_cow_and_growth_outliers_reject(self):
        control = self.totals(80 * MIB, 16 * MIB, 16 * MIB)
        clean = self.totals(80 * MIB, 32 * MIB, 32 * MIB)
        dirty = self.totals(80 * MIB, 64 * MIB, 64 * MIB)
        for bad_clean, bad_dirty, baseline in (
                (self.totals(160 * MIB, 32 * MIB, 32 * MIB), dirty, control),
                (self.totals(16 * MIB, 32 * MIB, 32 * MIB), dirty, control),
                (clean, clean, control),
                (clean, self.totals(160 * MIB, 64 * MIB, 64 * MIB), control),
                (clean, dirty, None)):
            with self.subTest(clean=bad_clean, dirty=bad_dirty):
                with self.assertRaises(ValueError):
                    evaluate_measurements(2, bad_clean, bad_dirty, baseline)

    def test_totals_use_ram_vmas_not_process_rss(self):
        records = [{"totals_bytes": {"Pss": 100, "Private_Dirty": 20, "Anonymous": 30, "Rss": 900},
                    "file_pss_bytes": 70},
                   {"totals_bytes": {"Pss": 200, "Private_Dirty": 40, "Anonymous": 60, "Rss": 900},
                    "file_pss_bytes": 140}]
        self.assertEqual(measurement_totals(records), {
            "ram_vma_pss_bytes": 300, "ram_vma_private_dirty_bytes": 60,
            "ram_vma_anonymous_bytes": 90, "ram_vma_file_pss_bytes": 210})


@unittest.skipUnless(os.path.exists("/proc/self/smaps") and os.sysconf("SC_PAGE_SIZE") == PAGE,
                     "actual Linux 4KiB smaps required")
class ActualRamMappingTests(unittest.TestCase):
    @staticmethod
    def layout(size):
        return {"packedLength": size, "regions": [
            {"guestPhysicalAddress": 0, "length": PAGE, "streamOffset": 0},
            {"guestPhysicalAddress": 0x100000, "length": size - PAGE, "streamOffset": PAGE}]}

    @staticmethod
    def actual_mapping_evidence(memory, info, layout):
        base = ctypes.addressof(ctypes.c_ubyte.from_buffer(memory))
        return {"schema": 1, "native_pid": os.getpid(), "packed_len": layout["packedLength"],
                "regions": [{"gpa": region["guestPhysicalAddress"], "length": region["length"],
                             "stream_offset": region["streamOffset"], "host_start": base + region["streamOffset"],
                             "device": info.st_dev, "inode": info.st_ino} for region in layout["regions"]]}

    def test_actual_readonly_inode_private_cow_unlink_and_retained_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ram"
            data = first_page(None) + first_page(0) + first_page(1) + first_page(2)
            with path.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            fd = os.open(path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                layout = self.layout(len(data))
                with mmap.mmap(fd, len(data), flags=mmap.MAP_PRIVATE,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as memory:
                    self.assertEqual(memory[:], data)
                    evidence = self.actual_mapping_evidence(memory, info, layout)
                    clean = ram_measurement(Path("/proc/self/smaps").read_text(), info.st_dev, info.st_ino, layout, evidence)
                    self.assertEqual(clean["file_pss_bytes"], len(data))
                    self.assertTrue(readonly_owners(os.getpid(), info.st_dev, info.st_ino))
                    page = check_saved_first_page(fd, layout, 0, None)
                    self.assertEqual(page["stream_offset"], 0)
                    page = check_saved_first_page(fd, layout, 0x100000, 0)
                    self.assertEqual(page["stream_offset"], PAGE)
                    with self.assertRaises(ValueError):
                        check_saved_first_page(fd, layout, 0x100000, 1)
                    memory[8] ^= 0xff
                    dirty = ram_measurement(Path("/proc/self/smaps").read_text(), info.st_dev, info.st_ino, layout, evidence)
                    self.assertEqual(dirty["totals_bytes"]["Anonymous"], PAGE)
                    self.assertGreaterEqual(dirty["totals_bytes"]["Private_Dirty"], PAGE)
                    self.assertEqual(dirty["totals_bytes"]["Pss"], len(data))
                    self.assertEqual(os.pread(fd, len(data), 0), data)
                    path.unlink()
                    self.assertEqual(os.fstat(fd).st_nlink, 0)
                    self.assertNotEqual(memory[:PAGE], data[:PAGE])
                    self.assertEqual(os.pread(fd, len(data), 0), data)
                    self.assertTrue(readonly_owners(os.getpid(), info.st_dev, info.st_ino))
                    after = ram_measurement(Path("/proc/self/smaps").read_text(), info.st_dev, info.st_ino, layout, evidence)
                    self.assertTrue(all(mapping["name"].endswith(" (deleted)") for mapping in after["mappings"]))
            finally:
                os.close(fd)

    def test_actual_shared_wrong_backing_and_wrong_host_range_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ram"
            path.write_bytes(bytes([0x41]) * (4 * PAGE))
            fd = os.open(path, os.O_RDWR)
            try:
                info = os.fstat(fd)
                layout = self.layout(4 * PAGE)
                with mmap.mmap(fd, 4 * PAGE, flags=mmap.MAP_SHARED,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as memory:
                    self.assertEqual(memory[0], 0x41)
                    evidence = self.actual_mapping_evidence(memory, info, layout)
                    with self.assertRaises(ValueError):
                        ram_measurement(Path("/proc/self/smaps").read_text(), info.st_dev, info.st_ino, layout, evidence)
                with mmap.mmap(fd, 4 * PAGE, flags=mmap.MAP_PRIVATE,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as first:
                    self.assertEqual(first[0], 0x41)
                    evidence = self.actual_mapping_evidence(first, info, layout)
                    text = Path("/proc/self/smaps").read_text()
                    with self.assertRaises(ValueError):
                        ram_measurement(text, info.st_dev, info.st_ino + 1, layout, evidence)
                    with self.assertRaises(ValueError):
                        ram_measurement(text, info.st_dev, info.st_ino, self.layout(8 * PAGE), evidence)
                    for field, value in (("device", info.st_dev + 1), ("host_start", evidence["regions"][0]["host_start"] + PAGE),
                                         ("stream_offset", PAGE), ("inode", info.st_ino + 1)):
                        wrong = copy.deepcopy(evidence)
                        wrong["regions"][0][field] = value
                        with self.subTest(field=field):
                            with self.assertRaises(ValueError):
                                ram_measurement(text, info.st_dev, info.st_ino, layout, wrong)
                    with mmap.mmap(fd, 4 * PAGE, flags=mmap.MAP_PRIVATE,
                                   prot=mmap.PROT_READ | mmap.PROT_WRITE) as second:
                        self.assertEqual(second[0], first[0])
                        # A separate alias is not registered RAM. HVA selection
                        # must exclude it rather than sum all same-inode VMAs.
                        measured = ram_measurement(Path("/proc/self/smaps").read_text(), info.st_dev, info.st_ino,
                                                   layout, evidence)
                        self.assertEqual(measured["totals_bytes"]["Size"], 4 * PAGE)
            finally:
                os.close(fd)

    def test_smaps_empty_truncated_measurement_and_duplicate_counter_reject(self):
        with self.assertRaises(ValueError):
            parse_smaps("")
        with self.assertRaises(ValueError):
            parse_smaps("Pss: 1 kB\n")
        with self.assertRaises(ValueError):
            parse_smaps("1000-2000 rw-p 00000000 00:00 1 /ram\nPss: 1\n")
        with self.assertRaises(ValueError):
            parse_smaps("1000-2000 rw-p 00000000 00:00 1 /ram\nPss: 1 kB\nPss: 1 kB\n")


class ReportingPublicationTests(unittest.TestCase):
    @staticmethod
    def observation():
        return {"schema": 1, "native_pid": 17, "reporting_negotiated": True,
                "host_reclaim_enabled": False, "ready": True, "next_used": 0,
                "used_idx": 0, "used_ring": 0x4000}

    def test_actual_used_publication_not_attempt_or_guest_churn_is_required(self):
        zero = self.observation()
        self.assertFalse(reporting_advanced(zero, 17, 0))
        self.assertFalse(reporting_advanced({**zero, "next_used": 1}, 17, 0))
        self.assertFalse(reporting_advanced({**zero, "used_idx": 1}, 17, 0))
        published = {**zero, "next_used": 1, "used_idx": 1}
        self.assertTrue(reporting_advanced(published, 17, 0))
        self.assertFalse(reporting_advanced(published, 17, 1))
        self.assertFalse(reporting_advanced({**published, "reporting_negotiated": False}, 17, 0))

    def test_child_used_index_advancement_handles_u16_wrap(self):
        zero = self.observation()
        self.assertTrue(reporting_advanced(zero, 17, 0xffff))
        self.assertFalse(reporting_advanced(zero, 17, 0))
        self.assertTrue(reporting_advanced({**zero, "next_used": 3, "used_idx": 3}, 17, 0xfffe))

    def test_unready_and_malformed_observations_cannot_acknowledge_completion(self):
        zero = self.observation()
        unready = {**zero, "ready": False, "next_used": None, "used_idx": None, "used_ring": None}
        self.assertFalse(reporting_advanced(unready, 17, 0))
        for changed in ({"native_pid": 18}, {"schema": True}, {"host_reclaim_enabled": True},
                        {"ready": 1}, {"reporting_negotiated": 1}, {"next_used": 65536},
                        {"used_idx": -1}, {"used_ring": 0x4001}, {"extra": 0}):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    reporting_advanced({**zero, **changed}, 17, 0)
        with self.assertRaises(ValueError):
            reporting_advanced({**unready, "next_used": 1}, 17, 0)
        with self.assertRaises(ValueError):
            reporting_advanced(zero, 17, True)


class PressureUnitOwnershipTests(unittest.TestCase):
    def test_only_exact_dedicated_current_service_can_change_properties(self):
        unit = "silo-phase10-sharing-n4.service"
        own = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
        validate_unit_binding(unit, own, own)
        for name, actual, reported in (
                ("tern-remote.service", "/system.slice/tern-remote.service", "/system.slice/tern-remote.service"),
                ("default.service", own, own),
                (unit, own, "/user.slice/other.service"),
                (unit, "/system.slice/tern-remote.service", "/system.slice/tern-remote.service"),
                (unit, own + "/child.scope", own + "/child.scope"),
                (unit, "/../../" + unit, "/../../" + unit),
                (unit, unit, unit)):
            with self.subTest(name=name, actual=actual, reported=reported):
                with self.assertRaises(ValueError):
                    validate_unit_binding(name, actual, reported)


class PressureCounterTests(unittest.TestCase):
    @staticmethod
    def counters():
        return {"events": {"high": 5, "max": 0, "oom": 0, "oom_kill": 0},
                "stat": {"pgscan": 100, "pgsteal": 80}, "psi_us": {"some": 30, "full": 20}}

    def test_actual_counter_grammar_and_pressure_deltas(self):
        self.assertEqual(key_values("high 123\noom 0\n"), {"high": 123, "oom": 0})
        self.assertEqual(pressure_totals("some avg10=0.01 avg60=0.00 avg300=0.00 total=12\n"
                                         "full avg10=0.00 avg60=0.00 avg300=0.00 total=3\n"),
                         {"some": 12, "full": 3})
        before = self.counters()
        after = copy.deepcopy(before)
        after["events"]["high"] += 1
        after["stat"]["pgscan"] += 4
        after["stat"]["pgsteal"] += 3
        after["psi_us"]["some"] += 2
        self.assertTrue(real_pressure(pressure_delta(before, after)))
        for section, key in (("events", "high"), ("stat", "pgscan"),
                             ("stat", "pgsteal"), ("psi_us", "some")):
            missing = copy.deepcopy(after)
            missing[section][key] = before[section][key]
            self.assertFalse(real_pressure(pressure_delta(before, missing)))

    def test_oom_max_regression_and_malformed_counters_reject(self):
        before = self.counters()
        for event in ("max", "oom", "oom_kill"):
            after = copy.deepcopy(before)
            after["events"][event] += 1
            with self.assertRaises(RuntimeError):
                real_pressure(pressure_delta(before, after))
        after = copy.deepcopy(before)
        after["stat"]["pgscan"] -= 1
        with self.assertRaises(ValueError):
            pressure_delta(before, after)
        for text in ("high -1", "high 1\nhigh 2", "high", "high 1 extra"):
            with self.assertRaises(ValueError):
                key_values(text)
        for text in ("", "some total=1", "some total=x\nfull total=0", "some total=1 total=2\nfull total=0"):
            with self.assertRaises(ValueError):
                pressure_totals(text)


if __name__ == "__main__":
    unittest.main()
