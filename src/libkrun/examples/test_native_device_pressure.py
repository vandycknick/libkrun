"""Pure numbered-console byte conservation across arbitrary snapshot boundaries."""
import unittest

from native_device_pressure import ConsoleRecords


class ConsoleBoundaryTests(unittest.TestCase):
    def test_every_cut_preserves_exact_prefix_and_numbered_continuation(self):
        complete = b"".join(f"CONSOLE {sequence}\n".encode("ascii") for sequence in range(1, 121))
        stream = complete + b"CONSOLE 121"
        for split in range(len(b"CONSOLE 1\n"), len(stream) + 1):
            with self.subTest(split=split):
                cut = ConsoleRecords.parse(stream[:split])
                fresh_output = stream[split:]
                continued = cut.continued(fresh_output)
                self.assertEqual(cut.data, stream[:split])
                self.assertEqual(continued.data, cut.trailing + fresh_output)
                self.assertEqual(cut.records + continued.records, tuple(range(1, 121)))
                self.assertEqual(continued.trailing, b"CONSOLE 121")
                self.assertEqual(cut.data + fresh_output, stream)

    def test_incomplete_record_is_retained_until_its_original_suffix_arrives(self):
        record = b"CONSOLE 2\n"
        for split in range(len(record)):
            with self.subTest(split=split):
                cut = ConsoleRecords.parse(b"CONSOLE 1\n" + record[:split])
                self.assertEqual(cut.records, (1,))
                self.assertEqual(cut.trailing, record[:split])
                pending = cut.continued(b"")
                self.assertEqual(pending.records, ())
                self.assertEqual(pending.trailing, record[:split])
                completed = cut.continued(record[split:])
                self.assertEqual(completed.records, (2,))
                self.assertEqual(completed.data, record)
                self.assertEqual(completed.trailing, b"")

    def test_dropped_replayed_reordered_or_changed_continuation_bytes_fail(self):
        cut = ConsoleRecords.parse(b"CONSOLE 1\nCONSOLE 2")
        for suffix in (b"CONSOLE 3\n", b"CONSOLE 2\nCONSOLE 3\n",
                       b"\nCONSOLE 4\n", b"\nCONSOLE 2\n", b"\r\nCONSOLE 3\n",
                       b"\nCONSOLE 03\n", b"\nCONSOLE 3\x00\n"):
            with self.subTest(suffix=suffix):
                with self.assertRaises(RuntimeError):
                    cut.continued(suffix)
        self.assertEqual(cut.data, b"CONSOLE 1\nCONSOLE 2")
        self.assertEqual(cut.trailing, b"CONSOLE 2")
        self.assertEqual(cut.continued(b"\nCONSOLE 3\n").records, (2, 3))

    def test_malformed_complete_records_and_impossible_prefixes_fail(self):
        for data in (b"CONSOLE 0\n", b"CONSOLE 01\n", b"CONSOLE 2\n", b"CONSOLE 1\r\n",
                     b"CONSOLE 1\n\n", b"CONSOLE 1\nCONSOLE 0", b"CONSOLE 1\nCONSOLE 02",
                     b"CONSOLE 1\nCONSOLE 2\r", b"CONSOLE 1\n\xff"):
            with self.subTest(data=data):
                with self.assertRaises(RuntimeError):
                    ConsoleRecords.parse(data)
        empty = ConsoleRecords.parse(b"")
        self.assertEqual(empty.data, b"")
        self.assertEqual(empty.records, ())
        self.assertEqual(empty.trailing, b"")


if __name__ == "__main__":
    unittest.main()
