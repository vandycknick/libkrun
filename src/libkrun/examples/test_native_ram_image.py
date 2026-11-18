"""Hypervisor-free identity and real descriptor authentication regressions."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from native_ram_image import (CHUNK_SIZE, authenticate_image, authentication_bytes,
                              iter_changes, layout_digest, stream_root, validate_layout, write_authentication)


def layout_bytes(length=4096):
    return json.dumps({"architecture": "x86_64", "kind": "ram-layout", "magic": "KRUNRAML", "packedLength": length,
                       "pageGranule": 4096,
                       "regions": [{"guestPhysicalAddress": 0, "length": length, "streamOffset": 0}],
                       "schema": 1, "topology": {"firmwareAddress": 0, "initrdAddress": length,
                       "ramAboveGap": 0, "ramBelowGap": length, "ramLastAddress": length,
                       "shmStartAddress": 4294967296}}, sort_keys=True, separators=(",", ":")).encode()


class RamImageAuthenticationTests(unittest.TestCase):
    def test_silo_stream_golden_zero_and_data_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ram, layout = root / "memory.ram", root / "memory-layout.json"
            data = layout_bytes(CHUNK_SIZE + 4096)
            layout.write_bytes(data)
            with ram.open("wb") as output:
                output.truncate(CHUNK_SIZE + 4096)
                output.seek(CHUNK_SIZE)
                output.write(b"x" * 4096)
            result = authenticate_image(ram, layout, hashlib.sha256(data).digest(), data)
            chunk = hashlib.sha256(b"x" * 4096).digest()
            leaf = b"silo:stream-map:leaf:v1\n" + struct.pack("<Q", 2) + chunk
            tree = hashlib.sha256(leaf).digest()
            for height in range(1, 5):
                tree = hashlib.sha256(b"silo:stream-map:branch:v1\n" + bytes([height])
                                      + struct.pack("<Q", 1) + tree).digest()
            canonical = b"silo:stream:v1\n" + struct.pack("<BQB", 16, CHUNK_SIZE + 4096, 1) + tree
            self.assertEqual(result["stream_root"], canonical.hex())
            self.assertEqual(result["stream_digest"], hashlib.sha256(canonical).hexdigest())
            self.assertEqual(result["caller_authentication_bytes_read"], len(data) + CHUNK_SIZE + 4096)
            auth = root / "authentication.bin"
            write_authentication(auth, result)
            self.assertEqual(auth.read_bytes(), hashlib.sha256(data).digest() + bytes.fromhex(result["stream_digest"]))
            self.assertEqual(authentication_bytes(result), auth.read_bytes())
            with self.assertRaises(FileExistsError):
                write_authentication(auth, result)

    def test_wrong_digest_altered_layout_and_identity_kind_confusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ram, layout = root / "ram", root / "layout"
            ram.write_bytes(bytes(4096))
            data = layout_bytes()
            layout.write_bytes(data)
            for digest in (bytes(32), hashlib.sha256(b"silo:ram-layout:v1\n" + data).digest(), b"short"):
                with self.subTest(digest=digest), self.assertRaises(ValueError):
                    authenticate_image(ram, layout, digest, data)
            changed = data.replace(b'"initrdAddress":4096', b'"initrdAddress":0')
            layout.write_bytes(changed)
            with self.assertRaises(ValueError):
                authenticate_image(ram, layout, hashlib.sha256(data).digest(), data)
            with self.assertRaises(ValueError):
                authenticate_image(ram, layout, hashlib.sha256(changed).digest(), data)

    def test_noncanonical_unknown_duplicate_malformed_geometry_refused(self):
        data = layout_bytes()
        invalid = (b"", data + b"\n", data.replace(b'"schema":1', b'"schema":1,"schema":1'),
                   data.replace(b'"schema":1', b'"schema":1,"extra":0'),
                   data.replace(b'"schema":1', b'"schema":true'),
                   data.replace(b'"magic":"KRUNRAML"', b'"magic":"WRONGMAG"'),
                   data.replace(b'"schema":1', b'"schema":2'),
                   data.replace(b'"length":4096', b'"length":4095'),
                   data.replace(b'"streamOffset":0', b'"streamOffset":4096'),
                   data.replace(b'"pageGranule":4096', b'"pageGranule":4096.0'))
        for value in invalid:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                validate_layout(value)
        self.assertEqual(layout_digest(data), hashlib.sha256(data).digest())

    def test_actual_retained_readonly_descriptor_not_reopened_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ram, layout = root / "ram", root / "layout"
            ram.write_bytes(bytes(4096))
            data = layout_bytes()
            layout.write_bytes(data)
            fd = os.open(ram, os.O_RDONLY)
            try:
                ram.unlink()
                ram.write_bytes(b"x" * 4096)
                result = authenticate_image(ram, layout, layout_digest(data), ram_fd=fd)
                self.assertEqual(result["stream_root"],
                                 (b"silo:stream:v1\n" + struct.pack("<BQB", 16, 4096, 0)).hex())
                self.assertEqual(result["ram_inode"], [os.fstat(fd).st_dev, os.fstat(fd).st_ino])
                self.assertNotEqual(result["ram_inode"][1], ram.stat().st_ino)
            finally:
                os.close(fd)
            writable = os.open(ram, os.O_RDWR)
            try:
                with self.assertRaises(ValueError):
                    authenticate_image(ram, layout, layout_digest(data), ram_fd=writable)
            finally:
                os.close(writable)
            ram.write_bytes(bytes(8192))
            with self.assertRaises(ValueError):
                authenticate_image(ram, layout, layout_digest(data))


class RamChangesTests(unittest.TestCase):
    def test_real_file_sorted_data_zero_run_and_short_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changes"
            header = b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, 1, 0)
            tail = hashlib.sha256(b"x" * 4096).digest()
            path.write_bytes(header + struct.pack("<QQB7s32s", 0, 2, 0, bytes(7), bytes(32))
                             + struct.pack("<QQB7s32s", 2, 1, 1, bytes(7), tail))
            self.assertEqual(list(iter_changes(path, 2 * CHUNK_SIZE + 4096, "incremental")),
                             [(0, 2, None), (2, 1, tail)])
            path.write_bytes(header)
            self.assertEqual(list(iter_changes(path, CHUNK_SIZE, "incremental")), [])

    def test_truncated_never_written_and_noncanonical_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changes"
            header = b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, 1, 0)
            zero = lambda first, count: struct.pack("<QQB7s32s", first, count, 0, bytes(7), bytes(32))
            data = struct.pack("<QQB7s32s", 0, 1, 1, bytes(7), b"x" * 32)
            for encoded in (b"", header[:-1], header + b"x", header + zero(0, 0),
                            header + zero(0, 1) + zero(1, 1), header + data + data,
                            header + zero(2, 2), header + data[:-1],
                            header[:10] + b"\x17" + header[11:],
                            header + struct.pack("<QQB7s32s", 0, 2, 1, bytes(7), b"x" * 32)):
                path.write_bytes(encoded)
                with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                    list(iter_changes(path, 3 * CHUNK_SIZE, "incremental"))
            path.write_bytes(b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, 0, 0) + zero(0, 1))
            with self.assertRaises(ValueError):
                list(iter_changes(path, CHUNK_SIZE, "full"))

    def test_sparse_root_frontiers_cross_leaf_and_branch_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ram"
            # Four independent leaf pages, including a height-1 boundary.
            indices = (0, 63, 64, 4095, 4096)
            length = 4096 * CHUNK_SIZE + 4096
            with path.open("wb") as output:
                output.truncate(length)
                for index in indices:
                    output.seek(index * CHUNK_SIZE)
                    output.write(b"x" * 4096)
            with path.open("rb") as source:
                actual = stream_root(source.fileno(), length)
            pages = {}
            for index in indices:
                payload = b"x" * 4096 + (bytes(CHUNK_SIZE - 4096) if index != 4096 else b"")
                pages.setdefault(index // 64, {})[index % 64] = hashlib.sha256(payload).digest()
            level = {index: hashlib.sha256(b"silo:stream-map:leaf:v1\n"
                     + struct.pack("<Q", sum(1 << bit for bit in entries))
                     + b"".join(entries[bit] for bit in sorted(entries))).digest()
                     for index, entries in pages.items()}
            for height in range(1, 5):
                parents = {}
                for index, digest in level.items():
                    parents.setdefault(index // 64, {})[index % 64] = digest
                level = {index: hashlib.sha256(b"silo:stream-map:branch:v1\n" + bytes([height])
                         + struct.pack("<Q", sum(1 << bit for bit in entries))
                         + b"".join(entries[bit] for bit in sorted(entries))).digest()
                         for index, entries in parents.items()}
            self.assertEqual(actual, b"silo:stream:v1\n" + struct.pack("<BQB", 16, length, 1) + level[0])


if __name__ == "__main__":
    unittest.main()
