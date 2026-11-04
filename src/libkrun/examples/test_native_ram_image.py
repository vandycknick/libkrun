"""Hypervisor-free identity and real descriptor authentication regressions."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from native_ram_image import (CHUNK_SIZE, authenticate_image, authentication_bytes,
                              layout_digest, validate_layout, write_authentication)


def layout_bytes(length=4096):
    return json.dumps({"architecture": "x86_64", "kind": "ram-layout", "packedLength": length,
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
            chunk = hashlib.sha256(b"x" * 4096).hexdigest()
            canonical = ('{"chunkSize":8388608,"chunks":["zero","sha256:' + chunk +
                         '"],"kind":"stream","length":8392704,"schema":1}').encode()
            self.assertEqual(result["stream_digest"], hashlib.sha256(b"silo:stream:v1\n" + canonical).hexdigest())
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
                self.assertEqual(result["stream_map"]["chunks"], ["zero"])
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


if __name__ == "__main__":
    unittest.main()
