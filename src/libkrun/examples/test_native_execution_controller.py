"""Real subprocess ownership regressions, without native devices or native ACKs."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

from native_execution_controller import invoke


CHILD = """
import json
import os
import signal
import socket
import sys

signal.signal(signal.SIGINT, signal.SIG_IGN)
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.connect(sys.argv[1])
print(json.dumps({"pid": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0)}), flush=True)
try:
    connection.recv(1)
finally:
    connection.close()
"""

CONTROLLER = """
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

root = Path(sys.argv[1])
child = None
try:
    child = subprocess.Popen([sys.executable, "-c", sys.argv[2], sys.argv[3]], stdout=subprocess.PIPE, text=True)
    ownership = {"controller": {"pid": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0)},
                 "child": json.loads(child.stdout.readline())}
    (root / "ownership.json").write_text(json.dumps(ownership))
    print("controller ready", flush=True)
    print("controller diagnostic", file=sys.stderr, flush=True)
    while True:
        signal.pause()
except KeyboardInterrupt:
    pass
finally:
    cleanup = {"interrupted": True}
    if child is not None and sys.argv[4] == "graceful":
        child.terminate()
        cleanup["child_exit_status"] = child.wait(timeout=5)
        child.stdout.close()
    (root / "finally.json").write_text(json.dumps(cleanup))
"""


@unittest.skipUnless(sys.platform == "linux", "Linux waitid(WNOWAIT) session ownership diagnostic")
class InvocationTimeoutTests(unittest.TestCase):
    def exercise_timeout(self, mode):
        with tempfile.TemporaryDirectory(prefix="native-invoke-") as temporary:
            root = Path(temporary)
            endpoint = root / "lifetime.sock"
            command = [sys.executable, "-c", CONTROLLER, str(root), CHILD, str(endpoint), mode]
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(endpoint))
                listener.listen(1)
                listener.settimeout(5)
                connection = None
                # This independently owned process must not receive group signals.
                with subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                                      stdin=subprocess.PIPE) as unrelated:
                    try:
                        with self.assertRaises(RuntimeError):
                            invoke(command, root, "timeout", timeout=3)
                        connection, _ = listener.accept()
                        connection.settimeout(5)
                        ownership = json.loads((root / "ownership.json").read_text())
                        record = json.loads((root / "timeout.invocation.json").read_text())
                        cleanup = json.loads((root / "finally.json").read_text())
                        controller = ownership["controller"]
                        child = ownership["child"]
                        self.assertEqual(record["command"], command)
                        self.assertEqual(record["pid"], controller["pid"])
                        self.assertEqual(controller["pid"], controller["pgid"])
                        self.assertEqual(controller["pid"], controller["sid"])
                        self.assertEqual(child["pgid"], controller["pgid"])
                        self.assertEqual(child["sid"], controller["sid"])
                        self.assertNotEqual(controller["pgid"], os.getpgrp())
                        self.assertTrue(record["timeout"])
                        self.assertFalse(record["native_cleanup_acknowledged"])
                        self.assertNotIn("status", record)
                        self.assertNotIn("all_reaped", record)
                        self.assertEqual(record["timeout_seconds"], 3)
                        self.assertTrue(record["cleanup"]["controller_exited_during_grace"])
                        self.assertTrue(record["cleanup"]["controller_reaped"])
                        self.assertEqual(record["cleanup"]["controller_exit_status"], 0)
                        self.assertEqual(record["cleanup"]["errors"], [])
                        self.assertTrue(cleanup["interrupted"])
                        if mode == "graceful":
                            self.assertEqual(cleanup["child_exit_status"], -signal.SIGTERM)
                        else:
                            self.assertNotIn("child_exit_status", cleanup)
                            self.assertTrue(record["cleanup"]["group_kill_sent"])
                        # EOF is an actual descendant-owned resource lifetime, not
                        # a PID lookup or an invented native cleanup acknowledgement.
                        self.assertEqual(connection.recv(1), b"")
                        self.assertIsNone(unrelated.poll())
                        self.assertEqual((root / "timeout.stdout").read_text(), "controller ready\n")
                        self.assertEqual((root / "timeout.stderr").read_text(), "controller diagnostic\n")
                        for suffix in ("stdout", "stderr", "invocation.json"):
                            self.assertEqual((root / f"timeout.{suffix}").stat().st_mode & 0o777, 0o600)
                    finally:
                        # A broken implementation must not leave the test's child
                        # behind: closing its real peer releases recv even without kill.
                        if connection is None:
                            try:
                                connection, _ = listener.accept()
                            except socket.timeout:
                                pass
                        if connection is not None:
                            connection.close()
                        unrelated.stdin.close()
                        unrelated.wait(timeout=5)

    def test_timeout_interrupts_controller_finally_and_child_cleanup(self):
        self.exercise_timeout("graceful")

    def test_timeout_kills_descendant_left_by_exited_controller(self):
        self.exercise_timeout("leave-child")


if __name__ == "__main__":
    unittest.main()
