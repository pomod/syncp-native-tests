"""Real executable acceptance. A missing build is BLOCKED, never a passing stub."""
from __future__ import annotations
from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


EXE = Path(os.environ.get("SYNCP_NATIVE_TEST_EXE", ""))


class NativeAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syncp-native-acceptance-")
        self.root = Path(self.temp.name) / "state"
        self.host = None
        self.unrelated = None
        self.launch()

    def launch(self):
        self.host = subprocess.Popen([str(EXE), "--data-dir", str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10  # Host startup observation only, not an execution deadline.
        files = []
        while time.monotonic() < deadline:
            if self.host.poll() is not None:
                self.fail("Native host did not start: " + self.host.stderr.read())
            files = list(self.root.glob("session-*.json"))
            if files:
                candidate = max(files, key=lambda p: p.stat().st_mtime_ns)
                try:
                    session = json.loads(candidate.read_text())
                    if session["host_pid"] == self.host.pid:
                        self.session = session
                        self.session_file = candidate
                        return
                except (OSError, ValueError):
                    pass
            time.sleep(0.02)
        self.fail("Native host startup observation exceeded 10 seconds")

    def api(self, path, *, data=None, token="manage", origin=None, host=None):
        headers = {}
        if token in {"manage", "read"}:
            headers["Authorization"] = "Bearer " + self.session[token + "_token"]
        elif token:
            headers["Authorization"] = "Bearer " + token
        if origin is not None:
            headers["Origin"] = origin
        if host is not None:
            headers["Host"] = host
        raw = None
        if data is not None:
            raw = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.session["origin"] + path, data=raw, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, json.loads(response.read())

    def stop_host(self):
        code, data = self.api("/api/v1/host/stop", data={})
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])
        self.host.wait(timeout=5)
        self.assertEqual(self.host.returncode, 0)
        self.host.stdout.close()
        self.host.stderr.close()
        self.host = None

    def tearDown(self):
        if self.host and self.host.poll() is None:
            try:
                self.stop_host()
            except Exception:
                # Cleanup only the Popen handle owned by this test, never a port/name scan.
                self.host.terminate()
                self.host.wait(timeout=5)
        if self.unrelated:
            self.unrelated.stdin.close()
            self.unrelated.wait(timeout=5)
        self.temp.cleanup()

    def test_native_health_version_and_loopback_binding(self):
        self.assertTrue(self.session["origin"].startswith("http://127.0.0.1:"))
        code, result = self.api("/api/v1/health", token=None)
        self.assertEqual(code, 200)
        self.assertEqual(result["api_version"], 1)
        self.assertEqual(result["qualification"], "ARCHITECTURE_PROOF")
        version = subprocess.run([str(EXE), "--version"], capture_output=True, text=True, check=True).stdout
        self.assertIn(result["version"], version)

    def test_missing_bad_and_read_only_capabilities(self):
        for token in (None, "wrong"):
            self.assertEqual(self.api("/api/v1/status", token=token)[0], 401)
        self.assertEqual(self.api("/api/v1/status", token="read")[0], 200)
        self.assertEqual(self.api("/api/v1/proof/start", data={}, token="read")[0], 403)
        self.assertFalse(self.api("/api/v1/status", token="read")[1]["capabilities"]["manage_proof"])

    def test_foreign_origin_and_dns_rebinding_rejected(self):
        self.assertEqual(self.api("/api/v1/proof/start", data={}, origin="https://evil.example")[0], 403)
        self.assertEqual(self.api("/api/v1/status", host="evil.example")[0], 403)
        self.assertEqual(self.api("/api/v1/status", origin="null")[0], 403)

    def test_owned_start_stop_is_idempotent_and_preserves_unrelated_process(self):
        self.unrelated = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
        self.assertEqual(self.api("/api/v1/proof/start", data={})[0], 200)
        first = self.api("/api/v1/status")[1]["owned_process"]
        self.assertTrue(first["running"])
        self.assertIsNone(first["healthy"])
        self.assertEqual(first["task_timeout_seconds"], 0)
        self.assertEqual(self.api("/api/v1/proof/start", data={})[0], 200)
        self.assertEqual(self.api("/api/v1/status")[1]["owned_process"]["pid"], first["pid"])
        self.assertEqual(self.api("/api/v1/proof/stop", data={})[0], 200)
        self.assertEqual(self.api("/api/v1/proof/stop", data={})[0], 200)
        final = self.api("/api/v1/status")[1]["owned_process"]
        self.assertFalse(final["running"])
        self.assertEqual(final["last_exit_code"], 0)
        self.assertIsNone(self.unrelated.poll())

    def test_configuration_persists_across_actual_restart(self):
        self.assertEqual(self.api("/api/v1/preferences", data={"theme": "light"})[0], 200)
        generation = self.api("/api/v1/status")[1]["generation"]
        old_token = self.session["manage_token"]
        self.stop_host()
        self.launch()
        result = self.api("/api/v1/status")[1]
        self.assertEqual(result["preferences"]["theme"], "light")
        self.assertEqual(result["generation"], generation)
        self.assertNotEqual(self.session["manage_token"], old_token)
        self.assertEqual(self.api("/api/v1/status", token=old_token)[0], 401)

    def test_configuration_and_recipe_injection_rejected(self):
        for data in ({"theme": "dark", "provider_key": "not-a-real-key"}, {"theme": "invalid"}):
            self.assertEqual(self.api("/api/v1/preferences", data=data)[0], 400)
        self.assertEqual(self.api("/api/v1/proof/start", data={"shell": "anything"})[0], 400)
        self.assertEqual(self.api("/api/v1/process/kill", data={"pid": os.getpid()})[0], 400)

    def test_concurrent_host_cannot_take_over_state(self):
        second = subprocess.run([str(EXE), "--data-dir", str(self.root)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(self.api("/api/v1/status")[0], 200)

    def test_private_descriptor_and_journal_redaction(self):
        if os.name != "nt":
            self.assertEqual(self.session_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.api("/api/v1/proof/start", data={})[0], 200)
        journal = (self.root / "events.jsonl").read_text()
        for token in (self.session["read_token"], self.session["manage_token"]):
            self.assertNotIn(token, journal)
        for line in journal.splitlines():
            self.assertEqual(json.loads(line)["api_version"], 1)

    def test_committed_corruption_fails_closed(self):
        self.api("/api/v1/preferences", data={"theme": "dark"})
        self.stop_host()
        committed = next(self.root.glob("preferences-*.json"))
        committed.write_text("corrupted acceptance fixture")
        restart = subprocess.run([str(EXE), "--data-dir", str(self.root)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(restart.returncode, 0)

    def test_interrupted_staging_is_reported_and_not_silently_applied(self):
        self.stop_host()
        (self.root / "preferences-00000000000000000001.pending").write_text('{"theme":"light"}')
        self.launch()
        result = self.api("/api/v1/status")[1]
        self.assertEqual(result["interrupted_staging_files"], 1)
        self.assertEqual(result["preferences"]["theme"], "dark")
        self.assertEqual(self.api("/api/v1/preferences", data={"theme": "light"})[0], 500)

    def test_native_identity_hardware_paths_and_unmanaged_components(self):
        result = self.api("/api/v1/components")[1]
        identity = result["host"]["identity"]
        import hashlib
        self.assertEqual(identity["sha256"], hashlib.sha256(EXE.read_bytes()).hexdigest())
        self.assertEqual(identity["bytes"], EXE.stat().st_size)
        for application in result["applications"]:
            self.assertFalse(application["managed"])
            self.assertFalse(application["launch_authorized"])
            self.assertIsNone(application["healthy"])
            self.assertEqual(application["installation_qualification"], "UNAVAILABLE")
        paths = self.api("/api/v1/paths")[1]["paths"]
        for key in ("data", "config", "cache"):
            self.assertTrue(Path(paths[key]).is_absolute())
        self.assertFalse(paths["writes_performed"])
        hardware = self.api("/api/v1/hardware")[1]["observation"]
        self.assertIsNone(hardware["network"]["available"])
        if sys.platform.startswith("linux"):
            self.assertGreater(hardware["memory"]["total_bytes"], 0)
        self.assertIn(hardware["gpu"]["confidence"], {"observed", "unknown"})
        self.assertIsInstance(hardware["gpu"]["devices"], list)

    def test_recovery_requires_exact_explicit_authorized_plan(self):
        self.api("/api/v1/preferences", data={"theme":"light"})
        self.stop_host()
        pending = self.root / "preferences-00000000000000000002.pending"
        pending.write_text('{"theme":"dark"}')
        self.launch()
        plan = self.api("/api/v1/recovery/plan")[1]
        self.assertTrue(plan["executable"])
        payload = {"plan_id":plan["plan_id"], "approved":True}
        self.assertEqual(self.api("/api/v1/recovery/approve",data=payload,token="read")[0],403)
        self.assertEqual(self.api("/api/v1/recovery/approve",data={**payload,"approved":False})[0],403)
        self.assertEqual(self.api("/api/v1/recovery/approve",data={**payload,"plan_id":"wrong"})[0],409)
        pending.write_text('{"theme":"light"}')
        self.assertEqual(self.api("/api/v1/recovery/approve",data=payload)[0],409)
        plan = self.api("/api/v1/recovery/plan")[1]
        self.assertEqual(self.api("/api/v1/recovery/approve",data={"plan_id":plan["plan_id"],"approved":True})[0],200)
        status = self.api("/api/v1/status")[1]
        self.assertEqual(status["interrupted_staging_files"],0)
        self.assertEqual(status["preferences"]["theme"],"light")
        self.assertEqual(status["generation"],1)
        self.assertEqual(len(list(self.root.glob("quarantine-*/*.pending"))),1)
        self.assertEqual(self.api("/api/v1/preferences",data={"theme":"dark"})[0],200)
        events = self.api("/api/v1/events")[1]["events"]
        self.assertIn("recovery.verified",[event["event"] for event in events])

    def test_new_interruption_and_journal_corruption_are_observed(self):
        pending = self.root / "preferences-00000000000000000001.pending"
        pending.write_text('{"theme":"light"}')
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            if self.api("/api/v1/status")[1]["interrupted_staging_files"] == 1:
                break
            time.sleep(0.02)
        else:
            self.fail("An interruption appearing after startup was not observed")
        with (self.root/"events.jsonl").open("a") as journal:journal.write("invalid journal acceptance record\n")
        self.assertEqual(self.api("/api/v1/events")[1]["malformed_records"],1)

    @unittest.skipUnless(os.name == "posix", "Signal shutdown needs native destination execution")
    def test_signal_shutdown_reaps_only_the_owned_child(self):
        self.unrelated = subprocess.Popen([sys.executable,"-c","import sys; sys.stdin.read()"],stdin=subprocess.PIPE)
        self.api("/api/v1/proof/start",data={})
        self.host.terminate()
        self.host.wait(timeout=5)
        self.assertEqual(self.host.returncode,0)
        self.assertIsNone(self.unrelated.poll())
        self.host.stdout.close(); self.host.stderr.close(); self.host=None
        self.assertIn("host.signal_shutdown",(self.root/"events.jsonl").read_text())

    @unittest.skipUnless(os.name == "posix", "Windows unexpected-exit injection needs a native Windows runner")
    def test_unexpected_owned_exit_is_not_healthy(self):
        self.api("/api/v1/proof/start", data={})
        pid = self.api("/api/v1/status")[1]["owned_process"]["pid"]
        os.kill(pid, signal.SIGTERM)  # Exact fixture child created in this isolated test.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.api("/api/v1/status")[1]["owned_process"]
            if not result["running"]:
                self.assertTrue(result["failed"])
                self.assertIsNone(result["healthy"])
                return
            time.sleep(0.02)
        self.fail("Owned child exit was not observed")


if __name__ == "__main__":
    if not str(EXE) or not EXE.is_file():
        print(json.dumps({"result": "BLOCKED", "reason": "A real built native host is required", "tests_executed": 0}))
        raise SystemExit(2)
    EXE = EXE.resolve()
    unittest.main()
