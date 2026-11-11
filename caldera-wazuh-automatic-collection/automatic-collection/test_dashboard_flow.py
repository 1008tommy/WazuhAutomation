"""Focused checks for dashboard launch and runner failure reporting."""
import argparse
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import run_scenario
import serve_dashboard


class RunnerFlowTests(unittest.TestCase):
    def run_with(self, operation_result, collector_code, builder_code=0):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({
                "caldera_url": "http://lab:8888", "windows_host": "WIN11-TEST01",
            }), encoding="utf-8")
            args = argparse.Namespace(
                config=config,
                specs=[run_scenario.HERE / "scenarios" / "discovery.json"],
                collect=True,
            )
            with patch.dict(os.environ, {"BAS_CALDERA_KEY": "synthetic-test-key"}), \
                 patch.object(run_scenario, "Caldera") as caldera, \
                 patch.object(run_scenario, "check_target"), \
                 patch.object(run_scenario, "run_one", return_value=operation_result), \
                 patch.object(run_scenario.subprocess, "run", side_effect=[
                     SimpleNamespace(returncode=collector_code),
                     SimpleNamespace(returncode=builder_code),
                 ]) as child:
                caldera.return_value.health.return_value = True
                with self.assertRaises(ValueError) as raised:
                    run_scenario.run(args)
                return str(raised.exception), child.call_args_list

    def test_collection_failure_is_visible_and_dashboard_is_not_rebuilt(self):
        message, calls = self.run_with(("op-id", "finished", True), 1)
        self.assertIn("collection and scoring failed", message)
        self.assertEqual(len(calls), 1)

    def test_failed_cleanup_is_visible_even_when_collection_succeeds(self):
        message, calls = self.run_with(("op-id", "finished", False), 0)
        self.assertIn("cleanup failed", message)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].kwargs["cwd"], str(run_scenario.HERE))

    def test_dashboard_rebuild_failure_is_visible(self):
        message, _ = self.run_with(("op-id", "finished", True), 0, 1)
        self.assertIn("dashboard rebuild failed", message)

    def test_thief_source_is_resolved_by_name_when_bundle_id_differs(self):
        spec = run_scenario.load_spec(run_scenario.HERE / "scenarios" / "thief-lab.json")
        client = Mock()
        client.get.return_value = [
            {"id": "basic-id", "name": "basic", "facts": [
                {"trait": "file.sensitive.extension", "value": "png"}]},
            {"id": "installed-thief-id", "name": "Thief-Lab", "facts": [
                {"trait": "file.sensitive.extension", "value": "txt"}]},
        ]
        self.assertEqual(run_scenario.resolve_source(client, spec), "installed-thief-id")

    def test_caldera_basic_fallback_is_reported_as_an_error(self):
        spec = run_scenario.load_spec(run_scenario.HERE / "scenarios" / "thief-lab.json")
        client = Mock()
        client.adversary.return_value = {"name": "Thief-Lab"}
        client.planner_id.return_value = "atomic-id"
        client.get.return_value = [{"id": "installed-thief-id", "name": "Thief-Lab", "facts": [
            {"trait": "file.sensitive.extension", "value": "txt"}]}]
        client.create_operation.return_value = {"id": "operation-id", "source": {"id": "basic-id", "name": "basic"}}
        with self.assertRaisesRegex(ValueError, "selected fact source 'basic'"):
            run_scenario.run_one(client, spec, "red", "WIN11-TEST01", {})


class DashboardLaunchTests(unittest.TestCase):
    def request(self):
        body = b'{"scenario":"discovery"}'
        handler = object.__new__(serve_dashboard.Handler)
        handler.path = "/api/launch"
        handler.headers = {"Content-Length": str(len(body))}
        handler.rfile = io.BytesIO(body)
        responses = []
        handler._send = lambda code, payload, ctype="application/json": responses.append((code, payload))
        return handler, responses

    def test_missing_config_is_reported_before_launch(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(serve_dashboard, "CONFIG", Path(directory) / "config.json"), \
             patch.object(serve_dashboard, "valid_scenarios", return_value={"discovery"}):
            handler, responses = self.request()
            handler.do_POST()
        self.assertEqual(responses[0][0], 503)

    def test_second_scenario_cannot_start_during_active_run(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "config.json").write_text("{}", encoding="utf-8")
            with patch.object(serve_dashboard, "CONFIG", Path(directory) / "config.json"), \
                 patch.object(serve_dashboard, "valid_scenarios", return_value={"discovery"}), \
                 patch.dict(serve_dashboard.JOBS, {"first": {"state": "running"}}, clear=True):
                handler, responses = self.request()
                handler.do_POST()
                self.assertEqual(responses[0][0], 409)
                self.assertEqual(json.loads(responses[0][1])["job"], "first")
                self.assertEqual(set(serve_dashboard.JOBS), {"first"})

    def test_page_reconnects_to_a_running_job(self):
        with patch.dict(serve_dashboard.JOBS, {"first": {"state": "running"}}, clear=True):
            page = serve_dashboard.render_page()
        self.assertIn(b'"active_job": "first"', page)

    def test_runner_receives_selected_config_path(self):
        selected = Path("C:/external/config.json")
        process = SimpleNamespace(stdout=iter(["finished\n"]), returncode=0)
        process.wait = lambda: None
        with patch.object(serve_dashboard, "CONFIG", selected), \
             patch.dict(serve_dashboard.JOBS, {"job": {"state": "running", "log": []}}, clear=True), \
             patch.object(serve_dashboard.subprocess, "Popen", return_value=process) as child:
            serve_dashboard.run_job("job", "discovery")
            command = child.call_args.args[0]
            self.assertEqual(command[command.index("--config") + 1], str(selected))
            self.assertEqual(serve_dashboard.JOBS["job"]["state"], "done")

    def test_launch_creates_trackable_job(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "config.json").write_text("{}", encoding="utf-8")
            with patch.object(serve_dashboard, "CONFIG", Path(directory) / "config.json"), \
                 patch.object(serve_dashboard, "valid_scenarios", return_value={"discovery"}), \
                 patch.dict(serve_dashboard.JOBS, {}, clear=True), \
                 patch.object(serve_dashboard.threading, "Thread") as worker:
                handler, responses = self.request()
                handler.do_POST()
                self.assertEqual(responses[0][0], 200)
                job = json.loads(responses[0][1])["job"]
                self.assertEqual(serve_dashboard.JOBS[job]["state"], "running")
                worker.return_value.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
