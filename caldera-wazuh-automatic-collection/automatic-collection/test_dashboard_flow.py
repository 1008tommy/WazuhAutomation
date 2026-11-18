"""Focused checks for dashboard launch and runner failure reporting."""
import argparse
import copy
import shutil
import subprocess
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import build_dashboard
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

    def test_finished_state_waits_for_cleanup_and_report_finish(self):
        client = Mock()
        client.operation.return_value = {"state": "finished"}
        client.operation_report.side_effect = [{"finish": None}, {"finish": "2026-11-11T07:42:00Z"}]
        _, state = run_scenario.wait_for_operation(client, "operation-id", 60, poll=0,
                                                    sleeper=lambda _: None)
        self.assertEqual(state, "finished")
        self.assertEqual(client.operation_report.call_count, 2)

    def test_open_report_times_out_without_claiming_cleanup_failure(self):
        client = Mock()
        client.operation.return_value = {"state": "finished"}
        client.operation_report.return_value = {"finish": None}
        with self.assertRaisesRegex(TimeoutError, "not fully closed"):
            run_scenario.wait_for_operation(client, "operation-id", 0)


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



class CompareRunsTests(unittest.TestCase):
    specs = [{"scenario": "file-delivery", "name": "File Delivery and Execution Lab"},
             {"scenario": "discovery", "name": "Discovery"}]

    def run_data(self, day, operation, name="file-delivery", complete=True):
        stamp = f"202611{day:02}T120000Z"
        when = f"2026-11-{day:02}T12:00:00Z"
        rows = [{"operation_name": f"{name}-{stamp}", "run_utc": when, "host": "TEST-PC",
                 "execution": "reported_success", "ability_id": ability, "ability_name": ability,
                 "technique_id": technique, "outcome": outcome, "rule_ids": rule}
                for ability, technique, outcome, rule in [
                    ("File creation", "T1105", "detected_unlabelled" if day == 1 else "telemetry_only",
                     "100" if day == 1 else ""),
                    ("Execution", "T1059.001", "telemetry_only", "")]]
        return {"run_id": f"{stamp}-{operation}", "meta": {"operation_id": operation,
                "collection_complete": complete, "archive_collection_status": "success"},
                "result": {"results": rows}}

    def test_known_scenario_and_execution_identity(self):
        r = self.run_data(1, "a")
        r["run_id"] = "recollected-later"
        info = build_dashboard.comparison_metadata(r, self.specs)
        self.assertEqual(("file-delivery", "a", ["test-pc"], "2026-11-01"),
                         (info["compare_scenario"], info["operation_id"], info["hosts"], info["execution_time"][:10]))
        for step in r["result"]["results"]:
            step["operation_name"] = "file-delivery-unrelated"
        self.assertIsNone(build_dashboard.comparison_metadata(r, self.specs)["compare_scenario"])

    def test_offline_compare_controls(self):
        # Optional: Node with jsdom exercises the actual embedded dashboard script offline.
        if not shutil.which("node") or subprocess.run(
                ["node", "-e", "require.resolve('jsdom')"], capture_output=True).returncode:
            self.skipTest("Install jsdom for the optional offline dashboard interaction test")
        runs = [self.run_data(1, "opA"), self.run_data(2, "opB"), self.run_data(3, "opC", complete=False),
                self.run_data(4, "only", name="discovery")]
        recollected = copy.deepcopy(runs[0])
        recollected["run_id"] = "20261105T120000Z-opA"
        runs.append(recollected)
        runs[2]["meta"]["windows_host"] = "OTHER-PC"
        runs[2]["result"]["results"].pop()
        runs[2]["result"]["results"].append(dict(runs[2]["result"]["results"][0], ability_id="new", ability_name="New step"))
        data = build_dashboard.build_data(runs, self.specs)
        script = r"""
const assert = require("node:assert/strict");
const {JSDOM, VirtualConsole} = require("jsdom");
const errors = [], console = new VirtualConsole();
console.on("jsdomError", err => errors.push(err.message));
const {window} = new JSDOM(require("node:fs").readFileSync(0,"utf8"), {
  pretendToBeVisual:true, runScripts:"dangerously", url:"file:///saved/index.html#compare", virtualConsole:console});
const get = id => window.document.getElementById(id);
const pick = (id,v) => {const s = get(id); s.value=v; assert.equal(s.value,v); s.onchange();};
assert.deepEqual(errors, []);
assert.ok(get("view-compare").classList.contains("on"));
assert.equal(get("cmpBase").options.length, 2);
pick("cmpBase","20261105T120000Z-opA");
pick("cmpLater","20261102T120000Z-opB");
const changes = () => [...get("cmpBody").rows].map(r => r.lastElementChild.textContent);
assert.deepEqual(changes(), ["Matched alert → Telemetry only","Same evidence category"]);
pick("cmpLater","20261103T120000Z-opC");
assert.match(get("cmpNotice").textContent,/Endpoint differs/);
assert.match(get("cmpNotice").textContent,/collection completeness not confirmed/);
assert.deepEqual(changes(), ["Comparison limited","Only in baseline","Only in later run"]);
pick("cmpScenario","discovery");
assert.ok(get("cmpLater").disabled && get("cmpPanel").hidden);
assert.deepEqual(errors, []);
window.close();
"""
        subprocess.run(["node", "-e", script], input=build_dashboard.render_html(data), text=True, check=True)


if __name__ == "__main__":
    unittest.main()
