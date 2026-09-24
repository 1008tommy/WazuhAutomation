"""Offline checks; no connection to lab VMs."""
import copy
import importlib.util
import json
import tempfile
import unittest
import gzip
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import collect_operation as runner
import remote_collect
from match_results import correlate

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        p=Path(__file__).parent/"test-fixtures"
        self.report=json.loads((p/"caldera-report.json").read_text())
        self.alerts=json.loads((p/"wazuh-alerts.json").read_text())
        self.closed=copy.deepcopy(self.report)
        self.closed["finish"]="2026-09-24T02:35:38Z"

    def test_window_and_output_request(self):
        start,end,steps=runner.select_window(self.closed,"Test")
        self.assertEqual(start.isoformat(),"2026-09-24T02:34:55+00:00")
        self.assertEqual(end.isoformat(),"2026-09-24T02:37:07+00:00")
        self.assertEqual(len(steps),1)

    def test_open_operation_rejected(self):
        with self.assertRaises(ValueError):
            runner.select_window(self.report,"Test")

    def test_no_finished_step_rejected(self):
        self.closed["steps"]["hotwzy"]["steps"][0]["run"]=None
        with self.assertRaises(ValueError):
            runner.select_window(self.closed,"Test")

    def test_match_and_wrong_pid(self):
        r=correlate(self.report,self.alerts,"001",host_filter="Test")
        self.assertEqual(r["results"][0]["matched_alert_count"],2)
        wrong=copy.deepcopy(self.alerts)
        for a in wrong["alerts"]:
            e=a["data"]["win"]["eventdata"]
            e["processId"]=e["parentProcessId"]="9999"
        self.assertEqual(correlate(self.report,wrong,"001")["results"][0]["matched_alert_count"],0)

    def test_api_request_shape(self):
        class Reply:
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def read(self): return b'{"steps": {}}'
        class Opener:
            def open(self,request,timeout):
                self.request=request
                return Reply()
        opener=Opener()
        with patch.object(runner,"build_opener",return_value=opener):
            runner.api("http://127.0.0.1:8888","test-key","operations/abc/report",
                       {"enable_agent_output":True})
        self.assertEqual(opener.request.method,"POST")
        self.assertEqual(json.loads(opener.request.data),{"enable_agent_output":True})
        self.assertEqual(opener.request.full_url,"http://127.0.0.1:8888/api/v2/operations/abc/report")

    def test_remote_rotation_dedup_and_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            past=datetime.now(timezone.utc)-timedelta(minutes=5)
            data=copy.deepcopy(self.alerts["alerts"][0])
            data["timestamp"]=past.isoformat()
            raw=(json.dumps(data)+"\n").encode()
            (root/"alerts.json").write_bytes(raw)
            month="Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[past.month-1]
            daily=root/str(past.year)/month
            daily.mkdir(parents=True)
            with gzip.open(daily/f"ossec-alerts-{past.day:02}.json.gz","wb") as f: f.write(raw)
            result=remote_collect.collect(root,"001",past-timedelta(seconds=1),past+timedelta(seconds=1))
            self.assertEqual(result["alert_count"],1)
            self.assertEqual(len(result["files_scanned"]),2)
            (root/"alerts.json").write_text('{"broken":')
            with self.assertRaises(ValueError):
                remote_collect.collect(root,"001",past-timedelta(seconds=1),past+timedelta(seconds=1))

    def test_complete_workflow_mock_transports(self):
        class Client:
            def close(self): pass
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            config=root/"config.json"
            config.write_text(json.dumps({
                "caldera_url":"http://127.0.0.1:8888","windows_host":"Test",
                "wazuh_agent_id":"001","wazuh_host":"127.0.0.1","wazuh_user":"test"}))
            import argparse
            args=argparse.Namespace(config=config,list=False,
                    operation="11111111-1111-4111-8111-111111111111",out=root/"run")
            with patch.object(runner,"api",return_value=self.closed), patch.object(runner,"connect",return_value=Client()), patch.object(runner.getpass,"getpass",return_value="test-only"), patch.object(runner,"remote",side_effect=[str(datetime.now(timezone.utc).timestamp()),json.dumps(self.alerts)]), patch.object(runner.time,"sleep"):
                # Use fixture-based past dates relative to environment so no real waits.
                with patch.object(runner,"datetime") as dt:
                    dt.now.return_value=datetime(2026,9,25,tzinfo=timezone.utc)
                    # remote clock check follows the mocked clock too.
                    with patch.object(runner,"remote",side_effect=[str(datetime(2026,9,25,tzinfo=timezone.utc).timestamp()),json.dumps(self.alerts)]):
                        runner.run(args)
            result=json.loads((root/"run/results/results.json").read_text())
            self.assertEqual(result["results"][0]["matched_alert_count"],2)

if __name__=="__main__":
    unittest.main()
