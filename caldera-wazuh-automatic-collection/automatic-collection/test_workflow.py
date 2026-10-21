"""Offline regression tests; fixtures are synthetic and do not contact any server."""
import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch
import remote_collect
from match_results import correlate

START = '2020-01-02T00:00:00+00:00'
END = '2020-01-02T00:05:00+00:00'

def report():
    return {'name':'test', 'finish':END, 'host_group':[{'paw':'a','host':'Test','host_ip_addrs':['10.0.0.1']}],
            'steps':{'a':{'steps':[{'link_id':'one','name':'discovery','command':'tasklist /m','pid':100,
             'status':0,'delegated':START,'run':'2020-01-02T00:01:00Z'}]}}}

def event():
    return {'id':'record-1','timestamp':'2020-01-02T00:01:00Z','agent':{'id':'002','name':'Test','ip':'10.0.0.1'},
            'data':{'win':{'system':{'eventID':'1','providerName':'Microsoft-Windows-Sysmon','systemTime':'2020-01-02T00:00:59Z'},
             'eventdata':{'processId':'100','parentProcessId':'50','commandLine':'powershell.exe -C tasklist /m'}}},
            'rule':{'id':'0','description':'An archive rule is not an alert'}}

def export(records, archive=False, status='success'):
    return {'collection_status':status,'agent_id':'002','start':START,'end':END,
            ('event_count' if archive else 'alert_count'):len(records), ('events' if archive else 'alerts'):records}

def scheduled_report():
    rep=report()
    rep['steps']['a']['steps']=[
        {'link_id':'create','name':'create task','command':r'schtasks.exe /Create /TN "Lab" /TR "C:\Windows\System32\cmd.exe /c mkdir C:\BASLab\done" /SC ONLOGON',
         'pid':100,'status':0,'delegated':START,'run':'2020-01-02T00:01:00Z'},
        {'link_id':'run','name':'run task','command':'schtasks.exe /Run /TN "Lab"',
         'pid':200,'status':0,'delegated':'2020-01-02T00:01:05Z','run':'2020-01-02T00:01:15Z'}]
    return rep

def scheduled_action_event():
    e=event()
    e['timestamp']='2020-01-02T00:01:11Z'
    e['data']['win']['system']['systemTime']='2020-01-02T00:01:10Z'
    e['data']['win']['eventdata']={
        'processId':'300','parentProcessId':'400',
        'image':r'C:\Windows\System32\cmd.exe',
        'commandLine':r'"C:\Windows\System32\cmd.exe" /c mkdir C:\BASLab\done',
        'parentImage':r'C:\Windows\System32\svchost.exe',
        'parentCommandLine':r'C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule'}
    e['rule']={'id':'92052','description':'Generic command prompt alert'}
    return e

class RegressionTests(unittest.TestCase):
    def result(self, alerts=None, archives=None, rep=None):
        return correlate(rep or report(), export(alerts or []), '002', archives=archives)['results'][0]

    def test_archive_confirms_collection_not_detection(self):
        row=self.result(archives=export([event()],True))
        self.assertEqual(row['event_collection'],'confirmed')
        self.assertEqual(row['detection'],'no_matching_alert_observed')
        self.assertEqual(row['matched_archive_event_count'],1)
        self.assertEqual(row['rule_ids'],'')
        self.assertNotIn('rule_id',row['archive_evidence'][0])

    def test_alert_confirms_even_when_archives_unavailable(self):
        row=self.result([event()],export([],True,'unavailable'))
        self.assertEqual(row['detection'],'observed')
        self.assertEqual(row['collection_evidence_sources'],'alerts')
        self.assertEqual(row['event_collection'],'confirmed')

    def test_empty_error_missing_sources_do_not_claim_missed(self):
        for archive in (None,export([],True),export([],True,'error'),export([],True,'unavailable')):
            row=self.result(archives=archive)
            self.assertEqual(row['event_collection'],'not_confirmed')
            self.assertEqual(row['detection'],'no_matching_alert_observed')

    def test_ambiguous_archive_does_not_confirm(self):
        rep=report(); rep['steps']['a']['steps'].append(copy.deepcopy(rep['steps']['a']['steps'][0]))
        row=self.result(archives=export([event()],True),rep=rep)
        self.assertEqual(row['event_collection'],'ambiguous_review')
        self.assertEqual(row['matched_archive_event_count'],0)

    def test_agent_and_window_mismatch_rejected(self):
        for key,value in [('agent_id','001'),('end','2020-01-02T00:06:00Z')]:
            archive=export([event()],True); archive[key]=value
            with self.assertRaises(ValueError): self.result(archives=archive)

    def test_child_matches_but_grandchild_does_not(self):
        e=event(); e['data']['win']['eventdata'].update(processId='200',parentProcessId='100',commandLine='tasklist.exe /m',parentCommandLine='powershell -C tasklist /m')
        self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],1)
        e['data']['win']['eventdata']['parentProcessId']='200'
        self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],0)

    def test_wrong_host_time_and_pid_do_not_match(self):
        for category in ('host','time','pid'):
            e=event()
            if category=='host': e['agent']['name']='Other'
            if category=='time': e['data']['win']['system']['systemTime']='2020-01-01T20:00:00Z'
            if category=='pid': e['data']['win']['eventdata']['processId']='999'
            self.assertEqual(self.result(archives=export([e],True))['event_collection'],'not_confirmed')

    def test_registered_scheduled_action_matches_scheduler_spawned_alert(self):
        e=scheduled_action_event()
        rows=correlate(scheduled_report(),export([e]),'002',archives=export([e],True))['results']
        self.assertEqual(rows[0]['detection'],'no_matching_alert_observed')
        self.assertEqual(rows[1]['detection'],'observed')
        self.assertEqual(rows[1]['rule_ids'],'92052')
        self.assertEqual(rows[1]['matched_archive_event_count'],1)
        self.assertEqual(rows[1]['evidence'][0]['relation'],'scheduled_task_action')
        self.assertEqual(rows[1]['evidence'][0]['task_name'],'Lab')

    def test_scheduled_action_requires_name_action_parent_and_time(self):
        for mismatch in ('name','action','parent','time'):
            rep=scheduled_report(); e=scheduled_action_event()
            if mismatch=='name': rep['steps']['a']['steps'][1]['command']='schtasks.exe /Run /TN "Other"'
            if mismatch=='action': e['data']['win']['eventdata']['commandLine']=r'"C:\Windows\System32\cmd.exe" /c mkdir C:\BASLab\other'
            if mismatch=='parent': e['data']['win']['eventdata']['parentCommandLine']=r'C:\Windows\System32\svchost.exe -k netsvcs -p -s Other'
            if mismatch=='time': e['data']['win']['system']['systemTime']='2020-01-02T00:02:00Z'
            row=correlate(rep,export([e]),'002')['results'][1]
            self.assertEqual(row['detection'],'no_matching_alert_observed',mismatch)

    def test_overlapping_scheduled_runs_remain_ambiguous(self):
        rep=scheduled_report()
        second=copy.deepcopy(rep['steps']['a']['steps'][1]); second['link_id']='run2'; second['pid']=201
        rep['steps']['a']['steps'].append(second)
        rows=correlate(rep,export([scheduled_action_event()]),'002')['results']
        self.assertEqual(rows[1]['detection'],'ambiguous_review')
        self.assertEqual(rows[2]['detection'],'ambiguous_review')

    def test_rotated_gzip_dedup_and_endpoint_filter(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); folder=root/'2020'/'Jan'; folder.mkdir(parents=True)
            e=event(); other=copy.deepcopy(e); other['agent']['id']='001'; other['id']='other'
            same_id=copy.deepcopy(e)
            same_id['data']['win']['system']['eventRecordID']='31221'
            same_id['data']['win']['eventdata']['image']=r'C:\BASLab\masquerade-test\lab-helper.exe'
            (root/'archives.json').write_text(json.dumps(e)+'\n'+json.dumps(same_id)+'\n'+json.dumps(other)+'\n')
            with gzip.open(folder/'ossec-archive-02.json.gz','wt') as f: f.write(json.dumps(e)+'\n')
            result=remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')
            self.assertEqual(result['event_count'],2)
            self.assertEqual({item['data']['win']['eventdata'].get('image') for item in result['events']},
                             {None,r'C:\BASLab\masquerade-test\lab-helper.exe'})
            self.assertEqual(len(result['files_scanned']),2)

    def test_missing_and_corrupt_files_are_not_silent_success(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with self.assertRaises(FileNotFoundError): remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')
            (root/'archives.json').write_text('{incomplete')
            with self.assertRaises(ValueError): remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')

class OrchestrationTests(unittest.TestCase):
    def test_one_run_writes_both_sources_and_results(self):
        import argparse
        import collect_operation
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            config=root/'config.json'
            config.write_text(json.dumps({'caldera_url':'http://lab:8888','wazuh_host':'lab',
                'windows_host':'Test','wazuh_agent_id':'002'}))
            args=argparse.Namespace(config=config,list=False,operation='338ef596-0594-4935-9938-d8485c33c8f1',out=root/'run')
            rep=report(); archives=export([event()],True)
            with patch.object(collect_operation,'api',return_value=rep), \
                 patch.object(collect_operation,'connect',return_value=MagicMock()), \
                 patch.object(collect_operation.getpass,'getpass',return_value='synthetic-test-only'), \
                 patch.object(collect_operation,'remote',side_effect=[str(datetime.now(timezone.utc).timestamp()),json.dumps(export([])),json.dumps(archives)]), \
                 patch.object(collect_operation,'select_window',return_value=(remote_collect.stamp(START),remote_collect.stamp(END),[])):
                collect_operation.run(args)
            self.assertTrue((args.out/'wazuh-archives.json').exists())
            result=json.loads((args.out/'results'/'results.json').read_text())['results'][0]
            self.assertEqual(result['event_collection'],'confirmed')
            self.assertEqual(result['detection'],'no_matching_alert_observed')

if __name__=='__main__': unittest.main()
