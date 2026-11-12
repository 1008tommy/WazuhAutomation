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
            'data':{'win':{'system':{'eventID':'1','providerName':'Microsoft-Windows-Sysmon','systemTime':'2020-01-02T00:00:59Z','computer':'Test'},
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

def download_report():
    rep=report()
    rep['steps']['a']['steps'][0].update(
        name='download lab script',
        command=r"Invoke-WebRequest -Uri 'http://lab/file/download' -OutFile $path",
        attack={'technique_id':'T1105'},
        output={'stdout':r'C:\BASLab\delivery-test\lab-note.ps1'})
    return rep

def file_creation_event():
    e=event()
    e['data']['win']['system']['eventID']='11'
    e['data']['win']['eventdata']={
        'processId':'100','processGuid':'{test-guid}',
        'image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        'targetFilename':r'C:\BASLab\delivery-test\lab-note.ps1'}
    e['rule']={'id':'92203','description':'Executable file created by powershell'}
    return e

def renamed_utility_report():
    rep=report()
    rep['steps']['a']['steps'][0].update(
        name='stage renamed lab utility',
        command=(r"$dir='C:\BASLab\masquerade-test'; $dst=Join-Path $dir 'lab-helper.exe'; "
                 r"Copy-Item -LiteralPath 'C:\Windows\System32\whoami.exe' -Destination $dst; "
                 r"Get-Item -LiteralPath $dst | Select-Object FullName,Length"),
        attack={'technique_id':'T1036.003'},
        output={'stdout':'FullName Length\n-------- ------\n'
                         'C:\\BASLab\\masquerade-test\\lab-helper.exe 98304'})
    return rep

def renamed_utility_file_event():
    e=file_creation_event()
    e['data']['win']['eventdata']['targetFilename']=r'C:\BASLab\masquerade-test\lab-helper.exe'
    return e

def scriptblock_event(text='tasklist /m', pid='100', mitre=None, rule_id='91815', level=4):
    e=event()
    e['data']['win']['system']['eventID']='4104'
    e['data']['win']['system']['providerName']='Microsoft-Windows-PowerShell'
    e['data']['win']['system']['processID']=pid
    e['data']['win']['eventdata']={'scriptBlockText':text}
    rule={'id':rule_id,'description':'PowerShell script block executed','level':level}
    if mitre is not None:
        rule['mitre']={'id':mitre if isinstance(mitre,list) else [mitre]}
    e['rule']=rule
    return e

def tagged_report(technique='T1057'):
    rep=report()
    rep['steps']['a']['steps'][0]['attack']={'technique_id':technique}
    return rep

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
            if category=='host': e['data']['win']['system']['computer']='Other'
            if category=='time': e['data']['win']['system']['systemTime']='2020-01-01T20:00:00Z'
            if category=='pid': e['data']['win']['eventdata']['processId']='999'
            self.assertEqual(self.result(archives=export([e],True))['event_collection'],'not_confirmed')

    def test_custom_agent_name_uses_windows_computer_and_legacy_fallback(self):
        e=event(); e['agent']['name']='CustomEnrollmentName'
        self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],1)
        del e['data']['win']['system']['computer']
        self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],0)
        e['agent']['name']='Test'
        self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],1)

    def test_agent_id_and_ip_still_required_with_custom_name(self):
        for field, value in (('id','001'),('ip','10.0.0.2')):
            e=event(); e['agent']['name']='CustomEnrollmentName'; e['agent'][field]=value
            self.assertEqual(self.result(archives=export([e],True))['matched_archive_event_count'],0)

    def test_registered_scheduled_action_matches_scheduler_spawned_alert(self):
        e=scheduled_action_event()
        rows=correlate(scheduled_report(),export([e]),'002',archives=export([e],True))['results']
        self.assertEqual(rows[0]['detection'],'no_matching_alert_observed')
        self.assertEqual(rows[1]['detection'],'observed')
        self.assertEqual(rows[1]['rule_ids'],'92052')
        self.assertEqual(rows[1]['matched_archive_event_count'],1)
        self.assertEqual(rows[1]['evidence'][0]['relation'],'scheduled_task_action')
        self.assertEqual(rows[1]['evidence'][0]['task_name'],'Lab')

    def test_t1105_file_creation_matches_exact_output_path_and_executor(self):
        e=file_creation_event()
        row=self.result([e],export([e],True),download_report())
        self.assertEqual(row['detection'],'observed')
        self.assertEqual(row['rule_ids'],'92203')
        self.assertEqual(row['matched_archive_event_count'],1)
        self.assertEqual(row['evidence'][0]['relation'],'file_created_by_executor')
        self.assertEqual(row['evidence'][0]['target_filename'],r'C:\BASLab\delivery-test\lab-note.ps1')

    def test_t1105_file_creation_rejects_other_pid_path_or_technique(self):
        for mismatch in ('pid','path','technique','output'):
            rep=download_report(); e=file_creation_event()
            if mismatch=='pid': e['data']['win']['eventdata']['processId']='999'
            if mismatch=='path': e['data']['win']['eventdata']['targetFilename']=r'C:\BASLab\delivery-test\other.ps1'
            if mismatch=='technique': rep['steps']['a']['steps'][0]['attack']['technique_id']='T1059.001'
            if mismatch=='output': rep['steps']['a']['steps'][0].pop('output')
            row=self.result([e],rep=rep)
            self.assertEqual(row['detection'],'no_matching_alert_observed',mismatch)

    def test_renamed_utility_staging_matches_reported_file_and_executor(self):
        e=renamed_utility_file_event()
        row=self.result([e],export([e],True),renamed_utility_report())
        self.assertEqual(row['detection'],'observed')
        self.assertEqual(row['rule_ids'],'92203')
        self.assertEqual(row['matched_archive_event_count'],1)
        self.assertEqual(row['evidence'][0]['relation'],'file_created_by_executor')

    def test_renamed_utility_staging_rejects_unrelated_file_events(self):
        for mismatch in ('pid','path','technique','command','output','status','path_suffix'):
            rep=renamed_utility_report(); e=renamed_utility_file_event()
            step=rep['steps']['a']['steps'][0]
            if mismatch=='pid': e['data']['win']['eventdata']['processId']='999'
            if mismatch=='path': e['data']['win']['eventdata']['targetFilename']=r'C:\BASLab\masquerade-test\other.exe'
            if mismatch=='technique': step['attack']['technique_id']='T1059.001'
            if mismatch=='command': step['command']='Get-Item -LiteralPath $dst'
            if mismatch=='output': step.pop('output')
            if mismatch=='status': step['status']=1
            if mismatch=='path_suffix': e['data']['win']['eventdata']['targetFilename']+= '.bak'
            row=self.result([e],rep=rep)
            self.assertEqual(row['detection'],'no_matching_alert_observed',mismatch)

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

    def test_live_file_partial_tail_keeps_complete_records_and_marks_gap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'archives.json').write_text(json.dumps(event())+'\n'+json.dumps(event())[:20])
            result=remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')
            self.assertEqual(result['event_count'],1)
            self.assertEqual(result['incomplete_tail_files'],[str(root/'archives.json')])
            self.assertIn('unfinished_trailing_line_skipped',result['completeness'])

    def test_malformed_complete_line_and_rotated_tail_still_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'archives.json').write_text(json.dumps(event())+'\n{incomplete\n')
            with self.assertRaises(ValueError): remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')
            (root/'archives.json').unlink()
            folder=root/'2020'/'Jan'; folder.mkdir(parents=True)
            (folder/'ossec-archive-02.json').write_text(json.dumps(event())+'\n{incomplete')
            with self.assertRaises(ValueError): remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')

    def test_live_file_complete_record_without_timestamp_still_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'archives.json').write_text(json.dumps(event())+'\n'+json.dumps({'agent':{'id':'002'}}))
            with self.assertRaises(ValueError): remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'archives')

    def test_event_time_filter_keeps_lagged_alert_and_tracks_watermark(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            lagged=event(); lagged['timestamp']='2020-01-02T00:21:00Z'   # event in window, ingested 20 min late
            future=event(); future['id']='future'; future['timestamp']='2020-01-02T00:30:00Z'
            future['data']['win']['system']['systemTime']='2020-01-02T00:10:00Z'   # occurs after window end
            (root/'alerts.json').write_text(json.dumps(lagged)+'\n'+json.dumps(future)+'\n')
            result=remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'alerts')
            self.assertEqual(result['alert_count'],1)                                 # only the in-window event
            self.assertEqual(result['agent_watermark'],'2020-01-02T00:10:00+00:00')   # watermark passed the window end

    def test_queue_saturation_rules_are_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            q=event(); q['id']='q'; q['rule']={'id':'203','description':'Events may be lost'}
            (root/'alerts.json').write_text(json.dumps(q)+'\n')
            result=remote_collect.collect(root,'002',remote_collect.stamp(START),remote_collect.stamp(END),'alerts')
            self.assertEqual(result['queue_alert_rule_ids'],['203'])

    def test_powershell_4104_matches_by_process_id(self):
        self.assertEqual(self.result([scriptblock_event(pid='100')],rep=tagged_report('T1082'))['evidence'][0]['relation'],'powershell_scriptblock')
        self.assertEqual(self.result([scriptblock_event(pid='999')],rep=tagged_report('T1082'))['detection'],'no_matching_alert_observed')

    def test_outcome_labelled_related_and_unlabelled(self):
        self.assertEqual(self.result([scriptblock_event(mitre='T1057')],rep=tagged_report('T1057'))['outcome'],'detected_labelled')
        row=self.result([scriptblock_event(mitre='T1087')],rep=tagged_report('T1087.001'))
        self.assertEqual((row['outcome'],row['technique_match']),('detected_labelled','related'))
        self.assertEqual(self.result([scriptblock_event(mitre='T1082')],rep=tagged_report('T1033'))['outcome'],'detected_unlabelled')

    def test_outcome_telemetry_only_from_archive(self):
        e=scriptblock_event()
        self.assertEqual(self.result(archives=export([e],True),rep=tagged_report('T1057'))['outcome'],'telemetry_only')

    def test_harness_artifact_excluded_from_scoring(self):
        row=self.result([scriptblock_event(text=r'C:\Users\u\AppData\Local\Temp\__PSScriptPolicyTest_x.ps1')],rep=tagged_report('T1057'))
        self.assertEqual(row['detection'],'no_matching_alert_observed')
        self.assertEqual(row['harness_alert_rule_ids'],'91815')
        self.assertEqual(self.result([scriptblock_event(rule_id='92213')],rep=tagged_report('T1057'))['detection'],'no_matching_alert_observed')

    def test_outcome_missed_requires_complete_collection(self):
        done=export([]); done['agent_watermark']='2020-01-02T00:06:00+00:00'; done['queue_alert_rule_ids']=[]
        self.assertEqual(correlate(tagged_report('T1057'),done,'002',archives=export([],True))['results'][0]['outcome'],'missed')
        partial=export([]); partial['agent_watermark']='2020-01-02T00:04:00+00:00'; partial['queue_alert_rule_ids']=[]
        self.assertEqual(correlate(tagged_report('T1057'),partial,'002',archives=export([],True))['results'][0]['outcome'],'not_assessable')

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
            alerts=export([]); alerts['agent_watermark']=END; alerts['queue_alert_rule_ids']=[]
            with patch.object(collect_operation,'api',return_value=rep), \
                 patch.object(collect_operation,'connect',return_value=MagicMock()), \
                 patch.object(collect_operation.getpass,'getpass',return_value='synthetic-test-only'), \
                 patch.object(collect_operation,'remote',side_effect=[str(datetime.now(timezone.utc).timestamp()),json.dumps(alerts),json.dumps(archives)]), \
                 patch.object(collect_operation,'select_window',return_value=(remote_collect.stamp(START),remote_collect.stamp(END),[])):
                collect_operation.run(args)
            self.assertTrue((args.out/'wazuh-archives.json').exists())
            result=json.loads((args.out/'results'/'results.json').read_text())['results'][0]
            self.assertEqual(result['event_collection'],'confirmed')
            self.assertEqual(result['detection'],'no_matching_alert_observed')

    def test_archive_progress_ends_wait_without_claiming_alert_completeness(self):
        import argparse
        import collect_operation
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            config=root/'config.json'
            config.write_text(json.dumps({'caldera_url':'http://lab:8888','wazuh_host':'lab',
                'windows_host':'Test','wazuh_agent_id':'002'}))
            args=argparse.Namespace(config=config,list=False,
                operation='338ef596-0594-4935-9938-d8485c33c8f1',out=root/'run')
            alerts=export([]); alerts['agent_watermark']='2020-01-02T00:04:00+00:00'
            archives=export([],True); archives['agent_watermark']='2020-01-02T00:06:00+00:00'
            with patch.object(collect_operation,'api',return_value=report()), \
                 patch.object(collect_operation,'connect',return_value=MagicMock()), \
                 patch.object(collect_operation.getpass,'getpass',return_value='synthetic-test-only'), \
                 patch.object(collect_operation,'remote',side_effect=[str(datetime.now(timezone.utc).timestamp()),
                     json.dumps(alerts),json.dumps(archives)]), \
                 patch.object(collect_operation,'select_window',return_value=(remote_collect.stamp(START),remote_collect.stamp(END),[])):
                collect_operation.run(args)
            metadata=json.loads((args.out/'run-metadata.json').read_text())
            result=json.loads((args.out/'results'/'results.json').read_text())['results'][0]
            self.assertEqual(metadata['collection_stop_reason'],'archive_watermark')
            self.assertFalse(metadata['collection_complete'])
            self.assertEqual(result['outcome'],'not_assessable')

class ScenarioRunnerTests(unittest.TestCase):
    def test_validate_spec_rejects_evasion_and_bad_fields(self):
        import run_scenario
        good={'scenario':'discovery','name':'D','adversary_id':'c6946236-d4e4-4e4f-8dc7-433c84a702a3','planner':'atomic'}
        run_scenario.validate_spec(good)
        for bad in [dict(good,obfuscator='base64'),dict(good,platform='linux'),
                    {k:v for k,v in good.items() if k!='adversary_id'},dict(good,adversary_id='nope')]:
            with self.assertRaises(ValueError): run_scenario.validate_spec(bad)

    def test_installed_specs_load_and_are_plain_text(self):
        import run_scenario
        for name in ('discovery','scheduled-task','renamed-utility','file-delivery','thief-lab'):
            spec=run_scenario.load_spec(run_scenario.HERE/'scenarios'/f'{name}.json')
            self.assertEqual(spec['obfuscator'],'plain-text')

    def test_check_target_allows_only_configured_host(self):
        import run_scenario
        now=datetime(2020,1,2,0,5,0,tzinfo=timezone.utc)
        ok=[{'paw':'tkjszy','group':'red','host':'WIN11-TEST01','trusted':True,'last_seen':'2020-01-02T00:04:30Z'}]
        self.assertEqual(run_scenario.check_target(ok,'red','WIN11-TEST01',now=now)['paw'],'tkjszy')
        for bad in [ok+[{'paw':'x','group':'red','host':'OTHER','trusted':True,'last_seen':'2020-01-02T00:04:30Z'}],
                    [dict(ok[0],trusted=False)],[dict(ok[0],last_seen='2020-01-02T00:00:00Z')],[]]:
            with self.assertRaises(ValueError): run_scenario.check_target(bad,'red','WIN11-TEST01',now=now)

    def test_cleanup_status_and_operation_fields(self):
        import run_scenario
        self.assertTrue(run_scenario.cleanup_status([{'cleanup':1,'status':0},{'cleanup':0,'status':1}])[0])
        ok,_,failed=run_scenario.cleanup_status([{'cleanup':1,'status':1}])
        self.assertFalse(ok); self.assertEqual(len(failed),1)
        f=run_scenario.operation_fields({'scenario':'d','adversary_id':'x'},'pid','sid','red')
        self.assertEqual((f['obfuscator'],f['adversary']['adversary_id'],f['group']),('plain-text','x','red'))

if __name__=='__main__': unittest.main()
