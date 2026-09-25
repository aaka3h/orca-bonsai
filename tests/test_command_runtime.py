"""Real harmless commands verify errors, capture, deadlines and child cleanup."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'outputs'))
import orca_agent as agent
from orca_process import run_process
from orca_task_evidence import result_failed
from orca_terminal_text import sanitize_terminal_text, extract_cli_errors

class CommandRuntimeTests(unittest.TestCase):
    def test_pipeline_failure_is_not_hidden_by_final_filter(self):
        r=agent.tool_run_command({'command':'false | cat'})
        self.assertNotEqual(r['exit_code'],0)
        self.assertTrue(result_failed(r))
        self.assertEqual(agent.tool_run_command({'command':'printf hello | cat'})['stdout'],'hello')

    def test_admin_command_uses_same_failure_tracking_without_running_sudo(self):
        with patch.object(agent,'JSONL_MODE',False),patch.object(agent.sys.stdin,'isatty',return_value=True),patch.object(agent,'run_process',return_value={}) as runner:
            agent.tool_run_admin_command({'command':'false | cat'})
            self.assertEqual(runner.call_args.args[0][-5:],['/bin/bash','-o','pipefail','-lc','false | cat'])

    def test_timeout_keeps_output_and_cleans_child(self):
        child="import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)"
        source="import subprocess,sys,time;p=subprocess.Popen([sys.executable,'-c',"+repr(child)+"]);print(p.pid,flush=True);print('partial diagnostic',file=sys.stderr,flush=True);time.sleep(30)"
        r=run_process([sys.executable,'-c',source],timeout=1)
        self.assertTrue(r['timed_out'])
        self.assertIn('partial diagnostic',r['stderr'])
        self.assertTrue(result_failed(r))
        pid=int(r['stdout'].strip())
        try:
            fd=os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            self.assertTrue(select.select([fd],[],[],2)[0],'child still running after command timeout')
        finally:
            os.close(fd)

    def test_large_output_tail_and_diagnostic_survive(self):
        source="import sys;print('start');print('x'*400000);print('tail');print('custom: permission denied',file=sys.stderr)"
        r=run_process([sys.executable,'-c',source])
        self.assertLessEqual(len(r['stdout']),4500)
        self.assertLessEqual(len(r['stderr']),1600)
        self.assertIn('start',r['stdout'])
        self.assertIn('tail',r['stdout'])
        self.assertTrue(r['output_truncated'])
        self.assertTrue(result_failed(r))

    def test_terminal_controls_and_invalid_utf8_are_inert(self):
        raw=b'\x1b[31mred\x1b[0m\rnext\xff\n\x1b]52;c;secret\x07end'
        r=run_process([sys.executable,'-c','import os;os.write(1,'+repr(raw)+')'])
        self.assertEqual(r['stdout'],'red\nnext\ufffd\nend')
        self.assertNotIn('secret',r['stdout'])

    def test_diagnostics_are_retained_before_output_excerpt(self):
        source="print('head');print('x'*5000);print('command failed: Operation not permitted (-1)');print('y'*5000)"
        r=run_process([sys.executable,'-c',source])
        self.assertIn('Operation not permitted',' '.join(r['diagnostics']))
        self.assertTrue(result_failed(r))

    def test_document_example_not_failure(self):
        r=run_process([sys.executable,'-c',"print('Example output:\\ncustom: permission denied\\n')"])
        self.assertFalse(result_failed(r))

    def test_missing_program_or_cwd_reports_error(self):
        self.assertIn('error',run_process(['/nonexistent/orca-test-tool']))
        self.assertIn('error',run_process([sys.executable,'-c','pass'],cwd='/nonexistent/orca-test-dir'))


class FailedRetryTests(unittest.TestCase):
    def test_unchanged_failed_admin_request_runs_only_twice(self):
        requests=[]
        events=[]
        def reply(path,payload,**kwargs):
            requests.append(payload)
            if payload.get('tool_choice')=='none':
                return {'choices':[{'message':{'content':'The command failed.','tool_calls':[]}}]}
            return {'choices':[{'message':{'content':None,'tool_calls':[{'id':str(len(requests)),'type':'function','function':{'name':'run_admin_command','arguments':json.dumps({'command':'example-operation'})}}]}}]}
        with patch.object(agent,'request_json',side_effect=reply),patch.object(agent,'review_progress',return_value=None),patch.dict(agent.DISPATCH,{'run_admin_command':lambda args:{'exit_code':1,'stderr':'example: permission denied'}}):
            agent.run_task([{'role':'system','content':'test'}],'test','Test a harmless mocked operation',10,events.append)
        results=[e for e in events if e['type']=='tool_result']
        self.assertEqual(len(results),3)
        self.assertFalse(results[0]['cached'])
        self.assertFalse(results[1]['cached'])
        self.assertTrue(results[2]['cached'])
        self.assertTrue(results[2]['result']['retry_suppressed'])
        self.assertIn('three unsuccessful rounds',events[-1]['text'])

    def test_changed_request_and_successful_mutations_are_not_cached(self):
        calls=[{'command':'first'},{'command':'second'},{'command':'second'}]
        ran=[]
        def reply(path,payload,**kwargs):
            if not calls:
                return {'choices':[{'message':{'content':'Done'}}]}
            args=calls.pop(0)
            return {'choices':[{'message':{'tool_calls':[{'id':'c'+str(len(calls)),'function':{'name':'run_admin_command','arguments':json.dumps(args)}}]}}]}
        def handler(args):
            ran.append(args['command'])
            return {'exit_code':1 if args['command']=='first' else 0}
        with patch.object(agent,'request_json',side_effect=reply),patch.object(agent,'review_progress',return_value=None),patch.dict(agent.DISPATCH,{'run_admin_command':handler}):
            agent.run_task([{'role':'system','content':'test'}],'test','Test',5,lambda e:None)
        self.assertEqual(ran,['first','second','second'])

if __name__=='__main__':unittest.main()
