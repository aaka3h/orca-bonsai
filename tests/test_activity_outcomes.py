"""GUI failures and capability routing use isolated state, never the user's DB."""
import io
import json
import os
from pathlib import Path
import queue
import sys
import tempfile
import unittest
from unittest.mock import patch
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'outputs'))
from PySide6.QtWidgets import QApplication
import orca_gui as gui
import orca_agent as agent
from orca_memory import MemoryStore

class ActivityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def test_activity_classifies_failed_timeout_and_reused(self):
        widget=gui.ActivityWidget()
        cases=[({'exit_code':0},False,'done'),({'error':'Invalid JSON'},False,'failed'),
               ({'exit_code':0,'stdout':'\x1b[31mcommand failed: Operation not permitted (-1)\x1b[0m'},False,'failed'),
               ({'timed_out':True,'error':'Timeout'},False,'timed out'),
               ({'exit_code':1},True,'reused')]
        for step,(result,cached,state) in enumerate(cases):
            widget.tool_start(step,'run_command',{})
            self.assertEqual(widget._entry_state(widget.entries[-1]),'running')
            widget.tool_result(step,'run_command',result,cached=cached)
            self.assertEqual(widget._entry_state(widget.entries[-1]),state)
        self.assertIn('2 failed',widget.toggle.text())
        self.assertIn('1 timed out',widget.toggle.text())
        self.assertNotIn('u001b',widget.details.toPlainText())
        widget.deleteLater()

    def test_redaction_preserved_with_terminal_cleanup(self):
        text=gui._safe_detail({'token':'private-value','stdout':'\x1b[31mvisible\x1b[0m','nested':[{'password':'other-secret'}]})
        self.assertIn('visible',text)
        self.assertNotIn('private-value',text)
        self.assertNotIn('other-secret',text)
        self.assertNotIn('u001b',text)

    def test_capabilities_menu_payload_and_busy_guard(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            memory=MemoryStore(Path(temp)/'test.sqlite3')
            window=gui.OrcaWindow(auto_start=False,memory_store=memory)
            window._ready=True
            window._write_queue=queue.Queue()
            window._refresh_controls()
            window.capabilities_action.trigger()
            request=window._write_queue.get_nowait()
            self.assertEqual(request['type'],'capabilities')
            self.assertEqual(request['conversation_id'],window._conversation_id)
            self.assertTrue(window._busy)
            self.assertFalse(window.capabilities_action.isEnabled())
            window.check_capabilities()
            self.assertTrue(window._write_queue.empty())
            window._on_process_line(window._generation,'stdout',json.dumps({'type':'task_done'}))
            self.assertFalse(window._busy)
            self.assertTrue(window.capabilities_action.isEnabled())
            window.close();window.deleteLater();self.app.processEvents()

class CapabilityIntegrationTests(unittest.TestCase):
    def test_cli_does_not_load_model(self):
        with patch.object(sys,'argv',['orca_agent','--capabilities']),patch.object(agent,'choose_model',side_effect=AssertionError('Must not load model')),patch('orca_capabilities.check_capabilities',return_value={'note':'inventory only'}),patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertEqual(agent.main(),0)
            self.assertIn('inventory only',output.getvalue())

    def test_saved_capability_task_uses_no_model_and_persists_answer(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp,patch.dict(os.environ,{'ORCA_MEMORY_DB':str(Path(temp)/'memory.sqlite3')}),patch.object(agent,'tool_check_capabilities',return_value={'note':'inspection only'}),patch.object(agent,'request_json',side_effect=AssertionError('Inventory must not ask model')):
            store=MemoryStore()
            cid=store.new_conversation()
            events=[]
            agent.run_saved_task({'type':'capabilities','text':'Check available tools','conversation_id':cid},'unused',event_sink=events.append)
            self.assertEqual(len(store.load_messages(cid)),2)
            self.assertEqual(events[-1]['type'],'conversation_saved')
            self.assertIn('inspection only',next(e['text'] for e in events if e['type']=='answer'))

    def test_jsonl_capability_request_is_accepted(self):
        request={'type':'capabilities','text':'Check tools','conversation_id':'mock'}
        with patch.object(sys,'argv',['orca_agent','--jsonl','--model','test']),patch('sys.stdin',io.StringIO(json.dumps(request)+'\n')),patch('sys.stdout',new_callable=io.StringIO) as output,patch.object(agent,'run_saved_task') as task:
            self.assertEqual(agent.main(),0)
            self.assertEqual(task.call_args.args[0],request)
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])['type'],'task_done')

if __name__=='__main__':unittest.main()
