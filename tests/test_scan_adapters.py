import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'outputs'))
import orca_scan_adapters as a


def xml(ports=(80,), extra=0, complete=True, version=False):
    values = ''.join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="http"' + (' product="Example" version="1.2.3"' if version else '') + '/></port>' for p in ports)
    return '<nmaprun><host><status state="up"/><ports>' + values + f'<extraports state="closed" count="{extra}"/>' + '</ports></host>' + ('<runstats><finished exit="success"/><hosts up="1"/></runstats></nmaprun>' if complete else '')


def template(path='{{BaseURL}}/health', method='GET'):
    return {'id': 'check-example', 'info': {'name': 'Example version', 'severity': 'info', 'tags': 'tech,discovery'},
            'http': [{'method': method, 'path': [path], 'matchers': [{'type': 'word', 'words': ['Example']}]}]}


class AdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.directory = Path(self.temp.name)
        self.paths = patch.object(a.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name)
        self.paths.start()

    def tearDown(self):
        self.paths.stop()
        self.temp.cleanup()

    def fake_nmap(self, argv, log, timeout, **kwargs):
        version = '-sV' in argv
        output = argv[argv.index('-oX') + 1]
        Path(output).write_text(xml(version=version))
        Path(log).write_text('Nmap done')
        return {'exit_code': 0, 'timed_out': False}

    def test_discovery_then_service_versions_only_open_ports(self):
        with patch.object(a, '_run', side_effect=self.fake_nmap) as run:
            result = a.run_services('http://127.0.0.1:80', self.directory, ports='80', timeout=20)
        self.assertEqual(result['status'], 'complete')
        first, second = [call.args[0] for call in run.call_args_list]
        self.assertNotIn('-sV', first)
        self.assertIn('-sV', second)
        self.assertEqual(second[second.index('-p') + 1], '80')
        self.assertEqual(result['observations']['open_services'][0]['version'], '1.2.3')
        self.assertEqual(result['observations']['open_port_count'], 1)
        self.assertEqual(len(result['artifacts']), 5)

    def test_full_port_scan_preserves_more_than_sixteen_services(self):
        def run(argv, log, timeout, **kwargs):
            version = '-sV' in argv
            Path(argv[argv.index('-oX') + 1]).write_text(xml(range(1, 25), extra=0 if version else 65511, version=version))
            Path(log).write_text('done')
            return {'exit_code': 0, 'timed_out': False}
        with patch.object(a, '_run', side_effect=run) as mocked:
            result = a.run_services('localhost', self.directory)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['observations']['open_port_count'], 24)
        self.assertEqual(result['observations']['ports_recorded'], 65535)
        self.assertIn('-p-', mocked.call_args_list[0].args[0])
        self.assertEqual(len(result['observations']['open_services']), 24)

    def test_timeout_retains_open_ports_and_partial_status(self):
        def run(argv, log, timeout, **kwargs):
            Path(argv[argv.index('-oX') + 1]).write_text(xml(complete=False))
            Path(log).write_text('interrupted')
            return {'exit_code': None, 'timed_out': True, 'error': 'budget exceeded'}
        with patch.object(a, '_run', side_effect=run):
            result = a.run_services('localhost', self.directory, timeout=10)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['observations']['open_port_count'], 1)
        self.assertIn('budget exceeded', result['error'])
        self.assertFalse(result['observations']['discovery_complete'])

    def test_no_open_ports_complete_when_all_recorded(self):
        def run(argv, log, timeout, **kwargs):
            Path(argv[argv.index('-oX') + 1]).write_text(xml((), extra=2))
            Path(log).write_text('done')
            return {'exit_code': 0, 'timed_out': False}
        with patch.object(a, '_run', side_effect=run) as mocked:
            result = a.run_services('localhost', self.directory, ports='80,443')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(mocked.call_count, 1)

    def test_bad_targets_and_ports_never_execute(self):
        with patch.object(a, '_run') as run:
            for target in ['-iL /tmp/list', 'localhost;echo hi', 'http://user:pass@localhost', '192.168.1.0/24']:
                for adapter in [a.run_services, a.run_nikto, a.run_nuclei]:
                    self.assertEqual(adapter(target, self.directory)['status'], 'blocked')
            for ports in ['0', '65536', '5-1', '1;id', '-p-', 'all,22', '1-65536']:
                self.assertEqual(a.run_services('localhost', self.directory, ports=ports)['status'], 'blocked')
            run.assert_not_called()
        self.assertEqual(a._port_spec('1-5,3,80')[1], 6)

    def test_long_nmap_fingerprint_still_drains_completion_events(self):
        path = self.directory / 'long.xml'
        path.write_text(xml(version=True).replace('name="http"', 'name="http" servicefp="' + 'x' * 20000 + '"'))
        rows, issues, complete, count, up = a._nmap_result(path)
        self.assertTrue(complete)
        self.assertEqual(count, 1)
        self.assertEqual(rows[0]['version'], '1.2.3')
        self.assertFalse(issues)

    def test_nikto_selection_excludes_mixed_exploit_tags_and_credentials(self):
        policy = a._nikto_policy(self.directory)
        manifest = json.loads(Path(policy['manifest']).read_text())
        self.assertIn('007004', manifest['skipped_ids'])  # b8e Axis2 credential attempt
        self.assertIn('003129', manifest['skipped_ids'])  # POST requesting database dump
        self.assertGreater(manifest['selected_database_tests'], 100)
        config = Path(policy['config']).read_text()
        self.assertIn('UPDATES=no', config)
        self.assertIn('SKIPIDS=', config)

    def test_nikto_classifies_plain_observations_and_missing_headers(self):
        self.assertEqual(a._nikto_classification('Server: Example/1.2.3'), 'observation')
        self.assertEqual(a._nikto_classification('The site redirects to https://localhost/'), 'observation')
        self.assertEqual(a._nikto_classification('The X-Frame-Options header is not present.'), 'hardening')
        self.assertEqual(a._nikto_classification('Possible version vulnerability'), 'candidate')

    def test_nikto_parses_real_schema_and_candidate_classification(self):
        def run(argv, log, timeout, **kwargs):
            Path(argv[argv.index('-output') + 1]).write_text(json.dumps([{'host': 'localhost', 'end_time': 'now', 'vulnerabilities': [{'id': '123', 'method': 'GET', 'url': '/info', 'msg': 'Possible disclosure', 'references': ['https://vendor.example/advisory']}]}]))
            Path(log).write_text('1 host(s) tested')
            return {'exit_code': 0, 'timed_out': False}
        with patch.object(a, '_run', side_effect=run) as mocked:
            result = a.run_nikto('http://localhost', self.directory)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['findings'][0]['classification'], 'candidate')
        argv = mocked.call_args.args[0]
        self.assertNotIn('-followredirects', argv)
        self.assertEqual(argv[argv.index('-Tuning') + 1], '123b')
        self.assertNotIn('shellshock', argv[argv.index('-Plugins') + 1])

    def test_nikto_internal_deadline_not_success(self):
        def run(argv, log, timeout, **kwargs):
            Path(argv[argv.index('-output') + 1]).write_text('[{"end_time":"now","vulnerabilities":[]}]')
            Path(log).write_text('+ ERROR: Host maximum execution time of 895 seconds reached')
            return {'exit_code': 0, 'timed_out': False}
        with patch.object(a, '_run', side_effect=run):
            result = a.run_nikto('http://localhost', self.directory)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('maximum execution', result['error'])

    def test_nikto_killed_before_json_close_keeps_stdout_candidates(self):
        def run(argv, log, timeout, **kwargs):
            Path(log).write_text('+ /info: Possible disclosure\n+ Server: Example\n')
            return {'exit_code': None, 'timed_out': True, 'error': 'deadline'}
        with patch.object(a, '_run', side_effect=run):
            result = a.run_nikto('http://localhost', self.directory, timeout=10)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['findings']), 1)
        self.assertIn('/info', result['findings'][0]['evidence'])

    def test_template_filter_accepts_only_bounded_static_retrieval(self):
        self.assertTrue(a._template_allowed(template()))
        self.assertTrue(a._template_allowed(template(method='HEAD')))
        for path in ['https://outside.example', '{{BaseURL}}@outside.example', '{{RootURL}}/../secret', '{{BaseURL}}/delete', '{{BaseURL}}?exec=test', '{{BaseURL}}/{{randstr}}', '{{BaseURL}}//outside.example', '{{BaseURL}}/%2e%2e/']:
            self.assertFalse(a._template_allowed(template(path)), path)
        for method in ['POST', 'PUT', 'DELETE']:
            self.assertFalse(a._template_allowed(template(method=method)))
        for key, value in [('raw', ['GET / HTTP/1.1']), ('payloads', {'a': ['x']}), ('body', 'x'), ('redirects', True), ('headers', {'Host': 'outside.example'})]:
            doc = template(); doc['http'][0][key] = value
            self.assertFalse(a._template_allowed(doc), key)
        for key in ['flow', 'code', 'javascript', 'dns', 'headless', 'variables']:
            doc = template(); doc[key] = 'untrusted'
            self.assertFalse(a._template_allowed(doc), key)
        doc = template(); doc['http'][0]['path'] *= 9
        self.assertFalse(a._template_allowed(doc))
        doc = template(); doc['info']['tags'] = 'rce'
        self.assertFalse(a._template_allowed(doc))

    def test_template_selection_requires_digest_and_records_hashes(self):
        import yaml
        root = self.directory / 'pack' / 'http'; root.mkdir(parents=True)
        (root / 'signed.yaml').write_text(yaml.safe_dump(template()) + '\n# digest: signature')
        (root / 'unsigned.yaml').write_text(yaml.safe_dump(template()))
        with patch.object(a, 'TEMPLATE_ROOT', root.parent):
            selected, manifest = a._select_templates(self.directory)
        self.assertEqual(len(selected), 1)
        self.assertEqual(manifest['excluded_count'], 1)
        self.assertEqual(len(selected[0]['sha256']), 64)
        self.assertEqual(Path(selected[0]['path']).stat().st_mode & 0o777, 0o600)

    def test_nuclei_result_keeps_candidate_and_info_observation(self):
        raw = self.directory / 'result.jsonl'
        raw.write_text('\n'.join(json.dumps({'template-id': 'sample', 'info': {'name': 'Sample', 'severity': severity}, 'matched-at': 'http://localhost/'}) for severity in ['high', 'info']) + '\n{"incomplete":')
        rows, errors = a._nuclei_findings(raw)
        self.assertEqual([r['classification'] for r in rows], ['candidate', 'observation'])
        self.assertEqual(len(errors), 1)

    def test_nuclei_full_findings_survive_large_raw_responses(self):
        raw = self.directory / 'large.jsonl'
        first = {'template-id': 'large', 'info': {'name': 'Large response', 'severity': 'info'}, 'response': 'x' * 25_000_000}
        last = {'template-id': 'last', 'info': {'name': 'Final finding', 'severity': 'medium'}}
        with raw.open('w') as stream:
            stream.write(json.dumps(first) + '\n' + json.dumps(last) + '\n')
        rows, errors = a._nuclei_findings(raw)
        self.assertFalse(errors)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]['id'], 'nuclei-last')

    def test_nuclei_completion_and_coverage_arguments(self):
        def run(argv, log, timeout, **kwargs):
            Path(log).write_text('[INF] Templates loaded for current scan: 2\n[INF] Scan completed in 1s. No results found.\n')
            return {'exit_code': 0, 'timed_out': False}
        update = a._base('update', 'complete', observations={'installed_template_version': 'v1.0.0'}, artifacts=[])
        selection = ([{'id': 'one'}, {'id': 'two'}], {'excluded_count': 3, 'maximum_requests': 2})
        with patch.object(a, 'update_nuclei_templates', return_value=update), patch.object(a, '_select_templates', return_value=selection), patch.object(a, '_run', side_effect=run) as mocked, patch.object(a, '_nuclei_env', return_value={}):
            result = a.run_nuclei('http://localhost', self.directory)
        self.assertEqual(result['status'], 'complete')
        argv = mocked.call_args.args[0]
        for flag in ['-dut', '-dr', '-ni', '-duc', '-no-stdin', '-nh']:
            self.assertIn(flag, argv)
        for flag in ['-code', '-headless', '-dast', '-dashboard', '-auth']:
            self.assertNotIn(flag, argv)
        self.assertEqual(argv[argv.index('-rl') + 1], '5')
        self.assertEqual(argv[argv.index('-c') + 1], '2')

    def test_nuclei_zero_results_with_errors_still_partial(self):
        def run(argv, log, timeout, **kwargs):
            Path(log).write_text('[INF] Templates loaded for current scan: 2\n[INF] Scan completed. No results found.\n')
            Path(argv[argv.index('-elog') + 1]).write_text('connection timeout')
            return {'exit_code': 0, 'timed_out': False}
        update = a._base('update', 'complete', observations={'installed_template_version': 'v1.0.0'}, artifacts=[])
        with patch.object(a, 'update_nuclei_templates', return_value=update), patch.object(a, '_select_templates', return_value=([{}, {}], {'excluded_count': 0, 'maximum_requests': 2})), patch.object(a, '_run', side_effect=run), patch.object(a, '_nuclei_env', return_value={}):
            result = a.run_nuclei('http://localhost', self.directory)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['findings'], [])

    def test_private_artifacts_and_child_process_group_inheritance(self):
        with patch.object(a.subprocess, 'run') as mocked:
            mocked.return_value.returncode = 0
            a._run(['/usr/bin/example'], self.directory / 'process.log', 1)
        kwargs = mocked.call_args.kwargs
        self.assertNotIn('start_new_session', kwargs)
        self.assertEqual(kwargs['umask'], 0o077)
        self.assertEqual((self.directory / 'process.log').stat().st_mode & 0o777, 0o600)

    def test_nuclei_environment_isolated_from_credentials_and_custom_sources(self):
        with patch.object(a, 'NUCLEI_STATE', self.directory / 'state'), patch.dict(os.environ, {'GITHUB_TOKEN': 'secret', 'PDCP_API_KEY': 'secret', 'NUCLEI_CUSTOM_TEMPLATES': '/untrusted'}):
            env = a._nuclei_env()
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertNotIn('PDCP_API_KEY', env)
        self.assertNotIn('NUCLEI_CUSTOM_TEMPLATES', env)
        self.assertEqual(env['DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD'], 'true')
        self.assertTrue(env['XDG_CONFIG_HOME'].startswith(str(self.directory)))

    def test_zap_inventory_version_ignores_java_runtime_banner(self):
        with patch.object(a.subprocess, 'run') as proc:
            proc.return_value.stdout = 'Found Java version 25.0.4\nUsing JVM args: -Xmx1g\n2.17.0\n'
            proc.return_value.stderr = ''
            self.assertEqual(a._version(['/usr/bin/zaproxy', '-version']), 'ZAP 2.17.0')

    def test_inventory_reports_versions_without_claiming_unknown_is_latest(self):
        with patch.object(a, '_version', return_value='Example 1.0.0'), patch.object(a.subprocess, 'run') as proc, patch.object(a.requests, 'get', side_effect=a.requests.RequestException('offline')):
            proc.return_value.stdout = '  Installed: 1.0.0\n  Candidate: 1.1.0\n'
            result = a.inventory()
        self.assertEqual(result['tools']['nmap']['latest_status'], 'not verified')
        self.assertEqual(result['tools']['nmap']['apt_candidate'], '1.1.0')
        self.assertEqual(result['status'], 'complete')


if __name__ == '__main__':
    unittest.main(verbosity=2)
