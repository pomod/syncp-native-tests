"""Real native installer tests; no stub application can satisfy the acceptance."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest

N = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_foundation_acceptance', N/'tests/native_acceptance.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
EXE = Path(os.environ['SYNCP_NATIVE_TEST_EXE']).resolve()
base.EXE = EXE


class InstallerAcceptance(base.NativeAcceptance):
    # Inherited fixture utilities, not inherited foundation cases (those run separately).
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='syncp-native-installer-')
        self.root = Path(self.temp.name)/'ui-state'
        self.install_root = Path(self.temp.name)/'installed-app'
        self.host = None
        self.unrelated = None
        self.launch()

    def launch(self):
        self.host = subprocess.Popen([str(EXE),'--installer','--install-root',str(self.install_root),'--data-dir',str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.host.poll() is not None:self.fail('Native installer failed to start: '+self.host.stderr.read())
            for path in self.root.glob('session-*.json'):
                try:
                    session=json.loads(path.read_text())
                    if session['host_pid']==self.host.pid:self.session=session;self.session_file=path;return
                except (ValueError,OSError):pass
            time.sleep(.02)
        self.fail('Native installer startup observation failed')

    def plan(self, operation):
        code,plan=self.api('/api/v1/installer/plan/'+operation)
        self.assertEqual(code,200,plan)
        return plan

    def perform(self,operation):
        plan=self.plan(operation)
        code,result=self.api('/api/v1/installer/approve',data={'operation':operation,'plan_id':plan['plan_id'],'approved':True})
        self.assertEqual(code,202,result)
        deadline=time.monotonic()+15 # Observation window for a small bundled native fixture, not a runtime deadline.
        while time.monotonic()<deadline:
            code,status=self.api('/api/v1/installer/status')
            if code==200 and status['job']['status'] not in ('RUNNING','CANCEL_REQUESTED'):
                self.assertEqual(status['job']['status'],'SUCCEEDED',status)
                return status
            time.sleep(.03)
        self.fail('Native installer did not reach an observed terminal state')

    def test_no_destination_writes_before_exact_authorized_approval(self):
        plan=self.plan('install')
        self.assertFalse(self.install_root.exists())
        self.assertEqual(plan['download_bytes'],0)
        self.assertEqual(plan['package']['sha256'],hashlib.sha256(EXE.read_bytes()).hexdigest())
        self.assertEqual(plan['service_changes'],[])
        self.assertEqual(plan['environment_changes'],[])
        for payload,token in [({'operation':'install','plan_id':plan['plan_id'],'approved':True},'read'),({'operation':'install','plan_id':'stale','approved':True},'manage'),({'operation':'install','plan_id':plan['plan_id'],'approved':False},'manage')]:
            self.assertGreaterEqual(self.api('/api/v1/installer/approve',data=payload,token=token)[0],400)
        self.assertFalse(self.install_root.exists())

    def test_actual_native_install_restart_uninstall_and_restore_preserve_data(self):
        installed=self.perform('install')
        package=installed['installation']['active']
        self.assertEqual(package['sha256'],hashlib.sha256(EXE.read_bytes()).hexdigest())
        binary=self.install_root/'versions'/(package['version']+'-'+package['sha256'])/('syncp-native-host.exe' if os.name=='nt' else 'syncp-native-host')
        self.assertTrue(binary.is_file())
        env={'PATH':''}
        version=subprocess.run([str(binary),'--version'],capture_output=True,text=True,env=env,check=True).stdout
        self.assertIn(package['version'],version)
        data=self.install_root/'data'
        sentinel=data/'user-owned-note.txt';sentinel.write_text('Keep this exact user-owned file.\n')
        preferences=sorted(data.glob('preferences-*.json'))
        protected={p.name:p.read_bytes() for p in preferences}
        self.stop_host();self.launch()
        self.assertEqual(self.api('/api/v1/installer/status')[1]['installation']['active']['sha256'],package['sha256'])
        uninstalled=self.perform('uninstall')
        self.assertIsNone(uninstalled['installation']['active'])
        self.assertFalse(binary.exists())
        self.assertEqual(sentinel.read_text(),'Keep this exact user-owned file.\n')
        for name,value in protected.items():self.assertEqual((data/name).read_bytes(),value)
        restored=self.perform('restore')
        self.assertEqual(restored['installation']['active']['sha256'],package['sha256'])
        self.assertTrue(binary.exists())
        self.assertEqual(sentinel.read_text(),'Keep this exact user-owned file.\n')

    def test_unowned_destination_and_recipe_injection_are_rejected(self):
        self.install_root.mkdir();(self.install_root/'foreign-user-data.txt').write_text('Preserve unrelated installation')
        self.assertEqual(self.api('/api/v1/installer/plan/install')[0],409)
        self.assertEqual((self.install_root/'foreign-user-data.txt').read_text(),'Preserve unrelated installation')
        self.assertEqual(self.api('/api/v1/installer/approve',data={'operation':'install','plan_id':'anything','approved':True,'shell':'untrusted catalog recipe'})[0],400)

    def test_interrupted_transaction_is_preserved_by_reviewed_reconciliation(self):
        self.perform('install')
        before=self.api('/api/v1/installer/status')[1]['installation']
        folder=self.install_root/'transactions'/('a'*64);folder.mkdir()
        (folder/'started.json').write_text('{"acceptance":"injected interrupted transaction"}')
        (folder/'unfinished-user-note.txt').write_text('Preserve interrupted staging evidence')
        self.assertIn('a'*64,self.api('/api/v1/installer/status')[1]['interrupted_transactions'])
        plan=self.plan('reconcile')
        self.assertEqual(plan['interrupted_records_to_preserve'][0]['id'],'a'*64)
        after=self.perform('reconcile')
        self.assertEqual(after['installation'],before)
        self.assertEqual(after['interrupted_transactions'],[])
        notes=list((self.install_root/'quarantine').glob('*/unfinished-user-note.txt'))
        self.assertEqual(len(notes),1)
        self.assertEqual(notes[0].read_text(),'Preserve interrupted staging evidence')

    def test_corrupt_cached_package_never_becomes_active(self):
        self.perform('install')
        self.perform('uninstall')
        plan=self.plan('install')
        cached=self.install_root/'cache'/(plan['package']['sha256']+'.verified')
        cached.write_bytes(b'Corrupted acceptance fixture, never executable')
        self.assertEqual(self.api('/api/v1/installer/approve',data={'operation':'install','plan_id':plan['plan_id'],'approved':True})[0],202)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            code,status=self.api('/api/v1/installer/status')
            if code==200 and status['job']['status']=='FAILED':
                self.assertIsNone(status['installation']['active']);return
            time.sleep(.03)
        self.fail('Corrupt package was not rejected')


if __name__=='__main__':
    # Run only the installer-specific cases here. Foundation cases have their own real run.
    names=[name for name in InstallerAcceptance.__dict__ if name.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(InstallerAcceptance(name) for name in names))
    raise SystemExit(0 if result.wasSuccessful() else 1)
