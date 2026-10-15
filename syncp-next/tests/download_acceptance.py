"""Native downloader uses real native package bytes over an owned loopback fixture."""
from pathlib import Path
import hashlib, importlib.util, json, os, subprocess, threading, time, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

N=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer_acceptance',N/'tests/installer_acceptance.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
EXE=base.EXE


class DownloadAcceptance(base.InstallerAcceptance):
    def setUp(self):
        self.mode='normal';self.release=threading.Event();self.requests=[];self.body=EXE.read_bytes();outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                start=0;range_header=self.headers.get('Range');outer.requests.append(range_header)
                if range_header:start=int(range_header.removeprefix('bytes=').removesuffix('-'))
                payload=outer.body
                if outer.mode=='corrupt':payload=b'X'+payload[1:]
                self.send_response(206 if start else 200)
                self.send_header('Content-Length',str(len(payload)-start))
                if start:self.send_header('Content-Range',f'bytes {start}-{len(payload)-1}/{len(payload)}')
                self.end_headers()
                try:
                    if outer.mode=='stall':
                        self.wfile.write(payload[start:start+65536]);self.wfile.flush();outer.release.wait()
                    else:self.wfile.write(payload[start:])
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}/native-package'
        super().setUp()

    def launch(self):
        self.host=subprocess.Popen([str(EXE),'--installer','--install-root',str(self.install_root),'--data-dir',str(self.root),'--test-download-url',self.url],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.host.poll() is not None:self.fail('Native download installer did not start')
            for p in self.root.glob('session-*.json'):
                try:
                    session=json.loads(p.read_text())
                    if session['host_pid']==self.host.pid:self.session=session;self.session_file=p;return
                except (ValueError,OSError):pass
            time.sleep(.02)
        self.fail('Native startup observation failed')

    def tearDown(self):
        self.release.set()
        super().tearDown()
        self.server.shutdown();self.server.server_close();self.thread.join()

    def begin(self):
        plan=self.plan('install')
        self.assertEqual(plan['download_bytes'],len(self.body))
        self.assertEqual(plan['download_body_timeout_seconds'],0)
        self.assertEqual(self.api('/api/v1/installer/approve',data={'operation':'install','plan_id':plan['plan_id'],'approved':True})[0],202)
        return plan

    def terminal(self, expected):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            code,status=self.api('/api/v1/installer/status')
            if code==200 and status['job']['status'] not in ('RUNNING','CANCEL_REQUESTED'):
                self.assertEqual(status['job']['status'],expected,status);return status
            time.sleep(.03)
        self.fail('Native download did not reach an observed terminal state')

    def test_real_download_integrity_and_native_install(self):
        self.begin();status=self.terminal('SUCCEEDED')
        self.assertEqual(status['installation']['active']['sha256'],hashlib.sha256(self.body).hexdigest())
        self.assertEqual(self.requests,[None])

    def test_corrupt_download_never_executes_or_activates(self):
        self.mode='corrupt';self.begin();status=self.terminal('FAILED')
        self.assertIsNone(status['installation']['active'])
        self.assertFalse((self.install_root/'data').exists())

    def test_stalled_download_cancellation_is_observed_and_preserves_prefix(self):
        self.mode='stall';plan=self.begin()
        partial=self.install_root/'cache'/(plan['package']['sha256']+'.partial')
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if partial.is_file() and partial.stat().st_size>0:break
            time.sleep(.02)
        self.assertTrue(partial.is_file())
        self.assertEqual(self.api('/api/v1/installer/cancel',data={})[0],202)
        status=self.terminal('CANCELLED')
        self.assertIsNone(status['installation']['active'])
        self.assertGreater(partial.stat().st_size,0)
        self.assertEqual(status['interrupted_transactions'],[])
        self.mode='normal';self.release.set()
        self.begin();self.terminal('SUCCEEDED')
        self.assertTrue(any(header and header.startswith('bytes=') for header in self.requests))

    @unittest.skipUnless(os.name=='posix', 'Crash observation requires native destination execution')
    def test_parent_crash_stops_owned_download_and_allows_reviewed_recovery(self):
        self.mode='stall';self.begin()
        deadline=time.monotonic()+5;helper=None
        while time.monotonic()<deadline:
            code,status=self.api('/api/v1/installer/status')
            if code==200 and status['job'].get('download_helper_pid'):
                helper=status['job']['download_helper_pid'];break
            time.sleep(.02)
        self.assertIsNotNone(helper)
        self.host.kill();self.host.wait(timeout=5);self.host.stdout.close();self.host.stderr.close();self.host=None
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            stat=Path('/proc')/str(helper)/'stat'
            if not stat.exists():break
            try:
                if stat.read_text().split(') ',1)[1].startswith('Z '):break
            except OSError:break
            time.sleep(.02)
        else:self.fail('Owned download helper remained live after its exact parent died')
        self.mode='normal';self.release.set();self.launch()
        self.assertGreater(len(self.api('/api/v1/installer/status')[1]['interrupted_transactions']),0)
        self.perform('reconcile')
        self.begin();self.terminal('SUCCEEDED')

    def test_offline_source_fails_without_an_active_installation(self):
        self.server.shutdown();self.server.server_close()
        self.begin();status=self.terminal('FAILED')
        self.assertIsNone(status['installation']['active'])


if __name__=='__main__':
    names=[name for name in DownloadAcceptance.__dict__ if name.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(DownloadAcceptance(name) for name in names))
    raise SystemExit(0 if result.wasSuccessful() else 1)
