"""Real native Doctor acceptance with explicitly injected failures in isolated state."""
from pathlib import Path
import os,sys,json,time,subprocess,threading,http.server,socket,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
try:from native_acceptance import NativeAcceptance
except ImportError:
 sys.path.insert(0,'/home/pomod/work/Project-AI/_control/syncp-next/tests');from native_acceptance import NativeAcceptance
EXE=Path(os.environ['SYNCP_NATIVE_TEST_EXE'])
class DoctorAcceptance(NativeAcceptance):
 def report(self):
  code,r=self.api('/api/v1/doctor/report');self.assertEqual(code,200);self.assertTrue(r['ok']);return {f['code']:f for f in r['findings']}
 def test_interrupted_settings_diagnosis_exact_repair_and_verification(self):
  self.api('/api/v1/preferences',data={'theme':'light'});saved={p.name:p.read_bytes() for p in self.root.glob('preferences-*.json')}
  pending=self.root/'preferences-00000000000000000002.pending';pending.write_bytes(b'{"theme":"dark"}')
  self.assertIn('INTERRUPTED_SETTINGS',self.report());_,plan=self.api('/api/v1/doctor/plan',data={'recipe':'quarantine-interrupted-settings'})
  payload={'recipe':plan['recipe'],'plan_id':plan['plan_id'],'approved':True}
  self.assertEqual(self.api('/api/v1/doctor/repair',data=payload,token='read')[0],403)
  self.assertEqual(self.api('/api/v1/doctor/repair',data=dict(payload,approved=False))[0],409)
  pending.write_bytes(b'{"theme":"dark","uncommitted":true}')
  self.assertEqual(self.api('/api/v1/doctor/repair',data=payload)[0],409)
  _,plan=self.api('/api/v1/doctor/plan',data={'recipe':'quarantine-interrupted-settings'});payload['plan_id']=plan['plan_id'];raw=pending.read_bytes();code,result=self.api('/api/v1/doctor/repair',data=payload)
  self.assertEqual(code,200);self.assertEqual(result['result'],'VERIFIED');self.assertTrue(result['committed_settings_preserved']);self.assertIsNone(result['runtime_health']);self.assertFalse(pending.exists())
  self.assertEqual(next(self.root.glob('quarantine-*/preferences-*.pending')).read_bytes(),raw);self.assertEqual({p.name:p.read_bytes() for p in self.root.glob('preferences-*.json')},saved);self.assertNotIn('INTERRUPTED_SETTINGS',self.report())
  self.stop_host();self.launch();self.assertEqual(self.api('/api/v1/status')[1]['preferences']['theme'],'light')
 def test_unsafe_pending_is_reported_without_silent_repair(self):
  pending=self.root/'preferences-untrusted.pending';pending.write_bytes(b'preserve evidence')
  r=self.report();self.assertIn('UNSAFE_STAGING_REQUIRES_MANUAL_REVIEW',r);self.assertIsNone(r['UNSAFE_STAGING_REQUIRES_MANUAL_REVIEW']['repair_recipe']);self.assertEqual(self.api('/api/v1/doctor/plan',data={'recipe':'quarantine-interrupted-settings'})[0],409);self.assertEqual(pending.read_bytes(),b'preserve evidence')
 def test_unexpected_owned_exit_is_repaired_without_touching_unrelated_process(self):
  self.unrelated=subprocess.Popen([str(EXE),'--fixture-child'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  self.api('/api/v1/proof/start',data={});pid=self.api('/api/v1/status')[1]['owned_process']['pid'];os.kill(pid,9)
  for _ in range(100):
   if self.api('/api/v1/status')[1]['owned_process']['failed']:break
   time.sleep(.01)
  self.assertIn('OWNED_VERIFICATION_PROCESS_FAILED',self.report());_,plan=self.api('/api/v1/doctor/plan',data={'recipe':'restart-owned-verification-fixture'});code,r=self.api('/api/v1/doctor/repair',data={'recipe':plan['recipe'],'plan_id':plan['plan_id'],'approved':True})
  self.assertEqual(code,200);self.assertEqual(r['result'],'VERIFIED');p=self.api('/api/v1/status')[1]['owned_process'];self.assertTrue(p['running']);self.assertNotEqual(p['pid'],pid);self.assertIsNone(self.unrelated.poll());self.assertNotIn('OWNED_VERIFICATION_PROCESS_FAILED',self.report())
 def test_model_mismatch_is_diagnosed_without_foreign_process_authority(self):
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'{"data":[{"id":"available-model"}]}')
   def log_message(self,*a):pass
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   c=self.api('/api/v1/onboarding/status')[1]['configuration'];c.update(local_endpoint='http://127.0.0.1:'+str(server.server_port),local_model='missing-model');_,plan=self.api('/api/v1/onboarding/plan',data=c);self.api('/api/v1/onboarding/approve',data={'configuration':c,'plan_id':plan['plan_id'],'approved':True})
   r=self.report();self.assertIn('SELECTED_LOCAL_MODEL_UNAVAILABLE',r);self.assertIsNone(r['SELECTED_LOCAL_MODEL_UNAVAILABLE']['repair_recipe']);self.assertFalse(r['SELECTED_LOCAL_MODEL_UNAVAILABLE']['observation']['managed']);self.assertEqual(self.api('/api/v1/doctor/plan',data={'recipe':'kill-foreign-runtime'})[0],409);self.assertTrue(thread.is_alive())
  finally:server.shutdown();server.server_close()
 def test_offline_is_intentional_and_not_a_cloud_error(self):
  r=self.report();self.assertEqual(r['CLOUD_DISABLED_BY_OFFLINE_MODE']['severity'],'info');self.assertFalse(r['CLOUD_DISABLED_BY_OFFLINE_MODE']['observation']['cloud_contact_performed']);self.assertNotIn('CLOUD_MODEL_AVAILABILITY_UNVERIFIED',r)
 def test_failed_local_request_stays_visible_without_crashing_host(self):
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  c=self.api('/api/v1/onboarding/status')[1]['configuration'];c['local_endpoint']='http://127.0.0.1:'+str(port);_,p=self.api('/api/v1/onboarding/plan',data=c);self.api('/api/v1/onboarding/approve',data={'configuration':c,'plan_id':p['plan_id'],'approved':True});self.api('/api/v1/onboarding/test',data={'kind':'local-probe','cloud_quota_approved':False})
  for _ in range(100):
   r=self.api('/api/v1/onboarding/status')[1]
   if r['job']['status']=='FAILED':break
   time.sleep(.02)
  self.assertEqual(r['job']['status'],'FAILED');report=self.report();self.assertIn('CONNECTION_TEST_FAILED',report);self.assertIn('LOCAL_ENDPOINT_UNAVAILABLE',report);self.assertEqual(self.api('/api/v1/health')[0],200)
if __name__=='__main__':
 names=[n for n in DoctorAcceptance.__dict__ if n.startswith('test_')];r=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(DoctorAcceptance(n) for n in names));sys.exit(not r.wasSuccessful())
