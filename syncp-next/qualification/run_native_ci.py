"""Run declared portable checks on an actual native destination, never an OS fixture.

No provider credentials, inference requests, model downloads or system packages.
Run on macOS CI with explicit Darwin/architecture expectations; Linux execution
only validates this harness locally and is never reported as macOS acceptance.
"""
from __future__ import annotations
import argparse, datetime, hashlib, json, os, platform, re, shutil, subprocess, sys
from pathlib import Path

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--expect-system',required=True,choices=['Darwin','Linux'])
    ap.add_argument('--expect-architecture',required=True,choices=['arm64','x86_64'])
    args=ap.parse_args()
    root=Path(__file__).resolve().parents[1]
    actual={'system':platform.system(),'architecture':platform.machine(),'release':platform.release()}
    if actual['system']!=args.expect_system or actual['architecture']!=args.expect_architecture:
        raise SystemExit('NATIVE_OS_OR_ARCHITECTURE_MISMATCH; no target PASS')
    binary=args.binary.resolve(strict=True)
    if not binary.is_file():raise SystemExit('REAL_NATIVE_EXECUTABLE_REQUIRED')
    output=args.output.resolve()
    if output.exists():raise SystemExit('NEW_OUTPUT_DIRECTORY_REQUIRED; existing evidence preserved')
    output.mkdir(parents=True)
    # Drop API-mode keys and provider tokens from child processes. No home credential
    # stores are read; none of the selected tests launch a cloud execution worker.
    allowed={'HOME','USERPROFILE','LOCALAPPDATA','APPDATA','PATH','SYSTEMROOT','WINDIR','TMP','TEMP','TMPDIR','LANG','LC_ALL','CARGO_HOME','RUSTUP_HOME','RUSTC'}
    env={k:v for k,v in os.environ.items() if k in allowed}
    env.update(SYNCP_NATIVE_TEST_EXE=str(binary),PYTHONPATH=str(root/'python'),PYTHONDONTWRITEBYTECODE='1')
    report={'schema_version':1,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'result':'RUNNING','actual_native_platform':actual,'binary_sha256':digest(binary),
            'binary_bytes':binary.stat().st_size,'cloud_requests':0,'private_context_sent':False,
            'automatic_toolchain_install':False,'general_inference_deadline_seconds':0,'checks':[],
            'excluded':['Linux-qualified onboarding and CLI workers','Linux registry/systemd optional applications',
                        'Cloud account/provider inference','Full native GUI/default-browser/packaging/Gatekeeper',
                        'Fresh OS optional-runtime bootstrap','GPU/Metal inference and model switching']}
    source_manifest=root/'qualification/source-manifest.json'
    if source_manifest.exists():
        manifest=json.loads(source_manifest.read_text())
        for entry in manifest['files']:
            rel=Path(entry['path'])
            if rel.is_absolute() or '..' in rel.parts:raise SystemExit('UNSAFE_SOURCE_MANIFEST')
            p=root/rel
            if p.is_symlink() or digest(p)!=entry['sha256']:raise SystemExit('SOURCE_MANIFEST_HASH_MISMATCH')
        report['source_manifest_sha256']=digest(source_manifest)
    receipt=output/'qualification.json'
    def save():receipt.write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd,expected_count=None):
        result=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True)
        # Test assertions can print an ephemeral local capability if rotation fails.
        # Scrub hex64 in test logs; artifact/source identities are recorded separately.
        text=re.sub(r'\b[0-9a-fA-F]{64}\b','[redacted-hex64]',result.stdout+result.stderr)
        log=output/(name+'.log');log.write_text(text)
        count_match=re.search(r'Ran (\d+) tests?',text) or re.search(r'(?:ℹ tests|running) (\d+)',text) or re.search(r'^# tests (\d+)\s*$',text,re.M)
        count=int(count_match.group(1)) if count_match else None
        ok=result.returncode==0 and (expected_count is None or count==expected_count)
        entry={'name':name,'exit_code':result.returncode,'result':'PASS' if ok else 'FAIL',
               'tests':count,'expected_count':expected_count,'log':log.name,'log_sha256':digest(log)}
        report['checks'].append(entry);save();print(json.dumps(entry),flush=True)
        if not ok:raise RuntimeError(name+' failed; no target PASS')
    try:
        run('native-version',[str(binary),'--version'])
        if actual['system']=='Darwin':
            output_file=subprocess.run(['/usr/bin/file',str(binary)],env=env,capture_output=True,text=True,check=True).stdout
            if 'Mach-O' not in output_file or actual['architecture'] not in output_file:
                raise RuntimeError('NATIVE_MACH_O_IDENTITY_REQUIRED')
            report['native_executable_format']=output_file.strip()
        for name,count in [('native_acceptance',15),('installer_acceptance',5),('download_acceptance',5)]:
            run(name,[sys.executable,str(root/'tests'/(name+'.py'))],count)
        doctor="""import sys,unittest
sys.path.insert(0,'tests')
from doctor_acceptance import DoctorAcceptance
names=[name for name in DoctorAcceptance.__dict__ if name.startswith('test_') and name!='test_failed_local_request_stays_visible_without_crashing_host']
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(DoctorAcceptance(name) for name in names))
raise SystemExit(not result.wasSuccessful())
"""
        run('portable-doctor',[sys.executable,'-c',doctor],5)
        run('optional-python-contracts',[sys.executable,'-m','unittest','discover','-s',str(root/'tests'),'-p','test_*.py'],39)
        node=shutil.which('node',path=env.get('PATH'))
        if node is None:raise RuntimeError('PREINSTALLED_TEST_NODE_REQUIRED; no runtime download attempted')
        run('ui-state-contracts',[node,str(root/'tests/host_ui.test.cjs')],15)
        cargo=shutil.which('cargo',path=env.get('PATH'))
        if cargo is None:raise RuntimeError('PREINSTALLED_RUST_TOOLCHAIN_REQUIRED; no toolchain download attempted')
        run('native-parser-unit',[cargo,'test','--manifest-path',str(root/'native-host/Cargo.toml'),'--target-dir',str(binary.parent.parent),'--release','--locked','--offline'],3)
        report['automated_test_count']=sum(check['tests'] or 0 for check in report['checks'])
        if report['automated_test_count']!=87:raise RuntimeError('INCOMPLETE_PORTABLE_MATRIX')
        artifact=output/'syncp-native-host';shutil.copy2(binary,artifact)
        setup=output/('Synforge-Setup-macOS-'+actual['architecture'] if actual['system']=='Darwin' else 'Synforge-Setup-Linux-local-validation')
        shutil.copy2(binary,setup)
        report['delivered_artifacts']=[{'file':p.name,'sha256':digest(p),'bytes':p.stat().st_size,'signed_release':False} for p in [artifact,setup]]
        report['result']='PASS_SCOPED_NATIVE_MACOS_BASE' if actual['system']=='Darwin' else 'PASS_LINUX_HARNESS_VALIDATION_ONLY'
        report['full_macos_product_qualified']=False
    except Exception as error:
        report['result']='FAIL';report['failure']=str(error);save();raise
    finally:save()
    print(json.dumps({'result':report['result'],'count':report['automated_test_count'],'full_macos_product_qualified':False}),flush=True)

if __name__=='__main__':main()
