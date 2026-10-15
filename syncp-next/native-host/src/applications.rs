//! Fixed optional application recipes. Catalog metadata never becomes a command.
//! This qualification path activates an already verified, isolated upstream stage.
//! Download/bootstrap qualification is reported separately, not inferred from it.
use crate::{auth,discovery,state};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{fs,io,path::{Path,PathBuf},process::{Command,Stdio},time::Duration};

const OWNER:&[u8]=b"Synforge isolated optional application qualification v1\n";
const VERSION:&str="2026.1012.0";
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    api_version:u32,id:String,version:String,upstream:String,recipe:String,
    stage_sha256:String,stage_files:u64,stage_bytes:u64,lock_sha256:String,
    node_executable:PathBuf,node_sha256:String,port:u16,db_port:u16,qualification:String,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {api_version:u32,generation:u64,installed:bool,package:Prepared,unit:Option<Unit>}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Unit {name:String,invocation:String}
pub struct Applications {root:PathBuf,_lock:fs::File}
fn code(s:&str)->io::Error{io::Error::other(s.to_owned())}
fn private_dir(path:&Path)->io::Result<()> {
 if path.exists(){if fs::symlink_metadata(path)?.file_type().is_symlink()||!path.is_dir(){return Err(code("UNSAFE_APP_DIRECTORY"));}}
 else {fs::create_dir(path)?;#[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(path,fs::Permissions::from_mode(0o700))?;}}
 Ok(())
}
fn valid_digest(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f'))}
fn read_bounded<T:serde::de::DeserializeOwned>(path:&Path)->io::Result<T>{
 if fs::symlink_metadata(path)?.file_type().is_symlink()||path.metadata()?.len()>16384{return Err(code("UNSAFE_APP_RECORD"));}
 Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn inventory(root:&Path)->io::Result<(String,u64,u64)>{
 fn walk(root:&Path,current:&Path,out:&mut Vec<PathBuf>)->io::Result<()>{
  for row in fs::read_dir(current)? {let path=row?.path();let m=fs::symlink_metadata(&path)?;
   if m.file_type().is_symlink(){if !path.canonicalize()?.starts_with(root.canonicalize()?){return Err(code("APP_LINK_ESCAPES_STAGE"));}out.push(path);}
   else if m.is_dir(){walk(root,&path,out)?;}else if m.is_file(){out.push(path);}else{return Err(code("UNSUPPORTED_APP_FILE"));}
  }Ok(())
 }
 if fs::symlink_metadata(root)?.file_type().is_symlink(){return Err(code("UNSAFE_APP_STAGE"));}
 let mut files=Vec::new();walk(root,root,&mut files)?;// Sort full normalized file names, not Path components: a/file vs a.js.
 files.sort_by(|a,b|a.as_os_str().cmp(b.as_os_str()));let mut hash=Sha256::new();let(mut count,mut bytes)=(0,0);
 for p in files {let rel=p.strip_prefix(root).map_err(|_|code("INVALID_APP_STAGE"))?.to_str().ok_or_else(||code("NON_UTF8_APP_FILE"))?;
  if rel.contains(['\t','\n','\r']){return Err(code("INVALID_APP_FILE_NAME"));}
  let meta=fs::symlink_metadata(&p)?;
  let line=if meta.file_type().is_symlink(){let target=fs::read_link(&p)?;let target=target.to_str().ok_or_else(||code("NON_UTF8_APP_LINK"))?;if target.contains(['\t','\n','\r']){return Err(code("INVALID_APP_LINK"));}format!("L\t{rel}\t{target}\n")}
  else {#[cfg(unix)]let mode={use std::os::unix::fs::PermissionsExt;meta.permissions().mode()&0o777};#[cfg(not(unix))]let mode=0u32;count+=1;bytes+=meta.len();format!("F\t{rel}\t{mode}\t{}\t{}\n",meta.len(),discovery::sha256(&p)?)};hash.update(line.as_bytes());
 }
 Ok((format!("{:x}",hash.finalize()),count,bytes))
}
impl Applications {
 pub fn new(root:PathBuf)->io::Result<Self>{
  if !cfg!(all(target_os="linux",target_arch="x86_64")){return Err(code("OPTIONAL_RECIPE_NOT_QUALIFIED_ON_THIS_PLATFORM"));}
  if !root.is_absolute()||root.parent().is_none()||fs::symlink_metadata(&root)?.file_type().is_symlink(){return Err(code("INVALID_OPTIONAL_ROOT"));}
  let marker=root.join(".syncp-optional-test-owner");if fs::symlink_metadata(&marker)?.file_type().is_symlink()||fs::read(marker)?!=OWNER{return Err(code("UNOWNED_OPTIONAL_ROOT"));}
  let lock_path=root.join(".native-application.lock");
  if lock_path.exists()&&fs::symlink_metadata(&lock_path)?.file_type().is_symlink(){return Err(code("UNSAFE_APP_LOCK"));}
  let mut options=fs::OpenOptions::new();options.read(true).write(true).create(true);
  #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
  let lock=options.open(lock_path)?;fs2::FileExt::try_lock_exclusive(&lock).map_err(|_|code("OPTIONAL_ROOT_ALREADY_MANAGED"))?;
  Ok(Self{root,_lock:lock})
 }
 fn prepared(&self)->io::Result<Prepared>{let p:Prepared=read_bounded(&self.root.join(".syncp-qualified-stage.json"))?;
  if p.stage_sha256!="2985b51dee1d689e508b6a570fe320e6c5f1cbd8850daffa0035b550032b491b"||p.lock_sha256!="298afae79e8640fe5a039be0f1a13ff33a41b09c9690f498c4eb89168e2631e0"||p.node_sha256!="bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"||p.api_version!=1||p.id!="paperclip"||p.version!=VERSION||p.upstream!="https://github.com/paperclipai/paperclip"||p.recipe!="paperclip-prepared-linux-user-v1"||p.port==0||p.db_port==0||p.port==p.db_port||!valid_digest(&p.stage_sha256)||!valid_digest(&p.node_sha256)||!valid_digest(&p.lock_sha256){return Err(code("UNTRUSTED_OR_UNSUPPORTED_APP_MANIFEST"));}Ok(p)
 }
 fn records(&self)->io::Result<PathBuf>{let p=self.root.join("records");private_dir(&p)?;Ok(p)}
 fn activation(&self)->io::Result<Option<Activation>>{
  let dir=self.root.join("records");if !dir.exists(){return Ok(None);}if fs::symlink_metadata(&dir)?.file_type().is_symlink(){return Err(code("UNSAFE_APP_RECORDS"));}
  let mut entries=fs::read_dir(dir)?.filter_map(Result::ok).map(|x|x.path()).filter(|x|x.file_name().and_then(|x|x.to_str()).is_some_and(|x|x.starts_with("activation-")&&x.ends_with(".json"))).collect::<Vec<_>>();entries.sort();
  match entries.last(){None=>Ok(None),Some(path)=>{let a:Activation=read_bounded(path)?;if a.api_version!=1||a.package.id!="paperclip"||a.package.version!=VERSION||serde_json::to_value(&a.package)?!=serde_json::to_value(self.prepared()?)?{return Err(code("INVALID_APP_ACTIVATION"));}Ok(Some(a))}}
 }
 fn commit(&self,mut a:Activation)->io::Result<()> {a.generation=self.activation()?.map(|a|a.generation+1).unwrap_or(1);let p=self.records()?.join(format!("activation-{:016}.json",a.generation));state::write_new_private(&p,&serde_json::to_vec(&a)?)}
 fn version(&self,p:&Prepared)->PathBuf{self.root.join("versions").join(format!("{}-{}",p.version,&p.stage_sha256[..16]))}
 fn node(&self)->PathBuf{self.root.join("runtime").join("node")}
 fn environment(&self)->Vec<(String,String)>{
  let mut env=vec![("PATH".into(),format!("{}:/usr/bin:/bin",self.root.join("runtime").display())),("LANG".into(),"C.UTF-8".into()),("PAPERCLIP_TELEMETRY_DISABLED".into(),"1".into()),("DO_NOT_TRACK".into(),"1".into()),("PAPERCLIP_UPDATE_CHECK".into(),"0".into()),("PAPERCLIP_NO_BROWSER".into(),"1".into()),("PAPERCLIP_OPEN_ON_LISTEN".into(),"false".into()),("BETTER_AUTH_TELEMETRY".into(),"false".into())];
  for (key,part) in [("HOME","home"),("TMPDIR","tmp")]{env.push((key.into(),self.root.join(part).to_string_lossy().into_owned()));}env
 }
 fn control(&self,exe:&str,args:&[&str])->io::Result<String>{
  // Only source-defined native OS utilities. No catalog executable or shell interpolation.
  let path=match exe{"systemctl"=>"/usr/bin/systemctl","systemd-run"=>"/usr/bin/systemd-run",_=>return Err(code("UNSUPPORTED_OS_UTILITY"))};
  let mut c=Command::new(path);c.env_clear().env("PATH","/usr/bin:/bin");for key in ["XDG_RUNTIME_DIR","DBUS_SESSION_BUS_ADDRESS"]{if let Some(v)=std::env::var_os(key){c.env(key,v);}}
  let out=c.args(args).stdin(Stdio::null()).output()?;if !out.status.success() && !(exe=="systemctl" && args.get(1)==Some(&"show") && out.status.code()==Some(4) && String::from_utf8_lossy(&out.stdout).lines().any(|line|line=="LoadState=not-found")){return Err(code("USER_SERVICE_OPERATION_FAILED"));}if out.stdout.len()>16384{return Err(code("OVERSIZED_SERVICE_OBSERVATION"));}Ok(String::from_utf8_lossy(&out.stdout).into_owned())
 }
 fn unit_observation(&self,unit:&Unit)->io::Result<Value>{
  if !unit.name.starts_with("syncp-next-paperclip-")||!unit.name.ends_with(".service")||!unit.name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'.')||unit.invocation.len()!=32||!unit.invocation.bytes().all(|b|b.is_ascii_hexdigit()){return Err(code("INVALID_OWNED_APP_UNIT"));}
  let output=self.control("systemctl",&["--user","show",&unit.name,"--property=InvocationID,ActiveState,SubState,Result,KillMode,TimeoutStopUSec,FragmentPath,LoadState"])?;let mut values=std::collections::BTreeMap::new();for line in output.lines(){if let Some((k,v))=line.split_once('='){values.insert(k,v);}}
  if values.get("LoadState")==Some(&"not-found") && values.get("InvocationID")==Some(&"") {
   return Ok(json!({"running":false,"healthy":null,"failed":false,"expired":true,"unit":unit.name,"recorded_invocation_id":unit.invocation,"ownership":"previous transient invocation ended; no current process adopted","autostart":false}));
  }
  if values.get("InvocationID")!=Some(&unit.invocation.as_str()){return Err(code("APP_SERVICE_IDENTITY_CHANGED_OR_EXPIRED"));}
  let running=values.get("ActiveState")==Some(&"active");Ok(json!({"running":running,"failed":values.get("Result").is_some_and(|value|*value!="success"),"active_state":values.get("ActiveState"),"sub_state":values.get("SubState"),"result":values.get("Result"),"unit":unit.name,"invocation_id":unit.invocation,"ownership":"exact transient user-service invocation; never a PID or port","autostart":false,"kill_mode":values.get("KillMode"),"stop_timeout":values.get("TimeoutStopUSec")}))
 }
 fn check_config(&self,p:&Prepared)->io::Result<()> {
  let path=self.root.join("data/instances/default/config.json");let cfg:Value=read_bounded(&path)?;
  let data=self.root.join("data").canonicalize()?;
  for field in [cfg["database"]["embeddedPostgresDataDir"].as_str(),cfg["logging"]["logDir"].as_str(),cfg["storage"]["localDisk"]["baseDir"].as_str(),cfg["secrets"]["localEncrypted"]["keyFilePath"].as_str()]{let path=PathBuf::from(field.ok_or_else(||code("INVALID_ISOLATED_APP_CONFIG"))?);let parent=if path.exists(){path.canonicalize()?}else{path.parent().ok_or_else(||code("INVALID_APP_PATH"))?.canonicalize()?};if !parent.starts_with(&data){return Err(code("APP_CONFIG_ESCAPES_OWNED_DATA"));}}
  if cfg["server"]["host"]!="127.0.0.1"||cfg["server"]["bind"]!="loopback"||cfg["server"]["deploymentMode"]!="local_trusted"||cfg["server"]["port"].as_u64()!=Some(p.port as u64)||cfg["database"]["mode"]!="embedded-postgres"||cfg["database"]["embeddedPostgresPort"].as_u64()!=Some(p.db_port as u64)||cfg.get("llm").is_some(){return Err(code("ISOLATED_APP_CONFIG_REQUIRES_REVIEW"));}Ok(())
 }
 pub fn status(&self)->io::Result<Value>{
  let a=self.activation()?;let p=self.prepared()?;let mut process=json!({"running":false,"healthy":null,"failed":false,"ownership":"none"});
  if let Some(unit)=a.as_ref().and_then(|a|a.unit.as_ref()) {process=match self.unit_observation(unit){Ok(v)=>v,Err(_)=>json!({"running":null,"healthy":null,"ownership":"unverified or expired invocation; no automatic takeover"})};
   if process["running"]==true {let url=format!("http://127.0.0.1:{}/api/health",p.port);let agent=ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(5))).max_redirects(0).proxy(None).build().new_agent();
    let observed=agent.get(&url).call().ok().and_then(|mut r|{use std::io::Read;let mut b=Vec::new();r.body_mut().as_reader().take(16385).read_to_end(&mut b).ok()?;if b.len()>16384{return None;}serde_json::from_slice::<Value>(&b).ok()});
    process["healthy"]=json!(observed.as_ref().is_some_and(|h|h["status"]=="ok"&&h["version"]==p.version&&h["startupRecovery"]["phase"]=="ready"));process["upstream_health"]=observed.unwrap_or(Value::Null);
   }
  }
  Ok(json!({"api_version":1,"ok":true,"id":"paperclip","version":p.version,"installed":a.as_ref().is_some_and(|a|a.installed),"configured":self.check_config(&p).is_ok(),"process":process,"origin":format!("http://127.0.0.1:{}",p.port),"generation":a.map(|a|a.generation).unwrap_or(0),"installation_qualification":"prepared pinned upstream package; isolated Linux x64 only","fresh_machine_bootstrap":"UNAVAILABLE","independence":"upstream application and own Node runtime; transient unit may continue when SynCP exits","publication":"NOT_AUTHORIZED","additional_harness":self.harness_status()?}))
 }
 fn harness_status(&self)->io::Result<Value>{
  let binary=self.root.join("harness/opencode");
  let installed=binary.is_file()&&!fs::symlink_metadata(&binary)?.file_type().is_symlink()&&discovery::sha256(&binary)?=="e26aa101cfdc40f0e680baa609ff18f131bbc6b91c60fdc11b2b2e2cba7281a4";
  Ok(json!({"id":"opencode","version":"2.0.27","installed":installed,"executable":if installed{Some(binary)}else{None},"running":null,"healthy":null,"qualification":"exact native binary; public local artifact task qualified separately; no cloud or general task-quality inference","data_policy":"independent OpenCode instance; user data retained","paperclip_compatibility_adapter":self.root.join("harness/syncp-opencode-paperclip").is_file()}))
 }
 fn harness_plan(&self,operation:&str)->io::Result<Value>{
  let digest="e26aa101cfdc40f0e680baa609ff18f131bbc6b91c60fdc11b2b2e2cba7281a4";let binary=self.root.join("harness/opencode");let archive=self.root.join("archive/opencode-2.0.27");
  let source=match operation {"install-opencode"=>{if binary.exists(){return Err(code("HARNESS_ALREADY_INSTALLED"));}discovery::on_path("opencode").ok_or_else(||code("QUALIFIED_HARNESS_SOURCE_UNAVAILABLE"))?},"uninstall-opencode"=>binary.clone(),"restore-opencode"=>{if binary.exists(){return Err(code("HARNESS_ALREADY_INSTALLED"));}archive.clone()},_=>return Err(code("UNSUPPORTED_HARNESS_OPERATION"))};
  if !source.is_file()||fs::symlink_metadata(&source)?.file_type().is_symlink()||discovery::sha256(&source)?!=digest{return Err(code("HARNESS_SOURCE_INTEGRITY_FAILED"));}
  let mut plan=json!({"api_version":1,"ok":true,"application":"opencode","version":"2.0.27","operation":operation,"source":source,"root":self.root,"sha256":digest,"bytes":source.metadata()?.len(),"additional_download_bytes":0,"privileges":"ordinary user","data_policy":"preserve all independent instance data","startup_units_installed":false,"trusted_recipe":"source-defined pinned native binary copy/archive/restore only"});plan["plan_id"]=json!(format!("{:x}",Sha256::digest(serde_json::to_vec(&plan)?)));Ok(plan)
 }
 fn compatibility_plan(&self)->io::Result<Value>{
  let binary=self.root.join("harness/opencode");
  if fs::symlink_metadata(&binary)?.file_type().is_symlink()||discovery::sha256(&binary)?!="e26aa101cfdc40f0e680baa609ff18f131bbc6b91c60fdc11b2b2e2cba7281a4"{return Err(code("COMPAT_HARNESS_INTEGRITY_FAILED"));}
  let source=std::env::current_exe()?.canonicalize()?;let destination=self.root.join("harness/syncp-opencode-paperclip");
  if destination.exists(){return Err(code("COMPATIBILITY_ADAPTER_ALREADY_INSTALLED"));}
  let mut plan=json!({"api_version":1,"ok":true,"application":"opencode-paperclip-compatibility","version":env!("CARGO_PKG_VERSION"),"operation":"install-opencode-compat","source":source,"destination":destination,"sha256":discovery::sha256(&source)?,"bytes":source.metadata()?.len(),"root":self.root,"additional_download_bytes":0,"privileges":"ordinary user","startup_units_installed":false,"behavior":"add the official --standalone flag to models/run when absent; preserve all other arguments, environment, prompts, providers, permissions, output and task timeouts","upstream_files_modified":false});
  plan["plan_id"]=json!(format!("{:x}",Sha256::digest(serde_json::to_vec(&plan)?)));Ok(plan)
 }
 pub fn plan(&self,operation:&str)->io::Result<Value>{
  if operation=="install-opencode-compat"{return self.compatibility_plan();}
  if operation.ends_with("-opencode"){return self.harness_plan(operation);}
  if !["install","start","stop","restart","uninstall","restore"].contains(&operation){return Err(code("UNSUPPORTED_OPTIONAL_OPERATION"));}
  let p=self.prepared()?;let a=self.activation()?;let installed=a.as_ref().is_some_and(|a|a.installed);let mut observation=Value::Null;
  match operation {
   "install"=>{if installed{return Err(code("APP_ALREADY_INSTALLED"));}let stage=self.root.join(format!("stage-{}",p.version));let (digest,files,bytes)=inventory(&stage)?;if digest!=p.stage_sha256||files!=p.stage_files||bytes!=p.stage_bytes||discovery::sha256(&stage.join("package-lock.json"))?!=p.lock_sha256||discovery::sha256(&p.node_executable)?!=p.node_sha256{return Err(code("PREPARED_APP_INTEGRITY_FAILED"));}self.check_config(&p)?;},
   "restore"=>{if installed||!self.root.join("archive").join(format!("{}-{}",p.version,&p.stage_sha256[..16])).is_dir(){return Err(code("NO_ARCHIVED_APP_VERSION"));}},
   _=>{if !installed{return Err(code("APP_NOT_INSTALLED"));}if let Some(unit)=a.as_ref().and_then(|a|a.unit.as_ref()){observation=self.unit_observation(unit)?;}}
  }
  if ["start","restart"].contains(&operation){self.check_config(&p)?;if discovery::sha256(&self.node())?!=p.node_sha256{return Err(code("MANAGED_NODE_INTEGRITY_FAILED"));}let (digest,_,_)=inventory(&self.version(&p))?;if digest!=p.stage_sha256{return Err(code("INSTALLED_APP_INTEGRITY_FAILED"));}}
  let mut out=json!({"api_version":1,"ok":true,"operation":operation,"application":"paperclip","version":p.version,"root":self.root,"package":p,"activation":a,"process_observation":observation,"privileges":"ordinary user","startup_units_installed":false,"data_policy":"all instance data and keys retained; uninstall archives application bytes","trusted_recipe":"source-defined; catalog cannot supply executable/arguments/PID","runtime_deadline_seconds":0});
  let digest=Sha256::digest(serde_json::to_vec(&out)?);out["plan_id"]=json!(format!("{:x}",digest));Ok(out)
 }
 pub fn approve(&self,operation:&str,id:&str,approved:bool)->io::Result<Value>{
  if !approved{return Err(code("EXPLICIT_APP_APPROVAL_REQUIRED"));}let plan=self.plan(operation)?;if plan["plan_id"].as_str()!=Some(id){return Err(code("STALE_OPTIONAL_PLAN"));}
  if operation=="install-opencode-compat" {
   let source=std::env::current_exe()?.canonicalize()?;let destination=self.root.join("harness/syncp-opencode-paperclip");let temporary=self.root.join("harness/compatibility.pending");
   if temporary.exists(){return Err(code("INTERRUPTED_COMPATIBILITY_COPY_REQUIRES_REVIEW"));}
   fs::copy(source,&temporary)?;if discovery::sha256(&temporary)?!=plan["sha256"].as_str().unwrap_or(""){return Err(code("COMPATIBILITY_COPY_INTEGRITY_FAILED"));}
   #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&temporary,fs::Permissions::from_mode(0o700))?;}
   fs::rename(temporary,destination)?;return self.status();
  }
  if operation.ends_with("-opencode") {
   private_dir(&self.root.join("harness"))?;private_dir(&self.root.join("archive"))?;
   let binary=self.root.join("harness/opencode");let archive=self.root.join("archive/opencode-2.0.27");let source=PathBuf::from(plan["source"].as_str().ok_or_else(||code("INVALID_HARNESS_SOURCE"))?);
   match operation {"install-opencode"=>{let temporary=self.root.join("harness/opencode.pending");if temporary.exists(){return Err(code("INTERRUPTED_HARNESS_COPY_REQUIRES_REVIEW"));}fs::copy(source,&temporary)?;if discovery::sha256(&temporary)?!=plan["sha256"].as_str().unwrap_or(""){return Err(code("HARNESS_COPY_INTEGRITY_FAILED"));}#[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&temporary,fs::Permissions::from_mode(0o700))?;}fs::rename(temporary,binary)?;},"uninstall-opencode"=>{if archive.exists(){return Err(code("HARNESS_ARCHIVE_COLLISION"));}fs::rename(binary,archive)?;},"restore-opencode"=>{fs::rename(archive,binary)?;},_=>return Err(code("UNSUPPORTED_HARNESS_OPERATION"))}
   return self.status();
  }
  let p=self.prepared()?;let mut a=self.activation()?.unwrap_or(Activation{api_version:1,generation:0,installed:false,package:p.clone(),unit:None});
  match operation {
   "install"=>{private_dir(&self.root.join("versions"))?;private_dir(&self.root.join("runtime"))?;let node=self.node();if !node.exists(){let temporary=self.root.join("runtime/node.pending");if temporary.exists(){return Err(code("INTERRUPTED_NODE_COPY_REQUIRES_REVIEW"));}fs::copy(&p.node_executable,&temporary)?;if discovery::sha256(&temporary)?!=p.node_sha256{return Err(code("NODE_COPY_INTEGRITY_FAILED"));}#[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&temporary,fs::Permissions::from_mode(0o700))?;}fs::rename(temporary,&node)?;}if discovery::sha256(&node)?!=p.node_sha256{return Err(code("MANAGED_NODE_INTEGRITY_FAILED"));}let dest=self.version(&p);if dest.exists(){return Err(code("APP_VERSION_COLLISION"));}fs::rename(self.root.join(format!("stage-{}",p.version)),dest)?;a.installed=true;self.commit(a)?;},
   "start"=>self.start(a)?,
   "stop"=>{self.stop(&a)?;a.unit=None;self.commit(a)?;},
   "restart"=>{self.stop(&a)?;a.unit=None;self.commit(a.clone())?;self.start(a)?;},
   "uninstall"=>{self.stop(&a)?;private_dir(&self.root.join("archive"))?;let dest=self.root.join("archive").join(format!("{}-{}",p.version,&p.stage_sha256[..16]));if dest.exists(){return Err(code("APP_ARCHIVE_COLLISION"));}fs::rename(self.version(&p),dest)?;a.installed=false;a.unit=None;self.commit(a)?;},
   "restore"=>{let source=self.root.join("archive").join(format!("{}-{}",p.version,&p.stage_sha256[..16]));if inventory(&source)?.0!=p.stage_sha256{return Err(code("APP_ARCHIVE_INTEGRITY_FAILED"));}fs::rename(source,self.version(&p))?;a.installed=true;self.commit(a)?;},
   _=>return Err(code("UNSUPPORTED_OPTIONAL_OPERATION")),
  }self.status()
 }
 fn stop(&self,a:&Activation)->io::Result<()> {if let Some(unit)=&a.unit{if self.unit_observation(unit)?["expired"]==true{return Ok(());}self.control("systemctl",&["--user","stop",&unit.name])?;}Ok(())}
 fn start(&self,mut a:Activation)->io::Result<()> {
  if let Some(unit)=&a.unit{if self.unit_observation(unit)?["running"]==true{return Ok(());}}
  // Observe conflicts; never terminate or adopt a foreign listener.
  for port in [a.package.port,a.package.db_port]{let address=std::net::SocketAddr::from(([127,0,0,1],port));if std::net::TcpStream::connect_timeout(&address,Duration::from_secs(1)).is_ok(){return Err(code("FOREIGN_APP_PORT_CONFLICT"));}}
  let name=format!("syncp-next-paperclip-{}.service",auth::token().map_err(|_|code("RANDOM_SOURCE_FAILED"))?);let directory=self.version(&a.package);let cli=directory.join("node_modules/paperclipai/dist/index.js");
  let mut args=vec!["--user".to_owned(),"--quiet".into(),format!("--unit={name}"),"--property=Type=exec".into(),"--property=KillMode=control-group".into(),"--property=KillSignal=SIGINT".into(),"--property=TimeoutStopSec=infinity".into(),"--property=RuntimeMaxSec=infinity".into(),"--property=Restart=no".into(),"--property=UMask=0077".into(),format!("--property=WorkingDirectory={}",directory.display()),"/usr/bin/env".into(),"-i".into()];
  for(k,v)in self.environment(){args.push(format!("{k}={v}"));}args.extend([self.node().to_string_lossy().into_owned(),cli.to_string_lossy().into_owned(),"run".into(),"--no-repair".into(),"--data-dir".into(),self.root.join("data").to_string_lossy().into_owned()]);
  self.control("systemd-run",&args.iter().map(String::as_str).collect::<Vec<_>>())?;
  let invocation=self.control("systemctl",&["--user","show",&name,"--property=InvocationID","--value"])?;let invocation=invocation.trim().to_owned();if invocation.len()!=32{return Err(code("APP_UNIT_IDENTITY_UNAVAILABLE"));}a.unit=Some(Unit{name,invocation});self.commit(a)
 }
}

/// Small optional upstream compatibility entry point. Neither prompts nor models,
/// permissions, output, provider configuration or task deadlines are rewritten.
/// OpenCode 2 metadata commands need --standalone in an isolated app environment.
pub fn opencode_compat() -> io::Result<()> {
 if !cfg!(target_os="linux"){return Err(code("OPENCODE_COMPAT_NOT_QUALIFIED_ON_THIS_PLATFORM"));}
 let current=std::env::current_exe()?.canonicalize()?;
 let binary=current.parent().ok_or_else(||code("INVALID_COMPAT_LOCATION"))?.join("opencode");
 if fs::symlink_metadata(&binary)?.file_type().is_symlink()||discovery::sha256(&binary)?!="e26aa101cfdc40f0e680baa609ff18f131bbc6b91c60fdc11b2b2e2cba7281a4"{return Err(code("COMPAT_HARNESS_INTEGRITY_FAILED"));}
 let mut args=std::env::args().skip(1).collect::<Vec<_>>();
 if !matches!(args.first().map(String::as_str),Some("models"|"run"|"--version"|"--help")){return Err(code("UNSUPPORTED_COMPAT_COMMAND"));}
 if matches!(args.first().map(String::as_str),Some("models"|"run"))&&!args.iter().any(|a|a=="--standalone"){args.insert(1,"--standalone".into());}
 let mut command=Command::new(binary);command.args(args);
 #[cfg(unix)] {use std::os::unix::process::CommandExt;return Err(command.exec());}
 #[cfg(not(unix))] {Err(code("OPENCODE_COMPAT_NOT_QUALIFIED_ON_THIS_PLATFORM"))}
}
