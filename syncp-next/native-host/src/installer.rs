use crate::{auth, discovery, download, state};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::fs::{self,File,OpenOptions};
use std::io::{self,Read,Write};
use std::path::{Path,PathBuf};
use std::process::{Child,Command,Stdio};
use std::sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}};
use std::time::Duration;

const OWNER: &[u8]=b"Synforge managed native installation v1\n";
const EXE_NAME: &str=if cfg!(windows){"syncp-native-host.exe"}else{"syncp-native-host"};

#[derive(Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub version:String,
    pub sha256:String,
    pub bytes:u64,
    pub platform:String,
    pub architecture:String,
}

impl Package {
    fn key(&self)->io::Result<String> {
        if self.version.is_empty() || self.version.len()>80 || !self.version.bytes().all(|b|b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.sha256.len()!=64 || !self.sha256.bytes().all(|b|b.is_ascii_hexdigit()) || self.bytes==0
            || self.platform!=std::env::consts::OS || self.architecture!=std::env::consts::ARCH {
            return Err(io::Error::other("UNSUPPORTED_PACKAGE_IDENTITY"));
        }
        Ok(format!("{}-{}",self.version,self.sha256))
    }
}

#[derive(Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Activation { api_version:u32,generation:u64,active:Option<Package>,transaction:String,operation:String }

#[derive(Clone)]
pub struct Installer {
    root:PathBuf,
    source:PathBuf,
    package:Package,
    test_download_url:Option<String>,
    shared:Arc<Mutex<Value>>,
    cancelled:Arc<AtomicBool>,
    worker_handle:Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

fn code(name:&'static str)->io::Error { io::Error::other(name) }

pub fn check_owned_root(root:&Path)->io::Result<()> {
    if !root.is_absolute() || root.parent().is_none() || fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(code("INVALID_INSTALL_ROOT"));
    }
    let marker=root.join(".syncp-installation-owner");
    if fs::symlink_metadata(&marker)?.file_type().is_symlink() || fs::read(marker)?!=OWNER { return Err(code("UNOWNED_INSTALL_ROOT")); }
    Ok(())
}

pub fn safe_dir(root:&Path,name:&str)->io::Result<PathBuf> {
    if !["cache","versions","records","transactions","archive","quarantine"].contains(&name) { return Err(code("INVALID_OWNED_DIRECTORY")); }
    let path=root.join(name);
    if path.exists() {
        if fs::symlink_metadata(&path)?.file_type().is_symlink() || !path.is_dir() { return Err(code("UNSAFE_INSTALL_DIRECTORY")); }
    } else {
        fs::create_dir(&path)?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;fs::set_permissions(&path,fs::Permissions::from_mode(0o700))?; }
    }
    Ok(path)
}

fn activation(root:&Path)->io::Result<Activation> {
    if !root.exists() { return Ok(Activation{api_version:1,generation:0,active:None,transaction:String::new(),operation:"none".into()}); }
    check_owned_root(root)?;
    let records=root.join("records");
    if !records.exists() { return Ok(Activation{api_version:1,generation:0,active:None,transaction:String::new(),operation:"none".into()}); }
    if fs::symlink_metadata(&records)?.file_type().is_symlink() { return Err(code("UNSAFE_RECORD_DIRECTORY")); }
    let mut candidates=Vec::new();
    for entry in fs::read_dir(records)? {
        let entry=entry?;let name=entry.file_name().to_string_lossy().into_owned();
        if let Some(number)=name.strip_prefix("activation-").and_then(|s|s.strip_suffix(".json")) {
            let number=number.parse::<u64>().map_err(|_|code("INVALID_ACTIVATION_RECORD"))?;candidates.push((number,entry.path()));
        }
    }
    candidates.sort_by_key(|entry|entry.0);
    if let Some((number,path))=candidates.last() {
        if fs::symlink_metadata(path)?.file_type().is_symlink() || path.metadata()?.len()>8192 { return Err(code("UNSAFE_ACTIVATION_RECORD")); }
        let record:Activation=serde_json::from_slice(&fs::read(path)?).map_err(|_|code("CORRUPT_ACTIVATION_RECORD"))?;
        if record.api_version!=1 || record.generation!=*number { return Err(code("UNSUPPORTED_ACTIVATION_RECORD")); }
        if let Some(package)=&record.active { package.key()?; }
        Ok(record)
    } else { Ok(Activation{api_version:1,generation:0,active:None,transaction:String::new(),operation:"none".into()}) }
}

fn commit(root:&Path,old:&Activation,package:Option<Package>,id:&str,operation:&str)->io::Result<Activation> {
    let records=safe_dir(root,"records")?;
    let record=Activation{api_version:1,generation:old.generation.checked_add(1).ok_or_else(||code("GENERATION_OVERFLOW"))?,active:package,transaction:id.into(),operation:operation.into()};
    let pending=records.join(format!("activation-{:020}.pending",record.generation));
    let final_path=records.join(format!("activation-{:020}.json",record.generation));
    state::write_new_private(&pending,&serde_json::to_vec(&record)?)?;
    fs::rename(pending,final_path)?;
    #[cfg(unix)] File::open(&records)?.sync_all()?;
    Ok(record)
}

fn nearest_existing(mut path:&Path)->io::Result<&Path> {
    while !path.exists() { path=path.parent().ok_or_else(||code("DESTINATION_PARENT_UNAVAILABLE"))?; }
    Ok(path)
}

fn previous_package(root:&Path,current:&Activation)->io::Result<Package> {
    let active=current.active.as_ref().ok_or_else(||code("ROLLBACK_REQUIRES_ACTIVE_VERSION"))?;
    let records=root.join("records");if !records.is_dir(){return Err(code("NO_PREVIOUS_VERSION"));}
    if fs::symlink_metadata(&records)?.file_type().is_symlink(){return Err(code("UNSAFE_RECORD_DIRECTORY"));}
    let mut choices=Vec::new();
    for entry in fs::read_dir(records)? {
        let path=entry?.path();if path.extension().and_then(|n|n.to_str())!=Some("json"){continue;}
        if fs::symlink_metadata(&path)?.file_type().is_symlink() || path.metadata()?.len()>8192{return Err(code("UNSAFE_ROLLBACK_RECORD"));}
        let record:Activation=serde_json::from_slice(&fs::read(path)?)?;
        if record.api_version==1 && record.generation<current.generation{if let Some(package)=record.active{package.key()?;if package.sha256!=active.sha256{choices.push((record.generation,package));}}}
    }
    choices.sort_by_key(|p|p.0);choices.pop().map(|p|p.1).ok_or_else(||code("NO_PREVIOUS_DISTINCT_VERSION"))
}

fn archived_package(root:&Path)->io::Result<Package> {
    let archive=root.join("archive");if !archive.is_dir(){return Err(code("NO_ARCHIVED_VERSION"));}
    if fs::symlink_metadata(&archive)?.file_type().is_symlink(){return Err(code("UNSAFE_ARCHIVE_DIRECTORY"));}
    let mut choices=Vec::new();
    for entry in fs::read_dir(archive)?{
        let path=entry?.path();let name=path.file_name().and_then(|n|n.to_str()).unwrap_or("");
        if !path.is_dir() || name.len()!=64 || !name.bytes().all(|b|b.is_ascii_hexdigit()){continue;}
        if fs::symlink_metadata(&path)?.file_type().is_symlink(){return Err(code("UNSAFE_ARCHIVED_VERSION"));}
        let metadata=path.join("package.json");if !metadata.is_file() || metadata.metadata()?.len()>8192{continue;}
        let package:Package=serde_json::from_slice(&fs::read(&metadata)?)?;package.key()?;
        choices.push((path.metadata()?.modified().ok(),package));
    }
    choices.sort_by_key(|p|p.0);choices.pop().map(|p|p.1).ok_or_else(||code("NO_ARCHIVED_VERSION"))
}

fn interrupted_inventory(root:&Path)->io::Result<Vec<Value>> {
    let mut records=Vec::new();let folder=root.join("transactions");if !folder.exists(){return Ok(records);}
    if fs::symlink_metadata(&folder)?.file_type().is_symlink(){return Err(code("UNSAFE_TRANSACTION_DIRECTORY"));}
    for entry in fs::read_dir(folder)?{
        let path=entry?.path();let name=path.file_name().and_then(|n|n.to_str()).ok_or_else(||code("INVALID_TRANSACTION_NAME"))?;
        if name.len()!=64 || !name.bytes().all(|b|b.is_ascii_hexdigit()) || fs::symlink_metadata(&path)?.file_type().is_symlink(){return Err(code("UNSAFE_TRANSACTION_REQUIRES_REVIEW"));}
        let start=path.join("started.json");if path.is_dir() && start.is_file() && !path.join("finished.json").is_file(){
            if fs::symlink_metadata(&start)?.file_type().is_symlink() || start.metadata()?.len()>16384{return Err(code("UNSAFE_TRANSACTION_RECORD"));}
            records.push(json!({"id":name,"started_sha256":discovery::sha256(&start)?,"operation":"preserve this entire interrupted transaction directory in quarantine"}));
        }
    }
    records.sort_by(|a,b|a["id"].as_str().cmp(&b["id"].as_str()));Ok(records)
}

impl Installer {
    pub fn new(root:PathBuf,version:&str,test_download_url:Option<String>)->io::Result<Self> {
        if !root.is_absolute() || root.parent().is_none() || root.components().any(|p|matches!(p,std::path::Component::ParentDir)) { return Err(code("INVALID_INSTALL_DESTINATION")); }
        if let Some(url)=&test_download_url { download::validate_url(url,true)?;let uri:ureq::http::Uri=url.parse().map_err(|_|code("INVALID_TEST_SOURCE"))?;if uri.host()!=Some("127.0.0.1"){return Err(code("TEST_SOURCE_MUST_BE_LITERAL_LOOPBACK"));} }
        let source=std::env::current_exe()?.canonicalize()?;
        let package=Package{version:version.into(),sha256:discovery::sha256(&source)?,bytes:source.metadata()?.len(),platform:std::env::consts::OS.into(),architecture:std::env::consts::ARCH.into()};
        package.key()?;
        Ok(Self{root,source,package,test_download_url,shared:Arc::new(Mutex::new(json!({"status":"IDLE","cancel_requested":false}))),cancelled:Arc::new(AtomicBool::new(false)),worker_handle:Arc::new(Mutex::new(None))})
    }

    pub fn plan(&self,operation:&str)->io::Result<Value> {
        if !["install","uninstall","restore","reconcile","rollback"].contains(&operation) { return Err(code("UNSUPPORTED_INSTALL_OPERATION")); }
        if self.root.exists() {
            if fs::symlink_metadata(&self.root)?.file_type().is_symlink(){return Err(code("SYMLINK_DESTINATION_REJECTED"));}
            if self.root.read_dir()?.next().is_some(){check_owned_root(&self.root)?;}
        }
        let current=if self.root.exists() && self.root.read_dir()?.next().is_some(){activation(&self.root)?}else{Activation{api_version:1,generation:0,active:None,transaction:String::new(),operation:"none".into()}};
        let target_package=match operation {
            "install"=>Some(self.package.clone()),
            "uninstall"=>Some(current.active.clone().ok_or_else(||code("NO_ACTIVE_MANAGED_INSTALLATION"))?),
            "restore"=>Some(archived_package(&self.root)?),
            "rollback"=>Some(previous_package(&self.root,&current)?),
            "reconcile"=>current.active.clone(),
            _=>return Err(code("UNSUPPORTED_INSTALL_OPERATION")),
        };
        let interrupted=if operation=="reconcile"{interrupted_inventory(&self.root)?}else{Vec::new()};
        let free=fs2::available_space(nearest_existing(&self.root)?)?;
        let disk=self.package.bytes.checked_mul(3).and_then(|n|n.checked_add(1048576)).ok_or_else(||code("DISK_REQUIREMENT_OVERFLOW"))?;
        let source=match operation {
            "install"=>self.test_download_url.clone().unwrap_or_else(||format!("bundled-native-file:{}",self.source.display())),
            "uninstall"=>format!("managed active version under {}",self.root.join("versions").display()),
            "restore"=>format!("verified archived package under {}",self.root.join("archive").display()),
            "rollback"=>format!("previous committed package under {}",self.root.join("versions").display()),
            "reconcile"=>format!("exact interrupted records under {}",self.root.join("transactions").display()),
            _=>return Err(code("UNSUPPORTED_INSTALL_OPERATION")),
        };
        let mut plan=json!({"api_version":1,"ok":true,"operation":operation,"component":"syncp-native-base","version":target_package.as_ref().map(|p|p.version.clone()),
            "package":target_package,"source":source,"destination":self.root,"interrupted_records_to_preserve":interrupted,"current_generation":current.generation,"current_active":current.active,
            "download_bytes":if self.test_download_url.is_some(){self.package.bytes}else{0},"disk_required_bytes":if operation=="install"{disk}else{1048576},"disk_available_bytes":free,
            "dependencies":["standard native OS libraries; no Python, Node or Rust developer toolchain"],"privileges":"ordinary user","network_required":self.test_download_url.is_some(),
            "environment_changes":[],"service_changes":[],"model_downloads":[],"optional_applications":"UNAVAILABLE until their separate qualification",
            "signing":"unsigned development artifact; exact source-built identity is shown","rollback":"retain previous activation and preserve data; uninstall archives managed binaries",
            "approval_required":true,"task_timeout_seconds":0,"download_body_timeout_seconds":0,
            "connection_observation_timeout_seconds":10,"cancellation":"terminate only the exact owned native download helper; retain partial cache and report observed cancellation"});
        if operation=="install" && free<disk { return Err(code("INSUFFICIENT_DISK_SPACE")); }
        let mut normative=plan.clone();normative.as_object_mut().ok_or_else(||code("INVALID_PLAN"))?.remove("disk_available_bytes");
        let hash=format!("{:x}",Sha256::digest(serde_json::to_vec(&normative)?));plan["plan_id"]=json!(hash);
        Ok(plan)
    }

    pub fn status(&self)->io::Result<Value> {
        let job=self.shared.lock().map_err(|_|code("INSTALL_STATE_LOCK_FAILED"))?.clone();
        let installed=if self.root.exists() && self.root.read_dir()?.next().is_some(){activation(&self.root)?}else{Activation{api_version:1,generation:0,active:None,transaction:String::new(),operation:"none".into()}};
        let mut interrupted=Vec::new();
        let transactions=self.root.join("transactions");
        if transactions.exists() {
            if fs::symlink_metadata(&transactions)?.file_type().is_symlink(){return Err(code("UNSAFE_TRANSACTION_DIRECTORY"));}
            for entry in fs::read_dir(transactions)? {
                let p=entry?.path();let name=p.file_name().map(|n|n.to_string_lossy().into_owned());
                let live=["RUNNING","CANCEL_REQUESTED"].contains(&job["status"].as_str().unwrap_or("")) && job["transaction_id"].as_str()==name.as_deref();
                if p.is_dir() && !fs::symlink_metadata(&p)?.file_type().is_symlink() && p.join("started.json").is_file() && !p.join("finished.json").is_file() && !live {interrupted.push(name);}
            }
        }
        Ok(json!({"api_version":1,"ok":true,"job":job,"installation":installed,"interrupted_transactions":interrupted,"data_policy":"installer preserves user data; verification is recorded per transaction"}))
    }

    pub fn approve(&self,operation:&str,plan_id:&str,approved:bool)->io::Result<()> {
        if !approved { return Err(code("EXPLICIT_PLAN_APPROVAL_REQUIRED")); }
        let plan=self.plan(operation)?;
        if plan["plan_id"].as_str()!=Some(plan_id){return Err(code("STALE_INSTALL_PLAN"));}
        let mut state=self.shared.lock().map_err(|_|code("INSTALL_STATE_LOCK_FAILED"))?;
        if ["RUNNING","CANCEL_REQUESTED"].contains(&state["status"].as_str().unwrap_or("")){return Err(code("INSTALL_OPERATION_ALREADY_RUNNING"));}
        self.cancelled.store(false,Ordering::SeqCst);*state=json!({"status":"RUNNING","operation":operation,"phase":"approved","cancel_requested":false});drop(state);
        let manager=self.clone();let operation=operation.to_owned();let handle=std::thread::spawn(move||{
            let outcome=manager.execute(&operation,&plan);
            let final_state=match outcome {
                Ok(())=>json!({"status":"SUCCEEDED","operation":operation,"phase":"verified","cancel_requested":false}),
                Err(error)=>json!({"status":if error.to_string()=="USER_CANCELLED"{"CANCELLED"}else{"FAILED"},"operation":operation,"phase":"recovery_required_or_previous_activation_preserved","error":error.to_string(),"cancel_requested":manager.cancelled.load(Ordering::SeqCst)}),
            };
            if let Ok(mut state)=manager.shared.lock(){*state=final_state;}
        });
        *self.worker_handle.lock().map_err(|_|code("INSTALL_STATE_LOCK_FAILED"))?=Some(handle);
        Ok(())
    }

    pub fn cancel(&self)->io::Result<()> {
        self.cancelled.store(true,Ordering::SeqCst);let mut state=self.shared.lock().map_err(|_|code("INSTALL_STATE_LOCK_FAILED"))?;
        if state["status"]=="RUNNING"{state["status"]=json!("CANCEL_REQUESTED");state["cancel_requested"]=json!(true);}Ok(())
    }

    pub fn shutdown(&self)->io::Result<()> {
        self.cancel()?;
        let handle=self.worker_handle.lock().map_err(|_|code("INSTALL_STATE_LOCK_FAILED"))?.take();
        if let Some(handle)=handle {handle.join().map_err(|_|code("INSTALL_WORKER_SHUTDOWN_FAILED"))?;}
        Ok(())
    }

    fn phase(&self,name:&str)->io::Result<()> {
        if self.cancelled.load(Ordering::SeqCst){return Err(code("USER_CANCELLED"));}
        if let Ok(mut state)=self.shared.lock(){state["phase"]=json!(name);}Ok(())
    }

    fn initialize(&self)->io::Result<File> {
        if !self.root.exists(){fs::create_dir_all(&self.root)?;}
        if !self.root.join(".syncp-installation-owner").exists(){
            if self.root.read_dir()?.next().is_some(){return Err(code("UNOWNED_NONEMPTY_INSTALL_ROOT"));}
            #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&self.root,fs::Permissions::from_mode(0o700))?;}
            state::write_new_private(&self.root.join(".syncp-installation-owner"),OWNER)?;
        }
        check_owned_root(&self.root)?;
        let path=self.root.join("install.lock");if path.exists() && fs::symlink_metadata(&path)?.file_type().is_symlink(){return Err(code("INVALID_INSTALL_LOCK"));}
        let mut options=OpenOptions::new();options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
        let lock=options.open(path)?;lock.try_lock_exclusive()?;Ok(lock)
    }

    fn execute(&self,operation:&str,approved_plan:&Value)->io::Result<()> {
        self.phase("preflight")?;
        let _lock=self.initialize()?;let old=activation(&self.root)?;
        if approved_plan["current_generation"].as_u64()!=Some(old.generation) || approved_plan["current_active"]!=serde_json::to_value(&old.active)?{return Err(code("INSTALLATION_CHANGED_AFTER_APPROVAL"));}
        if operation=="reconcile" && approved_plan["interrupted_records_to_preserve"]!=serde_json::to_value(interrupted_inventory(&self.root)?)?{return Err(code("INTERRUPTED_RECORDS_CHANGED_AFTER_APPROVAL"));}
        let id=auth::token().map_err(|_|code("RANDOM_SOURCE_FAILED"))?;
        let transaction=safe_dir(&self.root,"transactions")?.join(&id);fs::create_dir(&transaction)?;
        if let Ok(mut status)=self.shared.lock(){status["transaction_id"]=json!(id);}
        state::write_new_private(&transaction.join("started.json"),&serde_json::to_vec(&json!({"operation":operation,"previous_activation":old,"package":self.package}))?)?;
        let result=match operation {
            "install"=>self.install(&old,&id,&transaction),
            "uninstall"=>self.uninstall(&old,&id,&transaction),
            "restore"=>self.restore(&old,&id,&transaction),
            "reconcile"=>self.reconcile(&old,&id,&transaction),
            "rollback"=>self.rollback(&old,&id,&transaction),
            _=>Err(code("UNSUPPORTED_INSTALL_OPERATION")),
        };
        let end=json!({"ok":result.is_ok(),"error":result.as_ref().err().map(|e|e.to_string()),"activation":activation(&self.root).ok()});
        state::write_new_private(&transaction.join("finished.json"),&serde_json::to_vec(&end)?)?;
        result
    }

    fn payload(&self)->io::Result<PathBuf> {
        let cache=safe_dir(&self.root,"cache")?;let verified=cache.join(format!("{}.verified",self.package.sha256));
        if verified.exists(){
            if fs::symlink_metadata(&verified)?.file_type().is_symlink() || discovery::sha256(&verified)?!=self.package.sha256{return Err(code("CACHE_INTEGRITY_FAILED"));}
            return Ok(verified);
        }
        if let Some(url)=&self.test_download_url {
            let spec=download::DownloadSpec{root:self.root.clone(),url:url.clone(),sha256:self.package.sha256.clone(),sha512:None,bytes:self.package.bytes,loopback_test:true};
            let mut guard=OwnedProbe{child:Command::new(&self.source).arg("--download-worker").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?};
            let child=&mut guard.child;
            if let Some(stdin)=child.stdin.as_mut(){stdin.write_all(&serde_json::to_vec(&spec)?)?;stdin.write_all(b"\n")?;stdin.flush()?;}
            if let Ok(mut status)=self.shared.lock(){status["download_helper_pid"]=json!(child.id());status["download_owner_lifeline"]=json!("anonymous parent pipe");}
            loop {
                if self.cancelled.load(Ordering::SeqCst){let _=child.kill();let _=child.wait();return Err(code("USER_CANCELLED"));}
                if let Some(status)=child.try_wait()?{if !status.success(){return Err(code("DOWNLOAD_OR_INTEGRITY_FAILED"));}break;}
                std::thread::sleep(Duration::from_millis(30));
            }
        } else {
            let staged=cache.join(format!("{}.partial",self.package.sha256));
            if staged.exists(){return Err(code("REVIEW_EXISTING_PARTIAL_BEFORE_LOCAL_COPY"));}
            let mut input=File::open(&self.source)?;let mut output=OpenOptions::new().write(true).create_new(true).open(&staged)?;let mut buffer=[0u8;65536];
            loop{self.phase("copying_verified_bundle")?;let n=input.read(&mut buffer)?;if n==0{break;}output.write_all(&buffer[..n])?;}
            output.sync_all()?;drop(output);
            if staged.metadata()?.len()!=self.package.bytes || discovery::sha256(&staged)?!=self.package.sha256{return Err(code("BUNDLED_PACKAGE_INTEGRITY_FAILED"));}
            fs::rename(staged,&verified)?;
        }
        if !verified.is_file() || discovery::sha256(&verified)?!=self.package.sha256{return Err(code("PAYLOAD_INTEGRITY_FAILED"));}
        Ok(verified)
    }

    fn install(&self,old:&Activation,id:&str,transaction:&Path)->io::Result<()> {
        self.phase("obtaining_pinned_package")?;let payload=self.payload()?;
        let staged=transaction.join("candidate");fs::create_dir(&staged)?;let executable=staged.join(EXE_NAME);fs::copy(payload,&executable)?;
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&executable,fs::Permissions::from_mode(0o700))?;}
        if discovery::sha256(&executable)?!=self.package.sha256{return Err(code("STAGED_INTEGRITY_FAILED"));}
        self.phase("native_acceptance")?;verify_native(&executable,&self.root.join("data"),&self.package.version,&self.cancelled)?;
        self.phase("activating_verified_version")?;
        let version=safe_dir(&self.root,"versions")?.join(self.package.key()?);
        if version.exists(){if fs::symlink_metadata(&version)?.file_type().is_symlink() || discovery::sha256(&version.join(EXE_NAME))?!=self.package.sha256{return Err(code("VERSION_CONFLICT"));}}
        else{fs::rename(&staged,&version)?;}
        commit(&self.root,old,Some(self.package.clone()),id,"install")?;
        state::write_new_private(&transaction.join("verified.json"),&serde_json::to_vec(&json!({"package":self.package,"native_acceptance":true,"activation_committed":true}))?)?;Ok(())
    }

    fn uninstall(&self,old:&Activation,id:&str,transaction:&Path)->io::Result<()> {
        let package=old.active.as_ref().ok_or_else(||code("NO_ACTIVE_MANAGED_INSTALLATION"))?;
        let source=safe_dir(&self.root,"versions")?.join(package.key()?).join(EXE_NAME);
        if fs::symlink_metadata(&source)?.file_type().is_symlink() || discovery::sha256(&source)?!=package.sha256{return Err(code("UNINSTALL_IDENTITY_MISMATCH"));}
        self.phase("archiving_managed_binary")?;let archive=safe_dir(&self.root,"archive")?.join(id);fs::create_dir(&archive)?;
        fs::rename(&source,archive.join(EXE_NAME))?;
        state::write_new_private(&archive.join("package.json"),&serde_json::to_vec(package)?)?;
        match commit(&self.root,old,None,id,"uninstall") { Ok(_)=>{},Err(error)=>{fs::rename(archive.join(EXE_NAME),&source)?;return Err(error);} }
        state::write_new_private(&transaction.join("verified.json"),b"{\"managed_binary_archived\":true,\"data_preserved\":true}")?;Ok(())
    }

    fn reconcile(&self,old:&Activation,id:&str,transaction:&Path)->io::Result<()> {
        self.phase("reconciling_interrupted_transactions")?;
        if let Some(package)=&old.active {
            let binary=safe_dir(&self.root,"versions")?.join(package.key()?).join(EXE_NAME);
            if fs::symlink_metadata(&binary)?.file_type().is_symlink() || discovery::sha256(&binary)?!=package.sha256{return Err(code("COMMITTED_VERSION_REQUIRES_MANUAL_RECOVERY"));}
        }
        let transactions=safe_dir(&self.root,"transactions")?;
        let quarantine=safe_dir(&self.root,"quarantine")?;
        for entry in fs::read_dir(&transactions)? {
            let path=entry?.path();if path==transaction{continue;}
            let name=path.file_name().and_then(|n|n.to_str()).ok_or_else(||code("INVALID_TRANSACTION_NAME"))?;
            if name.len()!=64 || !name.bytes().all(|b|b.is_ascii_hexdigit()) || fs::symlink_metadata(&path)?.file_type().is_symlink(){return Err(code("UNSAFE_TRANSACTION_REQUIRES_REVIEW"));}
            if path.is_dir() && path.join("started.json").is_file() && !path.join("finished.json").is_file(){
                self.phase("preserving_interrupted_transaction")?;
                fs::rename(&path,quarantine.join(format!("interrupted-{name}-{id}")))?;
            }
        }
        if activation(&self.root)?.generation!=old.generation{return Err(code("RECONCILIATION_CHANGED_COMMITTED_STATE"));}
        state::write_new_private(&transaction.join("verified.json"),b"{\"interrupted_records_preserved\":true,\"committed_activation_unchanged\":true}")?;
        Ok(())
    }

    fn rollback(&self,old:&Activation,id:&str,transaction:&Path)->io::Result<()> {
        let current=old.active.as_ref().ok_or_else(||code("ROLLBACK_REQUIRES_ACTIVE_VERSION"))?;
        let mut records=Vec::new();
        for entry in fs::read_dir(safe_dir(&self.root,"records")?)? {
            let path=entry?.path();if path.extension().and_then(|n|n.to_str())!=Some("json"){continue;}
            if fs::symlink_metadata(&path)?.file_type().is_symlink() || path.metadata()?.len()>8192{return Err(code("UNSAFE_ROLLBACK_RECORD"));}
            let record:Activation=serde_json::from_slice(&fs::read(&path)?)?;
            if record.generation<old.generation{records.push(record);}
        }
        records.sort_by_key(|r|r.generation);
        let package=records.into_iter().rev().filter_map(|r|r.active).find(|p|p.sha256!=current.sha256).ok_or_else(||code("NO_PREVIOUS_DISTINCT_VERSION"))?;
        let binary=safe_dir(&self.root,"versions")?.join(package.key()?).join(EXE_NAME);
        if fs::symlink_metadata(&binary)?.file_type().is_symlink() || discovery::sha256(&binary)?!=package.sha256{return Err(code("PREVIOUS_VERSION_INTEGRITY_FAILED"));}
        self.phase("verifying_previous_native_version")?;verify_native(&binary,&self.root.join("data"),&package.version,&self.cancelled)?;
        self.phase("activating_verified_rollback")?;commit(&self.root,old,Some(package),id,"rollback")?;
        state::write_new_private(&transaction.join("verified.json"),b"{\"previous_version_verified\":true,\"user_data_unchanged\":true}")?;Ok(())
    }

    fn restore(&self,old:&Activation,id:&str,transaction:&Path)->io::Result<()> {
        if old.active.is_some(){return Err(code("RESTORE_REQUIRES_NO_ACTIVE_VERSION"));}
        let archive=safe_dir(&self.root,"archive")?;let mut entries=fs::read_dir(archive)?.filter_map(Result::ok).collect::<Vec<_>>();entries.sort_by_key(|e|e.metadata().and_then(|m|m.modified()).ok());
        let entry=entries.last().ok_or_else(||code("NO_ARCHIVED_VERSION"))?;let folder=entry.path();
        if fs::symlink_metadata(&folder)?.file_type().is_symlink(){return Err(code("UNSAFE_ARCHIVED_VERSION"));}
        let package:Package=serde_json::from_slice(&fs::read(folder.join("package.json"))?)?;let key=package.key()?;let source=folder.join(EXE_NAME);
        if fs::symlink_metadata(&source)?.file_type().is_symlink() || discovery::sha256(&source)?!=package.sha256{return Err(code("ARCHIVE_INTEGRITY_FAILED"));}
        self.phase("verifying_archived_native_version")?;verify_native(&source,&self.root.join("data"),&package.version,&self.cancelled)?;
        self.phase("restoring_verified_version")?;let version=safe_dir(&self.root,"versions")?.join(key);if !version.exists(){fs::create_dir(&version)?;}
        if fs::symlink_metadata(&version)?.file_type().is_symlink() || version.join(EXE_NAME).exists(){return Err(code("RESTORE_DESTINATION_CONFLICT"));}
        fs::rename(&source,version.join(EXE_NAME))?;
        match commit(&self.root,old,Some(package),id,"restore"){Ok(_)=>{},Err(error)=>{fs::rename(version.join(EXE_NAME),&source)?;return Err(error);}}
        state::write_new_private(&transaction.join("verified.json"),b"{\"native_restore_verified\":true,\"data_preserved\":true}")?;Ok(())
    }
}

struct OwnedProbe { child:Child }
impl Drop for OwnedProbe {fn drop(&mut self){if self.child.try_wait().ok().flatten().is_none(){let _=self.child.kill();let _=self.child.wait();}}}

fn request(origin:&str,token:&str,path:&str,body:Option<Value>)->io::Result<Value> {
    let agent=ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(5))).max_redirects(0).proxy(None).build().new_agent();
    let mut response=match body {
        Some(body)=>agent.post(format!("{origin}{path}")).header("Authorization",format!("Bearer {token}")).header("Content-Type","application/json")
            .send(serde_json::to_vec(&body)?).map_err(|_|code("NATIVE_ACCEPTANCE_REQUEST_FAILED"))?,
        None=>agent.get(format!("{origin}{path}")).header("Authorization",format!("Bearer {token}")).call().map_err(|_|code("NATIVE_ACCEPTANCE_REQUEST_FAILED"))?,
    };
    let mut bytes=Vec::new();response.body_mut().as_reader().take(16385).read_to_end(&mut bytes)?;
    if bytes.len()>16384{return Err(code("OVERSIZED_ACCEPTANCE_RESPONSE"));}
    let value:Value=serde_json::from_slice(&bytes)?;if value["ok"]!=true{return Err(code("NATIVE_ACCEPTANCE_REJECTED"));}Ok(value)
}

fn launch_probe(executable:&Path,data:&Path,cancel:&AtomicBool)->io::Result<(OwnedProbe,Value)> {
    let child=Command::new(executable).args(["--data-dir",data.to_str().ok_or_else(||code("INVALID_DATA_PATH"))?]).env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let mut owned=OwnedProbe{child};
    loop {
        if cancel.load(Ordering::SeqCst){return Err(code("USER_CANCELLED"));}
        if owned.child.try_wait()?.is_some(){return Err(code("INSTALLED_NATIVE_HOST_FAILED_TO_START"));}
        if data.exists(){for entry in fs::read_dir(data)?{let p=entry?.path();let name=p.file_name().and_then(|n|n.to_str()).unwrap_or("");if name.starts_with("session-") && name.ends_with(".json") && p.metadata()?.len()<8192 {
            if let Ok(session)=serde_json::from_slice::<Value>(&fs::read(&p)?){if session["host_pid"].as_u64()==Some(owned.child.id() as u64){return Ok((owned,session));}}
        }}}
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stop_probe(owned:&mut OwnedProbe,session:&Value)->io::Result<()> {
    request(session["origin"].as_str().ok_or_else(||code("INVALID_SESSION"))?,session["manage_token"].as_str().ok_or_else(||code("INVALID_SESSION"))?,"/api/v1/host/stop",Some(json!({})))?;
    if !owned.child.wait()?.success(){return Err(code("NATIVE_HOST_STOP_FAILED"));}Ok(())
}

fn verify_native(executable:&Path,data:&Path,version:&str,cancel:&AtomicBool)->io::Result<()> {
    let (mut owned,session)=launch_probe(executable,data,cancel)?;
    let origin=session["origin"].as_str().ok_or_else(||code("INVALID_SESSION"))?;let token=session["manage_token"].as_str().ok_or_else(||code("INVALID_SESSION"))?;
    let health=request(origin,token,"/api/v1/health",None)?;if health["version"]!=version{return Err(code("NATIVE_VERSION_MISMATCH"));}
    let before=request(origin,token,"/api/v1/status",None)?;
    request(origin,token,"/api/v1/proof/start",Some(json!({})))?;
    if request(origin,token,"/api/v1/status",None)?["owned_process"]["running"]!=true{return Err(code("NATIVE_OWNED_START_FAILED"));}
    request(origin,token,"/api/v1/proof/stop",Some(json!({})))?;
    let stopped=request(origin,token,"/api/v1/status",None)?;
    if stopped["owned_process"]["running"]!=false || stopped["owned_process"]["last_exit_code"]!=0{return Err(code("NATIVE_OWNED_STOP_FAILED"));}
    request(origin,token,"/api/v1/preferences",Some(before["preferences"].clone()))?;stop_probe(&mut owned,&session)?;
    let (mut restarted,restart_session)=launch_probe(executable,data,cancel)?;
    let after=request(restart_session["origin"].as_str().ok_or_else(||code("INVALID_SESSION"))?,restart_session["manage_token"].as_str().ok_or_else(||code("INVALID_SESSION"))?,"/api/v1/status",None)?;
    if after["preferences"]!=before["preferences"]{return Err(code("NATIVE_CONFIGURATION_RESTART_FAILED"));}
    stop_probe(&mut restarted,&restart_session)
}


pub fn installed_data_root()->io::Result<Option<PathBuf>> {
    let executable=std::env::current_exe()?.canonicalize()?;
    let Some(version)=executable.parent() else{return Ok(None);};
    let Some(versions)=version.parent() else{return Ok(None);};
    if versions.file_name().and_then(|n|n.to_str())!=Some("versions"){return Ok(None);}
    let Some(root)=versions.parent() else{return Ok(None);};
    check_owned_root(root)?;
    let record=activation(root)?;
    let active=record.active.ok_or_else(||code("NO_ACTIVE_MANAGED_VERSION"))?;
    if version.file_name().and_then(|n|n.to_str())!=Some(active.key()?.as_str())
        || discovery::sha256(&executable)?!=active.sha256{return Err(code("VERSION_IS_NOT_THE_APPROVED_ACTIVE_INSTALLATION"));}
    Ok(Some(root.join("data")))
}
