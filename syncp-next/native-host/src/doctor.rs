//! Deterministic Doctor based on observed state. No model-generated repair authority.
use crate::{state::Store, owned_process::OwnedFixture};
use serde_json::{Value,json};
use std::io;
use sha2::{Digest,Sha256};
fn fault(code:&str)->io::Error{io::Error::other(code.to_owned())}
fn finding(code:&str,severity:&str,observation:Value,cause:&str,confidence:&str,action:&str,recipe:Option<&str>)->Value{
    json!({"code":code,"severity":severity,"observation":observation,"probable_cause":cause,"confidence":confidence,
        "proposed_intervention":action,"repair_recipe":recipe,"required_permission":if recipe.is_some(){"explicit exact-plan manage approval"}else{"manual review; no repair authority"},
        "verification":if recipe.is_some(){"re-observe repaired state and unchanged committed settings"}else{"observe the selected runtime/provider again after its owner resolves the issue"}})
}
pub fn inspect(store:&mut Store,fixture:&mut OwnedFixture,onboarding:&Value,installation:Option<Value>)->io::Result<Value>{
    store.observe_staging()?;let mut findings=Vec::new();
    match store.recovery_plan(){
        Ok(plan) if plan["executable"]==true=>findings.push(finding("INTERRUPTED_SETTINGS","warning",plan["observation"].clone(),"A write may have been interrupted; exact cause unknown","pending records observed","Preserve pending records in an owned quarantine; retain committed settings",Some("quarantine-interrupted-settings"))),
        Err(_)=>findings.push(finding("UNSAFE_STAGING_REQUIRES_MANUAL_REVIEW","error",json!({"reported_pending_files":store.interrupted_staging_files}),"Uncommitted records do not meet the bounded safe-recovery contract","unsafe inventory observed; cause unknown","Preserve evidence and review permissions, names and symlinks manually",None)),
        _=>{}
    }
    let process=fixture.observe()?;
    if process["failed"]==true {findings.push(finding("OWNED_VERIFICATION_PROCESS_FAILED","warning",process,"The owned harmless verification process exited unexpectedly","exit observed; exact cause unknown","Restart only the source-defined harmless fixture, not an inference service",Some("restart-owned-verification-fixture")));}
    let config=&onboarding["configuration"];
    let local=crate::onboarding::doctor_local(config);
    if local["available"]==false {findings.push(finding("LOCAL_ENDPOINT_UNAVAILABLE","warning",local,"The selected external endpoint did not return a valid model list","probe failed; server absence, startup, authentication and network causes not distinguished","Ask the runtime owner to inspect it; SynCP does not take ownership or kill a foreign process",None));}
    else if local["selected_available"]==false {findings.push(finding("SELECTED_LOCAL_MODEL_UNAVAILABLE","warning",local,"The explicit selected model is absent from the observed model list","model list mismatch observed","Review and approve the intended model ID or have the runtime owner switch it",None));}
    else if config["local_model"]=="" {findings.push(finding("LOCAL_MODEL_NOT_SELECTED","info",local,"No explicit local model has been selected","configuration observed","Select an observed model ID and review connection settings",None));}
    if config["network_mode"]=="OFFLINE" {findings.push(finding("CLOUD_DISABLED_BY_OFFLINE_MODE","info",json!({"network_mode":"OFFLINE","cloud_contact_performed":false}),"Intentional OFFLINE mode blocks cloud recipes","configuration observed","No repair needed; ONLINE access requires reviewed settings",None));}
    else if config["cloud_connection"]!="none" && !onboarding["cloud_models"].as_array().is_some_and(|ids|ids.contains(&config["cloud_model"])) {
        findings.push(finding("CLOUD_MODEL_AVAILABILITY_UNVERIFIED","unknown",json!({"selected_model":config["cloud_model"],"cloud_contact_performed":false}),"No current subscription-model enumeration confirms this saved selection","unknown availability, not a provider failure","Use explicit ONLINE model discovery; do not silently select another model",None));
    }
    if onboarding["job"]["status"]=="FAILED" {findings.push(finding("CONNECTION_TEST_FAILED","warning",onboarding["job"].clone(),"A connection test failed; quota, authentication or protocol cause requires evidence","failed test observed; cause may remain unknown","Inspect the redacted connection evidence and official provider diagnostics; no login or quota change is performed",None));}
    if let Some(installation)=installation {
        if installation["interrupted_transactions"].as_array().is_some_and(|v|!v.is_empty()){findings.push(finding("INTERRUPTED_INSTALLATION","warning",installation["interrupted_transactions"].clone(),"An owned installation transaction did not commit","transaction evidence observed","Review the installer reconciliation plan; preserve transaction records and committed activation",None));}
    }
    Ok(json!({"api_version":1,"ok":true,"doctor_version":1,"assessment":"rule-based observed diagnostics; no AI-generated repair executed","findings":findings,
        "network_policy":"local diagnostic probe only; no implicit cloud or model inference","local_probe_timeout_seconds":5,
        "scope":"independent host settings, owned verification fixture and selected connection observations","production_service_changes":false,"credentials_read":false}))
}
pub fn plan(store:&Store,fixture:&mut OwnedFixture,recipe:&str)->io::Result<Value>{
    let evidence=match recipe {
        "quarantine-interrupted-settings"=>{let p=store.recovery_plan()?;if p["executable"]!=true{return Err(fault("NO_INTERRUPTED_SETTINGS_TO_REPAIR"));}p},
        "restart-owned-verification-fixture"=>{let p=fixture.observe()?;if p["failed"]!=true||p["running"]==true{return Err(fault("NO_FAILED_OWNED_FIXTURE_TO_REPAIR"));}p},
        _=>return Err(fault("UNSUPPORTED_DOCTOR_REPAIR_RECIPE"))
    };
    let mut p=json!({"api_version":1,"ok":true,"doctor_version":1,"recipe":recipe,"evidence":evidence,
        "committed_settings_generation":store.generation,"settings":store.preferences,"destination":store.root(),"destructive":false,
        "required_permission":"explicit approval of exact plan with manage capability","production_service_changes":false,"credential_changes":false,
        "rollback":if recipe=="quarantine-interrupted-settings"{"pending bytes preserved in quarantine; committed state unchanged"}else{"stop only the newly owned harmless fixture"},
        "verification":if recipe=="quarantine-interrupted-settings"{"no pending records; identical committed generation and settings"}else{"owned fixture observed running; runtime health remains unassessed"}});
    p["plan_id"]=json!(format!("{:x}",Sha256::digest(serde_json::to_vec(&p)?)));Ok(p)
}
pub fn repair(store:&mut Store,fixture:&mut OwnedFixture,recipe:&str,plan_id:&str,approved:bool)->io::Result<Value>{
    if !approved{return Err(fault("EXPLICIT_REPAIR_APPROVAL_REQUIRED"));}
    let p=plan(store,fixture,recipe)?;if p["plan_id"]!=plan_id{return Err(fault("DOCTOR_REPAIR_PLAN_CHANGED"));}
    let generation=store.generation;let settings=store.preferences.clone();store.journal("doctor.repair_requested")?;
    match recipe {
        "quarantine-interrupted-settings"=>store.approve_recovery(p["evidence"]["plan_id"].as_str().ok_or_else(||fault("INVALID_RECOVERY_EVIDENCE"))?)?,
        "restart-owned-verification-fixture"=>fixture.start()?,
        _=>return Err(fault("UNSUPPORTED_DOCTOR_REPAIR_RECIPE"))
    }
    store.observe_staging()?;let process=fixture.observe()?;
    let verified=store.generation==generation&&store.preferences==settings && if recipe=="quarantine-interrupted-settings"{store.interrupted_staging_files==0}else{process["running"]==true&&process["failed"]==false};
    if !verified{return Err(fault("DOCTOR_POST_REPAIR_VERIFICATION_FAILED"));}
    store.journal("doctor.repair_verified")?;
    Ok(json!({"api_version":1,"ok":true,"recipe":recipe,"result":"VERIFIED","committed_settings_preserved":true,"generation":store.generation,
        "runtime_health":null,"scope":"owned harmless fixture or independent settings; no production runtime repair"}))
}
