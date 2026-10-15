// UI unit tests only. The fake DOM/transport cannot qualify a native host or runtime.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {test} = require("node:test");
const code = fs.readFileSync(path.join(__dirname, "../web/host.js"), "utf8");

function unitPage(fetch) {
  const elements = {};
  const get = id => elements[id] ||= {textContent: "", value: "dark", disabled: true, listeners: {}, addEventListener(event, fn) {const prior=this.listeners[event]; this.listeners[event] = prior ? (...args)=>{prior(...args);fn(...args);} : fn;}};
  let removed = false;
  const storage = new Map();
  const context = {URLSearchParams, location: {hash: "#capability=unit-test-capability", pathname: "/"},
    sessionStorage: {setItem:(key,value)=>storage.set(key,value),getItem:key=>storage.get(key),removeItem:key=>storage.delete(key)},
    history: {replaceState(...args) {assert.equal(args[2], "/"); removed = true;}},
    document: {getElementById: get, documentElement: {dataset: {}}}, fetch};
  vm.runInNewContext(code, context);
  return {elements, get, context, storage, removed: () => removed};
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const status = {api_version: 1, ok: true, host: {version: "unit-test-version", healthy: true, os: "unit-test", architecture: "none"},
  capabilities: {manage_proof: true}, preferences: {theme: "dark"}, generation: 1, interrupted_staging_files: 0,
  owned_process: {running: false, failed: false, last_exit_code: null, pid: null}};
const response = value => ({ok: true, status: 200, json: async () => value});

test("local capability leaves the URL and is not stored in DOM state", async () => {
  const requests = [];
  const page = unitPage(async (url, options) => {requests.push({url, options}); return response(status);});
  await flush();
  assert.equal(page.removed(), true);
  assert.equal(page.storage.get("syncp.local.capability"),"unit-test-capability");
  assert.equal(requests[0].options.headers.Authorization, "Bearer unit-test-capability");
  assert.equal(requests[0].options.credentials, "omit");
  assert.equal(JSON.stringify(page.elements).includes("unit-test-capability"), false);
  assert.equal(page.get("connection").textContent, "Host connected");
});

test("pending operation disables duplicate actions until verification finishes", async () => {
  let release;
  const requests = [];
  const page = unitPage(async (url) => {
    requests.push(url);
    if (url === "/api/v1/proof/start") return new Promise(resolve => {release = () => resolve(response({ok: true}));});
    return response(status);
  });
  await flush();
  page.get("start").listeners.click();
  assert.equal(page.get("start").disabled, true);
  assert.match(page.get("message").textContent, /Working/);
  page.get("start").listeners.click();
  assert.equal(requests.filter(p => p === "/api/v1/proof/start").length, 1);
  release();
  await flush();
  assert.equal(page.get("start").disabled, false);
});

test("refresh preserves unsaved theme selection and save commits the chosen value", async () => {
  const writes = [];
  let actual = "dark";
  const page = unitPage(async (url, options) => {
    if (url === "/api/v1/preferences") {
      const input = JSON.parse(options.body);
      writes.push(input); actual = input.theme;
      return response({ok: true});
    }
    return response({...status, preferences: {theme: actual}});
  });
  await flush();
  page.get("theme").value = "light";
  page.get("theme").listeners.change();
  page.get("refresh").listeners.click();
  await flush();
  assert.equal(page.get("theme").value, "light");
  page.get("save").listeners.click();
  await flush();
  assert.deepEqual(writes, [{theme: "light"}]);
  assert.equal(page.context.document.documentElement.dataset.theme, "light");
});

test("read capability cannot enable mutation controls", async () => {
  const page = unitPage(async () => response({...status, capabilities: {manage_proof: false}}));
  await flush();
  for (const id of ["start", "stop", "save"]) assert.equal(page.get(id).disabled, true);
});

test("failed operation remains visible and does not produce a success message", async () => {
  const page = unitPage(async url => url === "/api/v1/proof/start"
    ? {ok: false, status: 403, json: async () => ({ok: false, error: "MANAGE_CAPABILITY_REQUIRED"})}
    : response(status));
  await flush();
  page.get("start").listeners.click();
  await flush();
  assert.match(page.get("message").textContent, /Operation failed: MANAGE_CAPABILITY_REQUIRED/);
  assert.equal(page.get("connection").textContent, "Verification failed");
});

test("expired native capability is cleared and mutation controls remain disabled", async () => {
  const page = unitPage(async () => ({ok:false,status:401,json:async()=>({ok:false,error:"LOCAL_AUTHORIZATION_REQUIRED"})}));
  await flush();
  assert.equal(page.storage.has("syncp.local.capability"),false);
  for (const id of ["start","stop","save"]) assert.equal(page.get(id).disabled,true);
  assert.match(page.get("message").textContent,/LOCAL_AUTHORIZATION_REQUIRED/);
});

const providerConfig = {api_version:1,network_mode:"ONLINE",local_endpoint:"http://127.0.0.1:8092",local_model:"test-local-model",cloud_connection:"none",cloud_model:""};
const providerStatus = {ok:true,configuration:providerConfig,generation:1,cloud_models:[],job:{status:"IDLE"}};
function prepareProviderPage(page) {
  page.context.document.createElement = () => ({value:"",textContent:""});
  page.get("cloud-model").replaceChildren = function(...options) {this.options=options;this.value=options[0]?.value || "";};
}
test("provider approval compares field values, not JSON key order", async () => {
  const page = unitPage(async (url,options) => {
    if (url === "/api/v1/onboarding/status") return response(providerStatus);
    if (url === "/api/v1/onboarding/plan") {
      const input = JSON.parse(options.body);
      const sorted = Object.fromEntries(Object.keys(input).sort().map(key=>[key,input[key]]));
      return response({ok:true,configuration:sorted,plan_id:"unit-reviewed-plan",destination:"isolated-unit"});
    }
    if (url === "/api/v1/onboarding/approve") return response({ok:true});
    if (url === "/api/v1/onboarding/test") return response({ok:true});
    return response(status);
  });
  prepareProviderPage(page);await flush();
  page.get("provider-refresh").listeners.click();await flush();
  page.get("local-model").value="test-local-model";page.get("local-model").listeners.input();
  page.get("provider-plan").listeners.click();await flush();
  assert.equal(page.get("provider-approve").disabled,false);
  page.get("provider-approve").listeners.click();await flush();
  page.get("local-smoke").listeners.click();await flush();
  assert.doesNotMatch(page.get("provider-progress").textContent,/Save reviewed connection settings/);
});
test("changed selection invalidates an in-flight provider plan", async () => {
  let release;
  const page=unitPage(async (url,options)=>{
    if(url==="/api/v1/onboarding/status")return response(providerStatus);
    if(url==="/api/v1/onboarding/plan")return new Promise(resolve=>{const input=JSON.parse(options.body);release=()=>resolve(response({ok:true,configuration:input,plan_id:"stale-plan"}));});
    return response(status);
  });prepareProviderPage(page);await flush();page.get("provider-refresh").listeners.click();await flush();
  page.get("provider-plan").listeners.click();page.get("local-model").value="changed-after-planning";page.get("local-model").listeners.change();release();await flush();
  assert.equal(page.get("provider-approve").disabled,true);
  assert.match(page.get("provider-summary").textContent,/Settings changed while planning/);
});
test("saved cloud model survives refresh as unverified when the live catalog is absent", async ()=>{
  const configuration={...providerConfig,cloud_connection:"official-antigravity-subscription",cloud_model:"gemini-saved"};
  const page=unitPage(async url=>response(url==="/api/v1/onboarding/status"?{...providerStatus,configuration}:status));prepareProviderPage(page);await flush();
  page.get("provider-refresh").listeners.click();await flush();
  assert.equal(page.get("cloud-model").value,"gemini-saved");
  assert.match(page.get("cloud-model").options.find(o=>o.value==="gemini-saved").textContent,/availability unverified/);
});

test("Doctor offers repairs only for observed findings and verifies the reviewed action", async()=>{
  let pendingRecord=true;const writes=[];
  const page=unitPage(async(url,options)=>{
    if(url==="/api/v1/doctor/report")return response({ok:true,findings:pendingRecord?[{code:"INTERRUPTED_SETTINGS",severity:"warning",repair_recipe:"quarantine-interrupted-settings"}]:[]});
    if(url==="/api/v1/doctor/plan")return response({ok:true,recipe:"quarantine-interrupted-settings",plan_id:"reviewed-doctor-plan"});
    if(url==="/api/v1/doctor/repair"){writes.push(JSON.parse(options.body));pendingRecord=false;return response({ok:true,result:"VERIFIED"});}
    return response(status);
  });prepareProviderPage(page);
  page.get("doctor-recipe").replaceChildren=function(...options){this.options=options;this.value=options[0]?.value||"";};await flush();
  page.get("doctor-report").listeners.click();await flush();assert.equal(page.get("doctor-recipe").value,"quarantine-interrupted-settings");assert.equal(writes.length,0);
  page.get("doctor-plan").listeners.click();await flush();assert.equal(page.get("doctor-repair").disabled,false);
  page.get("doctor-repair").listeners.click();await flush();assert.deepEqual(writes,[{recipe:"quarantine-interrupted-settings",plan_id:"reviewed-doctor-plan",approved:true}]);
  assert.match(page.get("doctor-result").textContent,/VERIFIED/);assert.equal(page.get("doctor-plan").disabled,true);assert.equal(page.get("doctor-recipe").value,"");
});

test("initial native UI load reads saved provider state without cloud enumeration", async()=>{
  const calls=[];const configuration={...providerConfig,cloud_connection:"official-antigravity-subscription",cloud_model:"gemini-saved"};
  const page=unitPage(async url=>{calls.push(url);return response(url==="/api/v1/onboarding/status"?{...providerStatus,configuration}:status);});prepareProviderPage(page);await flush();
  assert.equal(page.get("network-mode").value,"ONLINE");assert.equal(page.get("cloud-model").value,"gemini-saved");assert.equal(calls.filter(url=>url==="/api/v1/onboarding/status").length,1);assert.equal(calls.includes("/api/v1/onboarding/test"),false);
});

// A rejected reviewed plan is an application result, not loss of host authorization.
test("rejected application plan preserves healthy host controls and exposes the cause", async () => {
  const page=unitPage(async url => url === "/api/v1/applications/plan/install"
    ? {ok:false,status:409,json:async()=>({ok:false,error:"APPLICATION_REQUIRES_REVIEW",detail:"APP_ALREADY_INSTALLED"})}
    : response(status));
  await flush();page.get("app-install").listeners.click();await flush();
  assert.match(page.get("message").textContent,/Operation failed: APPLICATION_REQUIRES_REVIEW: APP_ALREADY_INSTALLED/);
  assert.equal(page.get("connection").textContent,"Host connected");
  assert.equal(page.get("start").disabled,false);
  assert.equal(page.get("app-approve").disabled,true);
});


test("changing cloud connection clears foreign catalog and old quota approval", async()=>{
 const configuration={...providerConfig,cloud_connection:"official-antigravity-subscription",cloud_model:"gemini-old"};
 const page=unitPage(async url=>response(url==="/api/v1/onboarding/status"?{...providerStatus,configuration,cloud_models:["gemini-old"],cloud_catalog_connection:"official-antigravity-subscription"}:status));
 prepareProviderPage(page);await flush();page.get("provider-refresh").listeners.click();await flush();
 page.get("cloud-quota-approval").checked=true;page.get("cloud-connection").value="official-chatgpt-subscription";page.get("cloud-connection").listeners.change();
 assert.equal(page.get("cloud-model").value,"");assert.equal(page.get("cloud-model").options.length,1);assert.equal(page.get("cloud-quota-approval").checked,false);
 page.get("provider-refresh").listeners.click();await flush();
 assert.equal(page.get("cloud-model").options.some(o=>o.value==="gemini-old"),false);
 assert.equal(page.get("cloud-connection").value,"official-chatgpt-subscription");
});

test("delayed provider observation cannot replace newer user selections",async()=>{
 let release;let delayed=false;
 const page=unitPage(async url=>{
  if(url==="/api/v1/onboarding/status")return delayed?new Promise(resolve=>{release=()=>resolve(response({...providerStatus,cloud_models:["foreign-old"],cloud_catalog_connection:"official-antigravity-subscription"}));}):response(providerStatus);
  return response(status);
 });prepareProviderPage(page);await flush();page.get("provider-refresh").listeners.click();await flush();
 delayed=true;page.get("provider-refresh").listeners.click();await flush();
 page.get("cloud-connection").value="official-chatgpt-subscription";page.get("cloud-connection").listeners.change();release();await flush();
 assert.equal(page.get("cloud-model").value,"");assert.equal(page.get("cloud-model").options.some(o=>o.value==="foreign-old"),false);
 assert.equal(page.get("cloud-connection").value,"official-chatgpt-subscription");
});


test("public test marks only its exact connection and model as tested",async()=>{
 const configuration={...providerConfig,cloud_connection:"official-chatgpt-subscription",cloud_model:"gpt-selected"};
 const tested={...providerStatus,configuration,cloud_catalog_connection:configuration.cloud_connection,cloud_models:["gpt-selected","gpt-unverified"],job:{status:"SUCCEEDED",result:{ok:true,kind:"cloud-smoke",connection:configuration.cloud_connection,selected_model:"gpt-selected"}}};
 const page=unitPage(async url=>response(url==="/api/v1/onboarding/status"?tested:status));prepareProviderPage(page);await flush();page.get("provider-refresh").listeners.click();await flush();
 assert.match(page.get("cloud-model").options.find(o=>o.value==="gpt-selected").textContent,/public test passed/);
 assert.match(page.get("cloud-model").options.find(o=>o.value==="gpt-unverified").textContent,/access needs test/);
 assert.match(page.get("provider-summary").textContent,/General task execution is not qualified/);
});
