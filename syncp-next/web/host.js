"use strict";
(() => {
  const fromFragment = new URLSearchParams(location.hash.slice(1)).get("capability");
  let token = fromFragment || "";
  try {
    if (fromFragment) sessionStorage.setItem("syncp.local.capability", fromFragment);
    else token = sessionStorage.getItem("syncp.local.capability") || "";
  } catch (_) { /* Per-tab persistence may be unavailable; the capability link still works. */ }
  // Retain at most for this browser tab/session. Never use persistent localStorage or leave it in a URL.
  history.replaceState(null, "", location.pathname);
  const el = id => document.getElementById(id);
  let pending = false;
  let editable = false;
  let themeDirty = false;
  let refreshSerial = 0;
  let recoveryPlan = null;
  let installPlan = null;
  let installerEnabled = false;
  let installRunning = false;
  let applicationEnabled = false;
  let applicationPlan = null;
  let applicationWaiting = false;
  let applicationPolling = false;
  async function request(path, body) {
    const headers = {Authorization: `Bearer ${token}`};
    const options = {headers, cache: "no-store", credentials: "omit"};
    if (body !== undefined) {
      options.method = "POST";
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const result = await response.json();
    if (!response.ok || !result.ok) {
      if (response.status === 401) {
        token = "";
        try { sessionStorage.removeItem("syncp.local.capability"); } catch (_) {}
      }
      const failure = new Error(result.detail ? `${result.error}: ${result.detail}` : result.error || `HTTP ${response.status}`);
      failure.status = response.status;
      throw failure;
    }
    return result;
  }
  function controls() {
    providerControls();
    doctorControls();
    for (const id of ["start", "stop", "save"]) el(id).disabled = pending || !editable;
    for (const id of ["refresh", "hardware-refresh", "applications-refresh", "events-refresh", "recovery-review"]) el(id).disabled = pending || !token;
    el("recovery-approve").disabled = pending || !editable || !recoveryPlan?.executable;
    for (const id of ["install-plan", "uninstall-plan", "restore-plan", "rollback-plan", "reconcile-plan"]) el(id).disabled = pending || !token || !installerEnabled || installRunning;
    el("install-approve").disabled = pending || !editable || !installPlan || installRunning;
    el("install-cancel").disabled = !editable || !installRunning;
    for (const id of ["app-install","app-start","app-stop","app-restart","app-uninstall","app-restore","app-install-opencode","app-uninstall-opencode","app-restore-opencode","app-install-opencode-compat"]) el(id).disabled = pending || !editable || !applicationEnabled;
    el("app-status").disabled = pending || !token || !applicationEnabled;
    el("app-approve").disabled = pending || !editable || !applicationPlan;
  }
  async function refresh() {
    const serial = ++refreshSerial;
    const result = await request("/api/v1/status");
    if (serial !== refreshSerial) return;
    editable = result.capabilities.manage_proof === true;
    installerEnabled = result.capabilities.installer_enabled === true;
    applicationEnabled = result.optional_applications === "PREPARED_LINUX_TEST_INSTALLATION";
    el("managed-application").hidden = !applicationEnabled;
    el("installer").hidden = !installerEnabled;
    el("installer-nav").hidden = !installerEnabled;
    el("connection").textContent = result.host.healthy === true ? "Host connected" : "Host health unknown";
    el("version").textContent = result.host.version;
    el("platform").textContent = `${result.host.os} · ${result.host.architecture}`;
    el("generation").textContent = String(result.generation);
    el("staging").textContent = String(result.interrupted_staging_files);
    const p = result.owned_process;
    el("process-state").textContent = p.running ? `Running · PID ${p.pid}` : p.failed ? "Failed" : "Stopped";
    el("exit-code").textContent = p.last_exit_code === null ? "Not observed" : String(p.last_exit_code);
    if (!themeDirty) el("theme").value = result.preferences.theme;
    document.documentElement.dataset.theme = result.preferences.theme;
    controls();
  }
  async function operate(operation) {
    if (pending) return;
    pending = true;
    el("message").textContent = "Working… Please wait for the verified result.";
    controls();
    try {
      await operation();
      await refresh();
      el("message").textContent = "State verified with the native host.";
    } catch (error) {
      if (error.status === 409) {
        // A rejected/stale application plan does not revoke a valid host capability.
        try { await refresh(); } catch (_) { editable = false; el("connection").textContent = "Verification failed"; }
      } else {
        editable = false;
        el("connection").textContent = "Verification failed";
      }
      el("message").textContent = `Operation failed: ${error.message}`;
    } finally {
      pending = false;
      controls();
    }
  }
  el("theme").addEventListener("change", () => { themeDirty = true; });
  el("refresh").addEventListener("click", () => operate(async () => {}));
  el("start").addEventListener("click", () => operate(() => request("/api/v1/proof/start", {})));
  el("stop").addEventListener("click", () => operate(() => request("/api/v1/proof/stop", {})));
  el("save").addEventListener("click", () => operate(async () => {
    await request("/api/v1/preferences", {theme: el("theme").value});
    themeDirty = false;
  }));
  el("hardware-refresh").addEventListener("click", () => operate(async () => {
    const result = await request("/api/v1/hardware");
    const h = result.observation;
    const gib = n => n === null || n === undefined ? "Unknown" : `${(n / 1024 ** 3).toFixed(1)} GiB`;
    el("hardware-summary").textContent = `${h.os.system} · ${h.os.architecture} · RAM ${gib(h.memory.total_bytes)} total, ${gib(h.memory.available_bytes)} available`;
    el("hardware-details").textContent = JSON.stringify(h, null, 2);
  }));
  el("applications-refresh").addEventListener("click", () => operate(async () => {
    const result = await request("/api/v1/components");
    el("applications-list").textContent = result.applications.map(app => `${app.name}: ${app.installed === true ? (app.managed ? "Managed installation" : "Executable discovered") : "Installation not established"}; ${app.healthy === true ? "healthy" : app.healthy === false ? "not ready" : "health unverified"}; installation ${app.installation_qualification.toLowerCase()}; ${app.managed ? "managed" : "unmanaged"}`).join("\n");
  }));
  function renderApplication(result, updateDetails = true) {
    const p = result.process;
    el("application-state").textContent = `Paperclip ${result.version} · ${result.installed ? "Installed" : "Not installed"} · ${p.running === true ? "Running" : p.running === false ? "Stopped" : "Lifecycle unknown"} · ${p.healthy === true ? "Healthy" : p.healthy === false ? "Not ready" : "Health unverified"}${p.failed === true ? " · Failed" : ""}`;
    if (updateDetails) el("app-observation").textContent = JSON.stringify(result, null, 2);
    applicationWaiting = p.running === true && p.healthy !== true && p.failed !== true;
    el("app-open").hidden = p.healthy !== true;
    if (p.healthy === true) el("app-open").href = result.origin;
  }
  el("app-status").addEventListener("click", () => operate(async () => renderApplication(await request("/api/v1/applications/status"))));
  for (const operation of ["install","start","stop","restart","uninstall","restore","install-opencode","uninstall-opencode","restore-opencode","install-opencode-compat"]) {
    el(`app-${operation}`).addEventListener("click", () => operate(async () => {
      applicationPlan = null;
      el("app-plan-details").textContent = "";
      applicationPlan = await request(`/api/v1/applications/plan/${operation}`);
      el("app-summary").textContent = `Review ${operation} for ${applicationPlan.application} ${applicationPlan.version}. Instance data and keys are retained. No autostart service is installed.`;
      el("app-plan-details").textContent = JSON.stringify(applicationPlan, null, 2);
    }));
  }
  el("app-approve").addEventListener("click", () => operate(async () => {
    if (!applicationPlan) throw new Error("Review an application plan first");
    const plan = applicationPlan; applicationPlan = null;
    renderApplication(await request("/api/v1/applications/approve", {operation:plan.operation,plan_id:plan.plan_id,approved:true}));
    el("app-summary").textContent = applicationWaiting ? "Application started. Waiting for observed readiness; no execution deadline." : "Application operation completed. Instance data retained.";
  }));
  async function applicationReadiness() {
    if (!applicationWaiting || applicationPolling || pending || !token || !applicationEnabled) return;
    applicationPolling = true;
    try {
      const result = await request("/api/v1/applications/status");
      // Preserve expanded/selected evidence; background observation only updates status.
      renderApplication(result, false);
      if (result.process.healthy === true) el("app-summary").textContent = "Paperclip is ready. Open the independent application when needed.";
    } catch (error) {
      applicationWaiting = false;
      el("app-summary").textContent = `Application observation failed: ${error.message}`;
    } finally { applicationPolling = false; }
  }
  if (typeof setInterval === "function") setInterval(applicationReadiness, 2000);
  el("events-refresh").addEventListener("click", () => operate(async () => {
    const result = await request("/api/v1/events");
    el("event-list").textContent = result.events.map(event => `${event.at_unix} · ${event.event} · settings generation ${event.generation}`).join("\n");
  }));
  el("recovery-review").addEventListener("click", () => operate(async () => {
    recoveryPlan = await request("/api/v1/recovery/plan");
    el("recovery-summary").textContent = recoveryPlan.executable ? `${recoveryPlan.observation.pending_records.length} unfinished settings record(s). This plan moves them to a preserved quarantine and keeps saved settings unchanged.` : "No interrupted settings need recovery.";
    el("recovery-plan").textContent = JSON.stringify(recoveryPlan, null, 2);
  }));
  el("recovery-approve").addEventListener("click", () => operate(async () => {
    if (!recoveryPlan?.executable) throw new Error("Review a current executable recovery plan first");
    await request("/api/v1/recovery/approve", {plan_id: recoveryPlan.plan_id, approved: true});
    recoveryPlan = null;
    el("recovery-summary").textContent = "Recovery verified: unfinished records preserved in quarantine; saved settings unchanged.";
    el("recovery-plan").textContent = "Recovery verified.";
  }));
  async function reviewInstallation(operation) {
    installPlan = await request(`/api/v1/installer/plan/${operation}`);
    el("install-plan-summary").textContent = `${operation.toUpperCase()} ${installPlan.component} ${installPlan.version} · Destination: ${installPlan.destination} · Source: ${installPlan.source} · Download: ${(installPlan.download_bytes/1024**2).toFixed(1)} MiB · Required space: ${(installPlan.disk_required_bytes/1024**2).toFixed(1)} MiB · Permissions: ${installPlan.privileges}. Saved user data is preserved; uninstall archives the managed binary.`;
    el("install-plan-details").textContent = JSON.stringify(installPlan,null,2);
  }
  for (const operation of ["install", "uninstall", "restore", "rollback", "reconcile"]) el(`${operation === "install" ? "install" : operation}-plan`).addEventListener("click", () => operate(() => reviewInstallation(operation)));
  el("install-approve").addEventListener("click", () => operate(async () => {
    if (!installPlan) throw new Error("Review an exact current plan first");
    await request("/api/v1/installer/approve", {operation:installPlan.operation,plan_id:installPlan.plan_id,approved:true});
    installRunning = true;
    installPlan = null;
  }));
  el("install-cancel").addEventListener("click", async () => {
    try { await request("/api/v1/installer/cancel",{});el("install-progress").textContent="Cancellation requested; waiting for observed worker termination."; }
    catch(error){el("install-progress").textContent=`Cancellation request failed: ${error.message}`;}
  });
  async function installerProgress() {
    if (!installerEnabled || !token) return;
    try {
      const result = await request("/api/v1/installer/status");
      const job = result.job;
      installRunning = ["RUNNING", "CANCEL_REQUESTED"].includes(job.status);
      el("install-progress").textContent = `${job.status} · ${job.phase || "idle"}${job.error ? ` · ${job.error}` : ""} · Active installation: ${result.installation.active?.version || "None"}${result.interrupted_transactions.length ? ` · Interrupted transactions: ${result.interrupted_transactions.length}` : ""}`;
      controls();
    } catch(error){el("install-progress").textContent=`Installation state could not be verified: ${error.message}`;}
  }
  if (typeof setInterval === "function") setInterval(installerProgress,500);
  let doctorPending = false;
  let doctorPlan = null;
  let doctorEpoch = 0;
  function doctorControls() {
    el("doctor-report").disabled = !token || doctorPending;
    el("doctor-plan").disabled = !editable || doctorPending || !el("doctor-recipe").value;
    el("doctor-repair").disabled = !editable || doctorPending || !doctorPlan;
  }
  async function doctorReport() {
    const result = await request("/api/v1/doctor/report");
    el("doctor-summary").textContent = result.findings.length ? result.findings.map(f => `${f.severity.toUpperCase()}: ${f.code}`).join(" · ") : "No problem observed by the implemented checks. Untested capabilities remain unqualified.";
    el("doctor-findings").textContent = JSON.stringify(result, null, 2);
    const names = {"quarantine-interrupted-settings":"Preserve interrupted settings in quarantine", "restart-owned-verification-fixture":"Restart failed owned verification process"};
    const previous = el("doctor-recipe").value;
    const recipes = result.findings.map(f => f.repair_recipe).filter(recipe => names[recipe]);
    const options = (recipes.length ? recipes : [""]).map(recipe => {
      const option = document.createElement("option");option.value=recipe;option.textContent=names[recipe] || "No automatic repair justified by these observations";return option;
    });
    el("doctor-recipe").replaceChildren(...options);
    if (recipes.includes(previous)) el("doctor-recipe").value=previous;
    if (!recipes.includes(doctorPlan?.recipe)) doctorPlan=null;
    doctorControls();
  }
  async function doctorOperate(operation) {
    if (doctorPending) return;
    doctorPending = true; doctorControls();
    try { await operation(); }
    catch(error) { el("doctor-result").textContent = `Doctor action rejected or failed: ${error.message}`; }
    finally { doctorPending = false; doctorControls(); }
  }
  el("doctor-recipe").addEventListener("change", () => {doctorPlan=null;++doctorEpoch;doctorControls();});
  el("doctor-report").addEventListener("click", () => doctorOperate(doctorReport));
  el("doctor-plan").addEventListener("click", () => doctorOperate(async () => {
    const epoch=doctorEpoch;
    const plan=await request("/api/v1/doctor/plan",{recipe:el("doctor-recipe").value});
    if(epoch!==doctorEpoch) throw new Error("Repair selection changed; review it again");
    doctorPlan=plan;el("doctor-plan-details").textContent=JSON.stringify(plan,null,2);
    el("doctor-result").textContent="Exact repair plan ready for review. No change has been made.";
  }));
  el("doctor-repair").addEventListener("click", () => doctorOperate(async () => {
    if(!doctorPlan) throw new Error("Review a current repair plan first");
    const reviewed=doctorPlan;
    const result=await request("/api/v1/doctor/repair",{recipe:reviewed.recipe,plan_id:reviewed.plan_id,approved:true});
    doctorPlan=null;el("doctor-result").textContent=`${result.result}: committed settings preserved; only the reviewed owned state changed.`;
    await refresh();await doctorReport();
  }));
  let providerPending = false;
  let providerRunning = false;
  let providerDirty = false;
  let providerPlan = null;
  let providerEpoch = 0;
  let providerModelSignature = null;
  let providerConfiguration = null;
  const providerFields = ["network-mode", "local-endpoint", "local-model", "cloud-connection", "cloud-model"];
  function providerControls() {
    for (const id of ["provider-refresh", "models-discover"]) el(id).disabled = !token || providerPending;
    for (const id of ["provider-plan", "local-probe", "local-smoke", "cloud-models", "cloud-smoke", "profile-review"]) el(id).disabled = !editable || providerPending || providerRunning;
    el("provider-approve").disabled = !editable || providerPending || providerRunning || !providerPlan;
    el("provider-cancel").disabled = !editable || !providerRunning;
    el("cloud-smoke").disabled ||= !el("cloud-quota-approval").checked;
  }
  function selectedProviderConfiguration() {
    return {api_version:1,network_mode:el("network-mode").value,local_endpoint:el("local-endpoint").value.trim(),local_model:el("local-model").value.trim(),cloud_connection:el("cloud-connection").value,cloud_model:el("cloud-connection").value === "none" ? "" : el("cloud-model").value};
  }
  for (const id of providerFields) for (const event of ["input", "change"]) el(id).addEventListener(event, () => {
    providerDirty = true;
    providerPlan = null;
    ++providerEpoch;
    el("provider-summary").textContent = "Settings changed. Review the current values before approving.";
    providerControls();
  });
  el("cloud-connection").addEventListener("change", () => {
    // Clear foreign-provider candidates synchronously, before any background reply.
    const option = document.createElement("option"); option.value = "";
    option.textContent = "Save this connection, then discover its model catalog";
    el("cloud-model").replaceChildren(option); providerModelSignature = null;
    el("cloud-quota-approval").checked = false;
    providerControls();
  });
  el("cloud-quota-approval").addEventListener("change", providerControls);
  async function providerRefresh() {
    const epoch = providerEpoch;
    const result = await request("/api/v1/onboarding/status");
    if (epoch !== providerEpoch) return;
    providerConfiguration = result.configuration;
    providerRunning = ["RUNNING", "CANCEL_REQUESTED"].includes(result.job.status);
    if (!providerDirty) {
      el("network-mode").value = result.configuration.network_mode;
      el("local-endpoint").value = result.configuration.local_endpoint;
      el("local-model").value = result.configuration.local_model;
      el("cloud-connection").value = result.configuration.cloud_connection;
    }
    const catalogMatches = !result.cloud_catalog_connection || result.cloud_catalog_connection === el("cloud-connection").value;
    const models = catalogMatches ? result.cloud_models : [];
    const publicTestPassed = result.job.status === "SUCCEEDED" && result.job.result?.kind === "cloud-smoke" && result.job.result.ok === true && result.job.result.connection === el("cloud-connection").value;
    const testedModel = publicTestPassed ? result.job.result.selected_model : null;
    const signature = JSON.stringify([el("cloud-connection").value, result.cloud_catalog_connection || "", models, result.configuration.cloud_connection, result.configuration.cloud_model, testedModel]);
    if (signature !== providerModelSignature) {
      providerModelSignature = signature;
      const previous = providerDirty ? el("cloud-model").value : result.configuration.cloud_model;
      const choices = ["", ...models];
      if (result.configuration.cloud_connection === el("cloud-connection").value && result.configuration.cloud_model && !choices.includes(result.configuration.cloud_model)) choices.push(result.configuration.cloud_model);
      const options = choices.map(model => {
        const option = document.createElement("option");
        option.value = model;
        option.textContent = model ? `${model}${testedModel === model ? " (public test passed)" : models.includes(model) ? " (catalog; access needs test)" : " (saved; availability unverified)"}` : "Select a model after ONLINE discovery";
        return option;
      });
      el("cloud-model").replaceChildren(...options);
      if (choices.includes(previous)) el("cloud-model").value = previous;
    } else if (!providerDirty && models.includes(result.configuration.cloud_model)) el("cloud-model").value = result.configuration.cloud_model;
    if (publicTestPassed && !providerDirty) el("provider-summary").textContent = `Public connection test passed for ${testedModel}. General task execution is not qualified.`;
    const job = result.job;
    el("provider-progress").textContent = `${job.status} · Saved mode: ${result.configuration.network_mode}${job.kind ? ` · ${job.kind}` : ""}${job.error ? ` · ${job.error}` : ""}${job.result?.error ? ` · ${job.result.error}` : ""}`;
    // Update the pre text, never recreate its enclosing details element or collapse it.
    const evidence = JSON.stringify(job, null, 2);
    if (el("provider-evidence").textContent !== evidence) el("provider-evidence").textContent = evidence;
    providerControls();
  }
  async function providerOperate(operation) {
    if (providerPending) return;
    providerPending = true;
    providerControls();
    try { await operation(); await providerRefresh(); }
    catch(error) { el("provider-progress").textContent = `Operation rejected or failed: ${error.message}`; }
    finally { providerPending = false; providerControls(); }
  }
  el("provider-refresh").addEventListener("click", () => providerOperate(async () => {}));
  el("models-discover").addEventListener("click", () => providerOperate(async () => {
    const result = await request("/api/v1/onboarding/models");
    el("models-summary").textContent = `${result.models.length} existing GGUF files discovered. No downloads or changes performed.`;
    el("models-details").textContent = JSON.stringify(result, null, 2);
  }));
  el("provider-plan").addEventListener("click", () => providerOperate(async () => {
    const epoch = providerEpoch;
    const result = await request("/api/v1/onboarding/plan", selectedProviderConfiguration());
    if (epoch !== providerEpoch) { el("provider-summary").textContent = "Settings changed while planning. Review the current values again."; return; }
    providerPlan = result;
    el("provider-summary").textContent = `${result.configuration.network_mode} · Local model: ${result.configuration.local_model || "None selected"} · Cloud: ${result.configuration.cloud_model || "None selected"} · Destination: ${result.destination}. No production settings or credentials change.`;
    el("provider-plan-details").textContent = JSON.stringify(result, null, 2);
  }));
  el("provider-approve").addEventListener("click", () => providerOperate(async () => {
    if (!providerPlan) throw new Error("Review the exact current configuration first");
    const approved = providerPlan;
    await request("/api/v1/onboarding/approve", {configuration:approved.configuration,plan_id:approved.plan_id,approved:true});
    providerPlan = null;
    const current = selectedProviderConfiguration();
    if (Object.keys(current).every(key => current[key] === approved.configuration[key])) providerDirty = false;
    el("provider-summary").textContent = "Independent connection settings saved. Connection health still requires a real test.";
  }));
  for (const kind of ["local-probe", "local-smoke", "cloud-models", "cloud-smoke"]) el(kind).addEventListener("click", () => providerOperate(async () => {
    if (providerDirty) throw new Error("Save reviewed connection settings before testing");
    await request("/api/v1/onboarding/test", {kind,cloud_quota_approved:kind === "cloud-smoke" && el("cloud-quota-approval").checked});
    if (kind === "cloud-smoke") el("cloud-quota-approval").checked = false;
  }));
  el("provider-cancel").addEventListener("click", () => providerOperate(() => request("/api/v1/onboarding/cancel", {})));
  el("profile-review").addEventListener("click", () => providerOperate(async () => {
    const result = await request("/api/v1/onboarding/recommend", {model_id:el("profile-model").value,backend:el("profile-backend").value,build:el("profile-build").value});
    el("profile-details").textContent = JSON.stringify(result, null, 2);
  }));
  if (typeof setInterval === "function") setInterval(async () => {
    if (!token || providerPending || !providerRunning) return;
    try { await providerRefresh(); }
    catch(error) { el("provider-progress").textContent = `Connection state unknown: ${error.message}`; }
  }, 750);

  // Read saved connection settings on initial load; this is local state, not cloud enumeration.
  if (token) operate(async () => {}).then(() => { if (token) providerOperate(async () => {}); });
})();
