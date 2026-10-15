# SynCP native macOS qualification candidate

Reviewed source/test package, 2026-10-14. The user authorized publication to `pomod/syncp-native-tests` and the two native macOS CI jobs. Qualification results must be read from the actual workflow run and its machine-readable receipts; this source package alone is not a macOS test result. This package is a development test candidate, not an audited open-source release or a new license grant.

## What the workflow will do

On GitHub's standard `macos-15` (Apple Silicon arm64) and `macos-15-intel` (x86_64) runners, check the actual OS/architecture, build this exact native Rust source using its pinned Cargo.lock, then run 87 declared checks. Verify native startup, security, owned processes, configuration restart persistence, actual base installation/uninstall/restore, data preservation, transfer failure/resume/recovery, five portable Doctor cases, optional Python contracts, UI state contracts and parser failure cases. Actual OS/CPU and Mach-O format must match; a Linux harness run cannot pass the macOS gate.

Use the runner's preinstalled Rust/Python/Node tools. Missing tools fail explicitly; no system packages, toolchain installers, model downloads or provider credentials are installed. Cargo may download the exact locked dependency graph from its standard registry. The base executable is independently exercised without developer runtimes on PATH by the installer tests. This does not claim that a preconfigured CI image is a pristine consumer Mac installation.

Publish only the unsigned native executable/setup entry point, sanitized test logs and a machine-readable receipt as a short-lived workflow artifact. Do not upload temporary state, session capabilities, personal home files, signing keys, API keys, model files or application databases. The diagnostic test harness has no general inference task deadline; GitHub's own job limits remain platform limits. No cloud inference runs.

The default workflow refuses private repositories and uses only standard public runners; no private-runner billing is authorized. Repository permissions are read-only, checkout credentials are not persisted, no secrets are referenced, and official actions are pinned to reviewed commit identities. It triggers on a source/workflow push or manual dispatch. A run is one verification job per architecture; failed checks remain failures.

## Limits

A successful run qualifies the named native base paths only. Full macOS GUI/default-browser opening, .app/.dmg delivery, Gatekeeper/signing, Metal/GPU models, actual local model switching, optional app bootstrap/supervision and macOS cloud CLI execution remain unqualified. The selected unit-style UI checks do not exercise a real Mac browser. Linux-specific onboarding/registry/CLI tests are excluded deliberately, not skipped and presented as macOS passes.

## Official references checked

- [GitHub native runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Public/free and private/quota billing](https://docs.github.com/en/actions/concepts/billing-and-usage)
- [Official checkout v5 identity](https://api.github.com/repos/actions/checkout/git/ref/tags/v5): `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`
- [Official upload-artifact v4 identity](https://api.github.com/repos/actions/upload-artifact/git/ref/tags/v4): `ea165f8d65b6e75b540449e92b4886f43607fa02`
