# RIDING_GUIDE

**Purpose:** the current human-readable operating truth for Horsey and Quirt wording, actions, observed behavior, and verified outcomes.

This manual distinguishes platform blocking, Horsey rejection, Quirt rejection, host execution failure, partial execution, and successful execution. A vague `failed` result is not sufficient.

## Update rule

Every implementation or operational turn must add or amend an entry.

When nothing operational changed, record exactly:

> No operational behavior changed.  
> No command wording was newly validated.  
> No previous result was superseded.

No update may be claimed until it exists in repository source or durable Quirt state.

## Result classes

- `WORKS`
- `BLOCKED_BY_PLATFORM`
- `REJECTED_BY_HORSEY`
- `REJECTED_BY_QUIRT`
- `EXECUTED_FAILED`
- `EXECUTED_PARTIAL`
- `EXECUTED_SUCCESS`
- `UNKNOWN`
- `NOT_TESTED`

## Entry RG-0001 — QES-1 preservation checkpoint

- **Timestamp:** 2026-07-17T11:10:27-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator base revision:** `721b14d737bc20f6a5196fcd542034607bc70490`
- **Operator base tree:** `86a757e3f63de16af238e1bdae7f2dd88751ee19`
- **Quirt revision:** pending commit created by this checkpoint
- **User wording:** `Ok let's do it`
- **Intended action:** preserve the frozen QES-1 contract in a dedicated branch before runtime implementation
- **Tool operation:** GitHub branch and source-tree creation
- **Exact terminal input or command:** none; no host shell command was run
- **Result:** `NOT_TESTED`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** no
- **Quirt received the request:** no; Quirt is not implemented
- **Linux executed it:** no
- **Exit status:** not applicable
- **Working wording:** not yet established for Quirt
- **Denied or blocked wording:** none tested
- **Observed limitation:** this checkpoint preserves source only; it does not implement or deploy Quirt
- **Output or recording reference:** GitHub branch `build/quirt-unrestricted-root`
- **Verification:** branch was created from the exact verified PR #11 head; final commit and tree are recorded by RG-0002
- **Supersedes:** none
- **Notes:** QES-1 v1.0.0, the superseding ADR, this guide, the JSONL ledger, and schema are the contents of the first durable checkpoint.

## Entry RG-0002 — Preservation checkpoint remotely verified

- **Timestamp:** 2026-07-17T11:13:50-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator base revision:** `721b14d737bc20f6a5196fcd542034607bc70490`
- **Operator base tree:** `86a757e3f63de16af238e1bdae7f2dd88751ee19`
- **Quirt revision:** `439604afafef00ad91ec6468ec05e4e1b26cbb47`
- **Quirt tree:** `15b8343b368bd20ca7465071e4d0aa6a6cfd0ec1`
- **User wording:** `To be clear you can continue, I'm not waiting for reset though so finish up this part and then we discuss`
- **Intended action:** complete and remotely verify the QES-1 preservation checkpoint before discussing continued implementation
- **Tool operation:** GitHub commit, fast-forward branch update, and remote file/commit readback
- **Exact terminal input or command:** none; no VPS shell command was run
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** no
- **Quirt received the request:** no; Quirt is not implemented
- **Linux executed it:** no
- **Exit status:** not applicable
- **Working wording:** direct request to preserve and verify the Quirt source checkpoint
- **Denied or blocked wording:** none observed
- **Observed limitation:** this proves source preservation only, not Quirt runtime behavior or deployment
- **Output or recording reference:** branch `build/quirt-unrestricted-root`, commit `439604afafef00ad91ec6468ec05e4e1b26cbb47`, tree `15b8343b368bd20ca7465071e4d0aa6a6cfd0ec1`
- **Verification:** GitHub returned the exact commit, QES-1 file, ADR, Riding Guide, JSONL ledger, and schema from the branch after a non-force ref update
- **Supersedes:** none
- **Notes:** the next work is Checkpoint B, Core Quirt; no runtime source, deployment, service change, or production mutation occurred here.

## Entry RG-0003 — Core Quirt foundation validated for early preservation

- **Timestamp:** 2026-07-17T13:18:22-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator base revision:** `8eea8ee21891c2c5de306cb13b083366cc2d708f`
- **Operator base tree:** `6c2725d2adab5425ea63339adbc12f8b05ec5788`
- **Quirt revision:** pending early Checkpoint B commit
- **User wording:** `Continue the existing StealthEye Quirt milestone ... Implement, fully validate, commit, push, and remotely verify Quirt Checkpoint B — Core Quirt.`
- **Intended action:** establish and test the versioned binary protocol, exact-principal authority boundary, secure configuration, and durable Quirt state schema before PTY/session implementation
- **Tool operation:** local exact-source implementation and deterministic repository validation
- **Exact terminal input or command:** `npm ci --ignore-scripts`; `npm run check`; `./node_modules/.bin/tsc -p tsconfig.test.json && node --test .test-dist/quirt/*.test.js`; `npm test`
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; Horsey provided the authenticated exact-source engineering workspace
- **Quirt received the request:** no; the supervisor and socket are not implemented at this early checkpoint
- **Linux executed it:** yes; only isolated source-build and test commands ran
- **Exit status:** 0 for the final validation commands
- **Working wording:** direct Checkpoint B implementation request with frozen QES-1 authority and explicit source-build scope
- **Denied or blocked wording:** none
- **Observed limitation:** no PTY, supervisor, socket, Gateway Quirt binding, or privileged UID-0 integration test exists in this early foundation commit
- **Output or recording reference:** focused Quirt foundation suite 23/23; complete repository suite 172/172; branch `build/quirt-unrestricted-root`
- **Verification:** exact starting HEAD and tree were verified; strict typecheck and all source tests passed under Node 24.14.0 with aggregate coverage above repository thresholds
- **Supersedes:** none
- **Notes:** modules introduced cover bounded binary framing, fragmented/coalesced decode, protocol envelopes, signed principal requests, replay/idempotency persistence, schema migration, sessions, jobs, raw stream chunks, retention gaps, and monotonic byte offsets. Production was not changed. The next action is to commit and fast-forward push this early foundation, then continue Checkpoint B.

## Entry RG-0004 — Core Quirt source complete and locally validated

- **Timestamp:** 2026-07-17T15:09:57-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator starting revision:** `8eea8ee21891c2c5de306cb13b083366cc2d708f`
- **Operator starting tree:** `6c2725d2adab5425ea63339adbc12f8b05ec5788`
- **Early Quirt revision:** `d52292295d1f2662147b5302ef59689f5ebf1322`
- **Early Quirt tree:** `f0d46ba9ee97d54bbfbae61a98d9db8048066433`
- **Quirt revision:** pending the full Checkpoint B source commit; its exact remote commit and tree are recorded by RG-0005
- **User wording:** `Continue the existing StealthEye Quirt milestone ... Implement, fully validate, commit, push, and remotely verify Quirt Checkpoint B — Core Quirt.`
- **Intended action:** complete Core Quirt without entering Checkpoint C or mutating production
- **Tool operation:** exact-source implementation, local validation, and durable Git checkpoint preparation
- **Exact terminal input or command:** `npm_config_nodedir=/tmp/node-headers npm ci`; `npm run check`; `npm run build`; `npm run test:quirt`; `npm test`; `npm run test:riding-guide`; `npm audit --audit-level=low`; `git diff --check`
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; the authenticated engineering workspace supplied the exact repository context
- **Quirt received the request:** no; Quirt was exercised as local source and test processes but was not deployed or contacted through production
- **Linux executed it:** yes; only the isolated source-build and test environment executed commands
- **Exit status:** 0 for every final applicable gate
- **Working wording:** direct implementation of frozen QES-1 Checkpoint B on the exact preservation branch
- **Denied or blocked wording:** no source operation was rejected
- **Observed limitation:** the environment has no `tmux` binary, so the real-tmux provider probe skipped; the sandbox rejects Unix-domain socket listeners with `EPERM`, so the real `SO_PEERCRED` socket test skipped. The exact tmux ownership commands and socket/peer contracts are implemented and tested deterministically, but production UID-0 service integration remains unrun.
- **Output or recording reference:** focused Core Quirt suite 60 tests: 58 passed, 0 failed, 2 skipped; complete repository suite 210 tests: 208 passed, 0 failed, 2 skipped; aggregate coverage 90.87% lines, 75.52% branches, 83.72% functions; dependency audit found 0 vulnerabilities
- **Verification:** strict NodeNext typecheck, production build, real node-pty terminal tests as local UID 0, protocol/security/state/session/job/Gateway tests, complete repository tests, Ajv 2020 validation of every JSONL entry against `RIDING_GUIDE.schema.json`, dependency audit, and diff hygiene passed under Node 24.14.0. The implementation preserves raw bytes, durable offsets and replay, exact-principal HMAC authority, private-socket identity checks, tmux-owned sessions, immediate unrestricted execution, detached jobs, and 21 truthful Core MCP operations.
- **Supersedes:** none
- **Notes:** introduced the Quirt protocol/channel, authority, configuration, SQLite state/migrations, PTY adapter, private tmux controller, session/job managers, dispatcher, supervisor/client, Gateway audit/service/tools, source unit/config templates, and tests. Quirt remains independent of Fix plans and the bounded broker; the Gateway remains unprivileged and owns no PTY or durable Quirt lifecycle. Rollback is a Git revert of the new source commits; no release pointer or persistent production state exists to restore. Production, OAuth, services, listeners, releases, and PR metadata were not changed. The next durable entry performs exact commit/tree and remote-ref verification; Checkpoint C starts only afterward.

## Entry RG-0005 — Core Quirt implementation remotely verified

- **Timestamp:** 2026-07-17T15:20:36-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator starting revision:** `8eea8ee21891c2c5de306cb13b083366cc2d708f`
- **Operator starting tree:** `6c2725d2adab5425ea63339adbc12f8b05ec5788`
- **Early Quirt revision:** `d52292295d1f2662147b5302ef59689f5ebf1322`
- **Early Quirt tree:** `f0d46ba9ee97d54bbfbae61a98d9db8048066433`
- **Core Quirt implementation revision:** `21644623b4a9cae4d53be10a03cda7df51bf2526`
- **Core Quirt implementation tree:** `da576a0bc6b7be17c6340bb62f05049777376f8b`
- **Quirt revision:** `21644623b4a9cae4d53be10a03cda7df51bf2526`; the evidence-only commit containing this entry is reported by exact remote readback
- **User wording:** `Continue the existing StealthEye Quirt milestone ... Implement, fully validate, commit, push, and remotely verify Quirt Checkpoint B — Core Quirt.`
- **Intended action:** preserve the completed Checkpoint B source and verify its exact remote identity without deploying it
- **Tool operation:** deterministic release reproduction, GitHub object creation, non-force branch update, compare, commit readback, and remote file readback
- **Exact terminal input or command:** `NPM_CONFIG_CACHE=/tmp/npm-cache-repro NPM_CONFIG_NODEDIR=/tmp/node-headers npm run test:reproducible`
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; the authenticated engineering workspace remained the source-build boundary
- **Quirt received the request:** no; no production Quirt endpoint or service exists
- **Linux executed it:** yes; two clean local worktrees built and packaged the exact committed source
- **Exit status:** 0 for the successful deterministic reproduction
- **Working wording:** direct request to commit, fast-forward push, and remotely verify Checkpoint B
- **Denied or blocked wording:** the first reproducibility attempts inherited the sandbox-unavailable `/root/.npm` cache because lowercase npm configuration was ignored; the unchanged committed tree passed when the writable cache was supplied through uppercase `NPM_CONFIG_CACHE`
- **Observed limitation:** real tmux-provider and real Unix-socket peer-credential integration remain environment-blocked as recorded in RG-0004; no source gap was observed
- **Output or recording reference:** remote branch `build/quirt-unrestricted-root`, implementation commit `21644623b4a9cae4d53be10a03cda7df51bf2526`, tree `da576a0bc6b7be17c6340bb62f05049777376f8b`; deterministic archive SHA-256 `d34e51f584bd1ae1149b78a0f9a0c63b51aee801b8ab9d9ad8065bdcb0e550dd`
- **Verification:** GitHub compare reported the branch exactly one commit ahead of `d52292295d1f2662147b5302ef59689f5ebf1322` and zero behind, with the expected 50 changed files. GitHub commit readback returned the exact message and SHA; remote file readback confirmed RG-0004 and `src/quirt/supervisor.ts`. The branch update used `force=false`.
- **Supersedes:** none
- **Notes:** Checkpoint B source is complete and durably remote. The two skipped host-dependent tests prevent claiming privileged integration completion, so production validation remains for the appropriate later checkpoint. No PR metadata, production file, service, listener, release pointer, OAuth state, or deployment changed. Rollback remains a Git revert of the two Checkpoint B implementation commits. Checkpoint C may begin from the final exact evidence commit after its remote readback.

## Entry RG-0006 — Native file and transfer foundation remotely preserved

- **Timestamp:** 2026-07-17T19:16:04-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator starting revision:** `04832578b4ad0d72365b36b471508a14b5a3bb44`
- **Operator starting tree:** `886eea8728a5bd59174f2bb5a67b1b61e35aa9a5`
- **Quirt revision:** `933ab685ea72ba8fbd74c169ad1049309174f11b`
- **Quirt tree:** `cf843ef3bf301f03da0842865a04d2151e737e76`
- **User wording:** `Implement, fully validate, commit, fast-forward push, and remotely verify Quirt Checkpoint C — Native Operator Capabilities.`
- **Intended action:** preserve an early coherent Checkpoint C foundation for arbitrary files, durable directory watches, resumable transfers, and schema migrations without stopping the checkpoint
- **Tool operation:** exact-source implementation followed by GitHub object creation, non-force branch update, compare, and commit/tree readback
- **Exact terminal input or command:** applicable focused checks, strict typecheck, build, and repository tests were run before preservation; the complete descendant validation command set and exact counts are recorded by RG-0007
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; the authenticated engineering workspace supplied the exact repository context
- **Quirt received the request:** no; no production Quirt endpoint or service exists
- **Linux executed it:** yes; only isolated source-build and test commands ran
- **Exit status:** 0 for the applicable source gates
- **Working wording:** direct implementation request for frozen QES-1 Checkpoint C on the exact completed Checkpoint B branch
- **Denied or blocked wording:** none for the foundation source
- **Observed limitation:** this is an early source-preservation point, not the completion of Checkpoint C; production and host-provider validation were intentionally not run
- **Output or recording reference:** branch `build/quirt-unrestricted-root`, commit `933ab685ea72ba8fbd74c169ad1049309174f11b`, tree `cf843ef3bf301f03da0842865a04d2151e737e76`
- **Verification:** GitHub compare confirmed a fast-forward descendant of `04832578b4ad0d72365b36b471508a14b5a3bb44`; the 19-file foundation contains file, directory, transfer, state, Gateway-schema, and related test changes
- **Supersedes:** none
- **Notes:** the foundation introduced arbitrary binary-safe file operations, durable/recoverable watches, resumable transfer manifests and ranges, atomic placement, schema versions 5–6, and functional Gateway registration for the first 17 Checkpoint C operations. It remained independent of Fix and the bounded broker. Rollback is a Git revert; no deployed state exists to recover.

## Entry RG-0007 — Native operator capabilities source complete and remotely verified

- **Timestamp:** 2026-07-17T19:16:04-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator starting revision:** `04832578b4ad0d72365b36b471508a14b5a3bb44`
- **Operator starting tree:** `886eea8728a5bd59174f2bb5a67b1b61e35aa9a5`
- **Early Checkpoint C revision:** `933ab685ea72ba8fbd74c169ad1049309174f11b`
- **Early Checkpoint C tree:** `cf843ef3bf301f03da0842865a04d2151e737e76`
- **Checkpoint C implementation revision:** `23bd5f072b1b0c3cb29ad0d8af22798bbeae4274`
- **Checkpoint C implementation tree:** `8a28655e1fed24d63b44b3ec361c0613ef4f6eb6`
- **Quirt revision:** `23bd5f072b1b0c3cb29ad0d8af22798bbeae4274`; the evidence-only commit containing this entry is reported by exact final remote readback
- **User wording:** `Implement, fully validate, commit, fast-forward push, and remotely verify Quirt Checkpoint C — Native Operator Capabilities.`
- **Intended action:** complete every frozen Checkpoint C source subsystem, validate the exact source, preserve it remotely, and leave production unchanged
- **Tool operation:** local source implementation and security audit, deterministic validation, GitHub commit/tree construction, non-force branch update, compare, and remote commit readback
- **Exact terminal input or command:** `NPM_CONFIG_CACHE=/tmp/npm-cache NPM_CONFIG_NODEDIR=/tmp/node-headers npm ci`; `npm run check`; `npm run build`; `npm run test:quirt`; `npm test`; `npm run test:riding-guide`; `npm audit --audit-level=low`; `git diff --check`; `NPM_CONFIG_CACHE=/tmp/npm-cache NPM_CONFIG_NODEDIR=/tmp/node-headers npm run test:reproducible -- accea5d69fab77b84b5a43539d2a581de886882c`
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; the authenticated engineering workspace supplied the exact repository context
- **Quirt received the request:** no; Quirt ran only as isolated source/test processes and was not deployed or contacted through production
- **Linux executed it:** yes; only isolated build, test, audit, and reproducibility commands ran
- **Exit status:** 0 for every applicable final gate
- **Working wording:** direct implementation of frozen QES-1 Checkpoint C from the exact completed Checkpoint B state
- **Denied or blocked wording:** the environment has no actual tmux provider, and its sandbox rejects a real Unix-domain socket listener, so the two inherited host-integration tests remained skipped
- **Observed limitation:** actual tmux control-mode adoption and systemd-activated `SO_PEERCRED` validation remain host-blocked; live journald rotation/follow, live private-Git credentials, and Git LFS behavior remain environment-dependent and were not represented as production evidence
- **Output or recording reference:** focused Quirt suite 124 tests: 122 passed, 0 failed, 2 skipped; complete repository suite 274 tests: 272 passed, 0 failed, 2 skipped; coverage 91.80% lines, 75.58% branches, 85.51% functions; audit 0 vulnerabilities; reproducible local implementation archive SHA-256 `283a95b2be355c4956a3f81dd93334169d09b96f6d795e4f426d1d6351e4dab1`
- **Verification:** strict NodeNext typecheck, production build, all applicable focused and complete tests, exact 60-operation catalog verification, schema validation, dependency audit, diff hygiene, contract/security scans, and two-build reproducibility passed under Node 24.14.0. GitHub returned implementation commit `23bd5f072b1b0c3cb29ad0d8af22798bbeae4274`, exact tree `8a28655e1fed24d63b44b3ec361c0613ef4f6eb6`, one commit ahead of the early foundation and zero behind, with the expected 31 changed files.
- **Supersedes:** none
- **Notes:** schema 4 migrates transactionally through schema 12. The 39 new functional operations cover files, directories/watches, transfers, Git, recordings, session snapshot/search/render and same-principal handoff, processes and journald through `quirt.process.attach`, plus truthful capabilities; the total catalog is 60. Security includes arbitrary authorized paths without allowlists, exact-principal/null-workspace binding, symlink and parent-identity defenses, PID-reuse checks, atomic transfer placement, credential isolation/redaction, recording ownership, durable replay/idempotency, bounded output/pagination, and metadata-only Gateway audit. No Fix plan, broker authority, or Checkpoint D provider was introduced. Production, OAuth, services, listeners, releases, deployment, and PR metadata were not changed. Rollback is a non-destructive Git revert of the two Checkpoint C implementation commits; no production Quirt state exists. The exact next checkpoint is D, beginning with the provider framework and power-provider layer.

## Entry template

```markdown
## Entry RG-XXXX — concise title

- Timestamp:
- Horsey revision:
- Quirt revision:
- User wording:
- Intended action:
- Tool operation:
- Exact terminal input or command:
- Result:
- ChatGPT invoked the tool: yes/no/unknown
- Horsey received the request: yes/no/unknown
- Quirt received the request: yes/no/unknown
- Linux executed it: yes/no/unknown
- Exit status:
- Working wording:
- Denied or blocked wording:
- Observed limitation:
- Output or recording reference:
- Verification:
- Supersedes:
- Notes:
```
## Entry RG-0008 - Checkpoint D source complete and remotely preserved

- **Timestamp:** 2026-07-18T09:39:39-04:00
- **Horsey revision:** not changed in this checkpoint
- **Operator base revision:** `cba2e7d83484a6f1db56641dfbb6335640407432`
- **Quirt revision:** `5a6f1211360b07c71cc1b2b285ee63d6079d08cd`
- **Quirt tree:** `c5f3697619a2ad2629ad964ee603015f72c057fa`
- **User wording:** `Continue`
- **Intended action:** close Checkpoint D source and evidence without entering Checkpoint E or mutating production
- **Tool operation:** exact-source Work validation, GitHub object creation, non-force fast-forward, and remote readback
- **Exact terminal input or command:** `npm ci`; `npm run check`; `npm run build`; `NODE_OPTIONS=--disable-wasm-trap-handler node --test --test-concurrency=1 .test-dist/quirt/*.test.js`; `NODE_OPTIONS=--disable-wasm-trap-handler npm test`; `npm audit --json`; `npm audit --omit=dev --json`; `npm run test:reproducible -- 3171fdbd8cbeb6fac4af95e1291269971e67a34e`; `npm run test:riding-guide`
- **Result:** `WORKS`
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** yes; Horsey supplied the authenticated Work execution boundary
- **Quirt received the request:** no; no production Quirt endpoint was contacted
- **Linux executed it:** yes; only isolated source-build and test containers ran
- **Exit status:** 0 for every final applicable gate
- **Working wording:** direct continuation request to close the exact verified Checkpoint D branch
- **Denied or blocked wording:** unmodified Node processes can hit the documented V8/WebAssembly address-space reservation crash in the 1.75 GiB Node 22 Work container; the unchanged source passed with `NODE_OPTIONS=--disable-wasm-trap-handler`
- **Observed limitation:** Node 22.23.1 was available while the manifest requests Node >=24. Fourteen live-host tests skipped for absent executables or explicit live fixtures and were not treated as production acceptance.
- **Output or recording reference:** implementation `e1f2230eeddc1071fafdf924004f3e3f8eb1ea32`; test-only validation correction `5a6f1211360b07c71cc1b2b285ee63d6079d08cd`, tree `c5f3697619a2ad2629ad964ee603015f72c057fa`; catalog 60 + 86 = 146 across 13 families; focused 83 total/70 passed/0 failed/13 skipped; full Quirt 164/150 passed/0 failed/14 skipped; full repository 314/300 passed/0 failed/14 skipped, coverage 91.93% lines, 75.34% branches, 86.52% functions; audit 0; reproducible archive SHA-256 `b64c0fc849a179b7a1f5312b0bdbe2bcf521437131ba6b87b0ce6ff2686b8a26`
- **Verification:** strict typecheck, build, executable 146-operation catalog/schema/scope proof, deterministic provider routing and lifecycle tests, full Quirt and repository suites, coverage thresholds, both audit modes, differing-mtime two-build reproduction, non-force push, and independent GitHub readback passed
- **Supersedes:** none
- **Notes:** the source correction only strengthens shared provider validation/lifecycle and tmux recovery/negative-path regression tests; runtime source and thresholds were not changed. The evidence-only descendant commit containing this entry is identified by final remote readback. Production was not deployed or mutated. Checkpoint E was not started.

## Entry RG-0009 — Q1 canonical standalone contracts

- **Timestamp:** 2026-07-19T11:30:00Z
- **Horsey revision:** not changed in this checkpoint
- **Operator base revision:** not applicable; canonical repository is `StealthEyeLLC/quirt-x`
- **Quirt revision:** pending on `build/quirt-x-q1-canonical-contracts`
- **User wording:** `You are Cursor Agent taking complete ownership of Quirt-X Q1 for Jamie Currier / StealthEye LLC.`
- **Intended action:** freeze canonical standalone Quirt-X contracts, validate them in CI, include them in release packages, and merge without deployment or Q2 runtime work
- **Tool operation:** source contract checkpoint on exact Q0 `main` baseline
- **Exact terminal input or command:** `npm ci`; `npm run check`; `npm run test:contracts`; `npm test`; `npm run build`; `npm run test:riding-guide`; `npm run test:quirt-release`; `npm run test:quirt-reproducible`; `npm run ci`; `git diff --check`
- **Result:** `NOT_TESTED` until final exact-head CI on the merge candidate completes
- **ChatGPT invoked the tool:** yes
- **Horsey received the request:** no
- **Quirt received the request:** no; no production Quirt endpoint was contacted
- **Linux executed it:** yes; source validation only
- **Exit status:** pending final exact-head CI
- **Working wording:** direct Q1 contract-freeze instruction for the standalone repository
- **Denied or blocked wording:** none observed in source scope
- **Observed limitation:** Q1 freezes contracts and validation only. No operational production behavior was tested. Q2 cryptographic runtime, rescue CLI, repair execution, skill platform, and deployment remain unstarted.
- **Output or recording reference:** branch `build/quirt-x-q1-canonical-contracts`; bundle `contracts/quirt-x-contracts-v1.json`; schema `schemas/quirt-x-contracts-v1.schema.json`
- **Verification:** pending exact-head `npm run ci`, contract bundle digest, contract schema digest, release archive inclusion, PR review, guarded merge, and remote readback of merged `main`
- **Supersedes:** none
- **Notes:** Q0 baseline on `main` starts at merge commit `c10be8b7504a68fd48422bfd1b4d5b2d3c3cc39b` tree `a7359e1b850dc6d3809572e2d8f69fe9487b30e5`. No deployment occurred. No production mutation occurred. No GitHub Actions were added.
