# Quirt Engineering Specification

**Specification:** QES-1  
**Version:** 1.0.0  
**Status:** FROZEN FOR IMPLEMENTATION  
**Product:** StealthEye Horsey  
**Owner authority:** Jamie Currier / StealthEye LLC  
**Target:** the authorized StealthEye VPS  
**Milestone:** one complete source, deployment, and acceptance milestone

## 1. Product definition

Quirt is Horsey's persistent, reconnectable, fully interactive, unrestricted remote root operator.

Quirt shall provide the practical equivalent of a direct root login through a high-quality terminal application while being callable and controllable through Horsey. It is intended to replace Termius for routine engineering and operations.

Quirt shall provide:

- actual Linux UID 0 execution;
- persistent and reconnectable interactive terminal sessions;
- complete filesystem authority;
- unrestricted process execution and management;
- unrestricted network and socket authority;
- package-manager access;
- Git and private-repository access;
- complete systemd and journald access;
- mounts, namespaces, firewall, users, groups, permissions, devices, and kernel controls;
- interactive programs, editors, debuggers, REPLs, installers, and prompts;
- native file transfer;
- detached jobs;
- multiple concurrent sessions;
- terminal recording, replay, and operational learning;
- optional high-level accelerators that never restrict the underlying root shell.

Quirt is not a constrained command broker, plan executor, fixed administrative operation catalog, or rootless workspace.

## 2. Non-negotiable requirements

### 2.1 Unrestricted root

After an authorized Quirt session is established, Quirt shall not impose:

- executable allowlists;
- argument allowlists;
- path allowlists;
- package restrictions;
- service-unit restrictions;
- network-destination restrictions;
- working-directory restrictions;
- rootless containers;
- mandatory sandboxing;
- mandatory plan/apply;
- per-command broker approval;
- predetermined command schemas.

Quirt shall allow arbitrary commands, scripts, binaries, interpreters, terminal input, and host administration as UID 0.

### 2.2 Immediate operation

Ordinary Quirt execution shall not require a separate planning operation followed by an apply operation.

The operator shall be able to:

1. open or attach to a root session;
2. send terminal input;
3. observe the result.

A one-shot execution call shall likewise start execution immediately.

### 2.3 Persistent shell semantics

Quirt shall preserve:

- current working directory;
- shell variables;
- exported environment;
- functions and aliases;
- shell options;
- command history;
- foreground processes;
- terminal dimensions;
- terminal modes;
- tmux windows and panes;
- active interactive programs.

The shell shall survive the end of an MCP request and temporary Horsey disconnection.

### 2.4 Quirt-only operator experience

Jamie shall not need separate tools for routine work. Third-party free/open-source utilities may implement internal providers, but Horsey shall expose them through Quirt.

Examples:

- tmux may provide session persistence;
- Playwright may provide browser automation;
- restic or Kopia may provide snapshots;
- rclone may provide remote storage;
- Ansible may provide fleet operations;
- code-server may provide a browser IDE.

The user-facing interface remains Quirt.

### 2.5 Root shell is always the escape hatch

Structured Quirt operations are accelerators only. No structured subsystem may prevent the operator from falling back to the unrestricted root terminal.

## 3. Architecture decision

### 3.1 Superseding decision

The prior doctrine stated that Fix is the sole durable execution kernel and its bounded privilege broker is the sole privileged root boundary.

QES-1 deliberately supersedes that rule for Quirt.

The new doctrine is:

- Horsey remains the unified product and control surface.
- Neigh remains an objective and orchestration protocol.
- Fix remains the durable general-purpose execution kernel.
- The existing bounded Fix privilege broker remains available for narrowly defined automated operations.
- Quirt becomes a separate Jamie-exclusive unrestricted privileged terminal authority.
- Quirt owns its terminal sessions, terminal streams, interactive state, file transfers, recordings, provider state, and Quirt-specific jobs.
- Quirt is not required to translate interactive work into Fix plans.
- Horsey may select Fix or Quirt according to the work requested.
- Jamie may direct Horsey to use Quirt exclusively.

This decision is recorded in `docs/adr/ADR-QUIRT-UNRESTRICTED-ROOT.md`.

### 3.2 Repository placement

Primary implementation repository:

```text
StealthEyeLLC/stealtheye-fix-operator
```

Horsey integration and exact pinning:

```text
StealthEyeLLC/horsey
```

Fix changes should be limited to documentation required to acknowledge the superseding architecture. Quirt runtime code shall not be embedded in the generic Fix execution kernel.

## 4. Runtime topology

```text
ChatGPT / Horsey client
          |
          | HTTPS + OAuth + MCP
          v
Horsey Gateway
unprivileged service account
          |
          | private authenticated local protocol
          v
/run/horsey/quirt.sock
          |
          v
Quirt Supervisor
UID 0
          |
          +-- persistent root PTYs
          +-- tmux control server
          +-- immediate root jobs
          +-- file-transfer engine
          +-- browser and IDE providers
          +-- storage and snapshot providers
          +-- tunnel and network providers
          +-- tracing and debugging providers
          +-- fleet providers
```

Quirt shall not expose its own public Internet listener. The Horsey gateway remains the remote application boundary.

## 5. System services and paths

### 5.1 Services

```text
stealtheye-quirt.socket
stealtheye-quirt.service
```

Optional provider services may exist as:

```text
stealtheye-quirt-<provider>.service
```

### 5.2 Runtime socket

```text
/run/horsey/quirt.sock
```

### 5.3 Persistent state

```text
/var/lib/stealtheye-quirt/
├── sessions/
├── jobs/
├── streams/
├── transfers/
├── recordings/
├── snapshots/
├── repositories/
├── credentials/
├── tunnels/
├── browsers/
├── providers/
├── receipts/
└── state.sqlite
```

### 5.4 Configuration

```text
/etc/stealtheye-quirt/
├── quirt.json
├── providers.json
└── trusted-authority.json
```

### 5.5 Immutable releases

```text
/opt/stealtheye-quirt/
├── releases/<revision>/
├── current -> releases/<revision>
└── previous -> releases/<revision>
```

Persistent state shall never reside inside a release directory.

## 6. Internal Quirt protocol

The gateway-to-Quirt protocol shall be:

- versioned;
- framed;
- binary-safe;
- streaming;
- multiplexed;
- reconnectable;
- suitable for raw PTY bytes and large files;
- independent of individual HTTP request duration.

Each request shall include:

- protocol version;
- request ID;
- operation;
- authenticated principal identity;
- target host identity;
- timestamp;
- operation payload.

Request IDs shall be idempotent where duplicate execution would be incorrect.

The protocol shall support unsolicited events for:

- terminal output;
- job state changes;
- process exits;
- transfer progress;
- browser events;
- tunnel state;
- provider state.

## 7. Core MCP surface

### 7.1 Identity and status

```text
quirt.status
quirt.capabilities
quirt.version
```

### 7.2 Persistent root sessions

```text
quirt.session.open
quirt.session.list
quirt.session.get
quirt.session.attach
quirt.session.read
quirt.session.write
quirt.session.resize
quirt.session.signal
quirt.session.detach
quirt.session.close
quirt.session.snapshot
quirt.session.search
quirt.session.render
```

`quirt.session.open` shall support:

- session name;
- shell or executable;
- initial working directory;
- initial environment;
- terminal dimensions;
- login-shell mode;
- tmux-backed mode;
- direct PTY mode.

The default shall be a persistent root login shell.

### 7.3 One-shot and detached execution

```text
quirt.exec
quirt.job.list
quirt.job.get
quirt.job.read
quirt.job.input
quirt.job.signal
quirt.job.cancel
quirt.job.attach
```

`quirt.exec` shall support:

- arbitrary command or script;
- executable plus arguments;
- optional shell interpretation;
- working directory;
- environment;
- stdin;
- PTY or non-PTY execution;
- attached or detached operation;
- timeout;
- request ID;
- stdout and stderr streaming;
- exit code and terminating signal.

Execution shall start immediately.

### 7.4 Files and directories

```text
quirt.file.read
quirt.file.write
quirt.file.patch
quirt.file.stat
quirt.file.search
quirt.file.remove
quirt.file.move
quirt.file.copy
quirt.directory.list
quirt.directory.create
quirt.directory.watch
```

These operations shall support arbitrary host paths.

### 7.5 Binary transfers

```text
quirt.transfer.begin
quirt.transfer.read
quirt.transfer.write
quirt.transfer.status
quirt.transfer.complete
quirt.transfer.cancel
```

Transfers shall support:

- upload and download;
- arbitrary binary data;
- resumable offsets;
- SHA-256 verification;
- sparse files;
- large files;
- compression;
- metadata preservation;
- directories and archives;
- atomic final placement;
- symlinks;
- ownership, mode, and timestamps.

### 7.6 Pane and terminal workspace control

```text
quirt.pane.open
quirt.pane.list
quirt.pane.split
quirt.pane.focus
quirt.pane.resize
quirt.pane.move
quirt.pane.broadcast
quirt.pane.close
```

Tmux control mode shall be the preferred initial provider.

## 8. Terminal fidelity

Quirt shall support:

- true PTYs;
- raw byte input and output;
- UTF-8;
- ANSI escape sequences;
- 24-bit color;
- Unicode width handling;
- mouse input;
- terminal resizing;
- bracketed paste;
- alternate screen buffers;
- control characters;
- foreground process groups;
- terminal signals;
- terminal scrollback;
- searchable terminal history;
- terminal-state serialization;
- clickable links;
- OSC sequences;
- Kitty or Sixel image protocols where supported;
- ZMODEM or trzsz transfer compatibility.

Programs such as the following shall function correctly:

```text
bash
zsh
tmux
vim
nano
less
top
htop
gdb
strace
psql
sqlite3
node
python
ssh
apt
systemctl
journalctl
```

## 9. Output, replay, and recording

Every terminal and job stream shall use monotonically increasing byte offsets.

A reader shall be able to request:

```text
session ID
stream ID
after offset
maximum bytes
```

Quirt shall not require rereading an entire terminal to resume.

Recording capabilities:

```text
quirt.record.start
quirt.record.stop
quirt.record.list
quirt.record.search
quirt.record.replay
quirt.record.export
```

Recordings shall support:

- terminal input;
- terminal output;
- timestamps;
- resize events;
- markers;
- bookmarks;
- variable-speed replay;
- text transcript;
- searchable indexing;
- HTML or compatible export.

## 10. Repository and Git capabilities

Quirt shall provide complete Git authority through the root shell.

It shall additionally offer:

```text
quirt.git.materialize
quirt.git.mirror
quirt.git.fetch
quirt.git.status
quirt.git.worktree
quirt.git.verify
quirt.git.push
```

The Git provider shall support:

- private repositories;
- persistent local bare mirrors;
- exact commit and tree checkout;
- branches;
- tags;
- submodules;
- Git LFS;
- worktrees;
- signed commits and tags;
- fetch and push;
- authenticated GitHub operations;
- object reuse across workspaces.

Quirt shall be able to materialize any authorized repository without manual archive reconstruction.

## 11. Browser, IDE, and preview capabilities

### 11.1 Browser IDE

```text
quirt.ide.open
quirt.ide.list
quirt.ide.repository
quirt.ide.port
quirt.ide.close
```

The initial provider may use code-server.

### 11.2 Browser automation

```text
quirt.browser.open
quirt.browser.list
quirt.browser.command
quirt.browser.screenshot
quirt.browser.video
quirt.browser.download
quirt.browser.upload
quirt.browser.show
quirt.browser.close
```

The initial provider shall use Playwright and support:

- Chromium;
- Firefox;
- WebKit;
- persistent profiles;
- login state;
- headed and headless operation;
- screenshots;
- PDFs;
- downloads;
- uploads;
- console logs;
- network logs;
- mobile emulation;
- live viewing and takeover where available.

### 11.3 Local-service previews

```text
quirt.preview.open
quirt.preview.list
quirt.preview.get
quirt.preview.logs
quirt.preview.close
```

Any authorized local port or Unix socket may be published through a temporary Quirt-managed route.

## 12. Storage, synchronization, and snapshots

### 12.1 Continuous synchronization

```text
quirt.sync.create
quirt.sync.list
quirt.sync.status
quirt.sync.pause
quirt.sync.resume
quirt.sync.remove
```

The initial provider may use Syncthing.

### 12.2 Remote storage

```text
quirt.remote.add
quirt.remote.list
quirt.remote.mount
quirt.remote.copy
quirt.remote.sync
quirt.remote.serve
quirt.remote.unmount
```

The initial provider may use rclone.

### 12.3 Versioned filesystem snapshots

```text
quirt.snapshot.create
quirt.snapshot.list
quirt.snapshot.get
quirt.snapshot.diff
quirt.snapshot.mount
quirt.snapshot.restore
quirt.snapshot.unmount
quirt.snapshot.remove
```

The initial provider may use restic or Kopia.

## 13. Network and tunnel capabilities

```text
quirt.network.interfaces
quirt.network.routes
quirt.network.connections
quirt.network.listeners
quirt.network.firewall
quirt.network.capture
```

Universal tunnel controls:

```text
quirt.tunnel.open
quirt.tunnel.list
quirt.tunnel.get
quirt.tunnel.pause
quirt.tunnel.resume
quirt.tunnel.close
```

Tunnels shall be capable of:

- TCP;
- UDP;
- HTTP;
- HTTPS;
- SOCKS5;
- Unix sockets;
- local forwarding;
- reverse forwarding;
- privileged ports;
- domain routing;
- temporary listeners;
- localhost-only service access;
- QUIC or other providers where available;
- health checking;
- load balancing.

Initial providers may use OpenSSH, socat, and FRP.

## 14. Process, debugging, and tracing capabilities

```text
quirt.process.list
quirt.process.get
quirt.process.signal
quirt.process.attach
quirt.process.tree
quirt.process.namespaces
```

Tracing controls:

```text
quirt.trace.start
quirt.trace.list
quirt.trace.follow
quirt.trace.stop
quirt.trace.report
quirt.trace.flamegraph
```

Providers may include:

- strace;
- ltrace;
- gdb;
- perf;
- bpftrace;
- eBPF tooling;
- tcpdump.

Quirt shall support tracing both kernel and userspace behavior when the host supports it.

## 15. Checkpoint and restoration capabilities

```text
quirt.checkpoint.create
quirt.checkpoint.list
quirt.checkpoint.get
quirt.checkpoint.restore
quirt.checkpoint.remove
```

The first implementation may use CRIU or DMTCP.

This provider may report `unsupported` for processes or kernel configurations it cannot checkpoint. Provider unavailability shall not affect the unrestricted root shell.

## 16. Desktop and graphical capabilities

```text
quirt.desktop.open
quirt.desktop.list
quirt.desktop.capture
quirt.desktop.input
quirt.desktop.resize
quirt.desktop.close
```

Potential providers include Apache Guacamole, MeshCentral, VNC, RDP, or a browser-based Linux desktop.

This capability is conditional when the target host has no graphical environment, but the protocol and provider boundary shall be included in the milestone.

## 17. Multi-host and fleet capabilities

```text
quirt.host.add
quirt.host.list
quirt.host.get
quirt.host.remove
quirt.host.shell
quirt.fleet.exec
quirt.fleet.copy
quirt.fleet.playbook
quirt.fleet.status
```

Initial providers may use OpenSSH, SSH multiplexing, jump hosts, and Ansible.

Quirt shall remain the only user-facing interface when additional authorized hosts are added.

## 18. Provider architecture

Advanced capabilities shall be implemented through provider interfaces.

Each provider descriptor shall report:

- provider ID;
- semantic version;
- installation state;
- executable version;
- supported operations;
- current health;
- required host capabilities;
- current limitations;
- data directories;
- active instances.

Provider absence shall return a precise `provider_unavailable` result.

Provider absence shall never disable:

- root shell sessions;
- arbitrary root execution;
- native file operations;
- native transfers.

Quirt shall be capable of installing missing free/open-source providers through its own root package and source-management capabilities.

## 19. Capability inventory

`quirt.capabilities` shall report:

- kernel and architecture;
- operating system;
- init system and version;
- installed shells;
- package managers;
- Git version and credential mechanisms;
- available language runtimes;
- container runtimes;
- debugging tools;
- network tools;
- filesystem types;
- mount support;
- terminal capabilities;
- browser providers;
- IDE providers;
- sync and storage providers;
- snapshot providers;
- tracing providers;
- checkpoint providers;
- desktop providers;
- fleet providers;
- Quirt protocol and release identity.

The inventory shall distinguish:

```text
available
installed
healthy
degraded
unsupported
unknown
```

## 20. Session handoff

Quirt shall produce a compact handoff containing:

- session identity;
- session name;
- working directory;
- environment summary;
- tmux windows and panes;
- foreground processes;
- latest output offsets;
- active repositories;
- branches and commits;
- active jobs;
- active transfers;
- active previews;
- active tunnels;
- unfinished work;
- last successful command.

Another conversation shall be able to attach to the same session without reconstructing state from prose.

## 21. RIDING_GUIDE operating truth

The repository shall include:

```text
RIDING_GUIDE.md
RIDING_LOG.jsonl
RIDING_GUIDE.schema.json
```

### 21.1 Required update cadence

Every implementation or operational turn shall produce a Riding Guide entry.

When nothing operational changed, the entry shall explicitly state:

```text
No operational behavior changed.
No command wording was newly validated.
No previous result was superseded.
```

No update shall be claimed until it exists in repository source or durable Quirt state.

### 21.2 Entry fields

Each entry shall contain:

- entry ID;
- timestamp;
- Horsey revision;
- Quirt revision;
- user wording;
- intended action;
- tool operation;
- exact terminal input or command;
- result classification;
- whether ChatGPT invoked the tool;
- whether Horsey received the request;
- whether Quirt received the request;
- whether Linux executed it;
- exit status;
- working wording;
- denied or blocked wording;
- observed limitation;
- output or recording reference;
- verification;
- superseded entries;
- notes.

### 21.3 Result classifications

```text
WORKS
BLOCKED_BY_PLATFORM
REJECTED_BY_HORSEY
REJECTED_BY_QUIRT
EXECUTED_FAILED
EXECUTED_PARTIAL
EXECUTED_SUCCESS
UNKNOWN
NOT_TESTED
```

### 21.4 Recipes

Repeated proven actions may become recipes:

```text
quirt.riding.recipe.list
quirt.riding.recipe.get
quirt.riding.recipe.run
```

Recipes are optional accelerators and may always be bypassed through the unrestricted shell.

## 22. Release and upgrade model

Quirt shall have a dedicated immutable release lane.

Operations:

```text
quirt.release.status
quirt.release.stage
quirt.release.verify
quirt.release.activate
quirt.release.rollback
```

The initial installation may use the existing operator or bounded privilege broker. After acceptance, Quirt shall be capable of staging and activating future Quirt releases itself.

Activation shall preserve:

- persistent sessions where technically possible;
- tmux server state;
- state database;
- recordings;
- transfers;
- repository mirrors;
- snapshots;
- credential agents;
- browser profiles;
- tunnels.

A gateway restart shall not terminate Quirt sessions.

## 23. Initial operator toolbelt

The production host shall provide or permit Quirt to install:

```text
bash
zsh
tmux
git
git-lfs
openssh-client
rsync
rclone
curl
wget
jq
yq
ripgrep
fd
fzf
tar
zip
unzip
zstd
socat
netcat-openbsd
lsof
strace
ltrace
gdb
perf
bpftrace
tcpdump
dnsutils
iproute2
nftables
sqlite3
node
python
playwright
code-server
restic or kopia
syncthing
ansible
```

This is not an allowlist. Other software remains installable.

## 24. Acceptance tests

Quirt is not accepted until all mandatory tests pass on the authorized VPS.

### 24.1 Root identity

Prove that:

```text
id -u
```

returns:

```text
0
```

### 24.2 Persistent PTY

Prove:

- shell opens;
- directory changes persist;
- environment variables persist;
- an editor works;
- a REPL works;
- terminal resize works;
- control characters work;
- disconnect and reconnect preserve the shell;
- Horsey gateway restart preserves the shell.

### 24.3 Full host authority

Prove successful authorized use of:

- arbitrary filesystem create, modify, move, and remove;
- package installation;
- private Git fetch and push;
- systemd inspection and restart;
- journald follow;
- process creation and signaling;
- network listener creation;
- firewall inspection;
- mount inspection or operation;
- user and permission inspection;
- detached background process;
- multiple concurrent root sessions.

### 24.4 Transfer

Prove:

- binary upload;
- binary download;
- resume after interruption;
- SHA-256 identity;
- large-file streaming;
- atomic placement;
- metadata preservation.

### 24.5 Terminal fidelity

Prove:

- tmux;
- vim or nano;
- less;
- top or htop;
- ANSI color;
- alternate screen;
- mouse or terminal events where supported;
- exact output replay from an offset.

### 24.6 Recording and handoff

Prove:

- recording;
- replay;
- transcript search;
- recording reference in Riding Guide;
- another conversation or client attaches to the same session.

### 24.7 Capability providers

Mandatory provider acceptance:

- Git materialization;
- code-server IDE;
- local-port preview;
- Playwright persistent browser;
- remote-storage mount or copy;
- snapshot create/list/restore;
- tunnel open/close;
- process tracing;
- host capability inventory.

Conditional provider acceptance:

- process checkpoint;
- desktop session;
- multi-host fleet execution.

Conditional providers may return a documented unsupported result when the VPS genuinely lacks required host support.

### 24.8 Upgrade and rollback

Prove:

- exact release identity;
- stage;
- verify;
- activate;
- health check;
- state preservation;
- rollback;
- exact previous release restoration.

### 24.9 Riding Guide

Every acceptance action shall produce a validated Riding Guide entry.

## 25. Source quality gates

The milestone shall pass:

- formatting;
- linting;
- strict typecheck;
- build;
- unit tests;
- integration tests;
- protocol tests;
- PTY integration tests;
- terminal replay tests;
- transfer-resume tests;
- gateway-restart tests;
- Quirt-restart tests;
- provider contract tests;
- malformed-input tests;
- concurrency tests;
- duplicate-request tests;
- release activation tests;
- rollback tests;
- Riding Guide schema validation;
- dependency audit;
- deterministic source and artifact identity verification.

GitHub Actions shall not be required as the execution substrate.

## 26. Single-milestone implementation order

This is one milestone, executed in durable checkpoints.

### Checkpoint A — Frozen contract

- engineering specification;
- architecture decision;
- Riding Guide files;
- provider contracts;
- public tool catalog;
- protocol schemas.

Commit and push immediately.

### Checkpoint B — Core Quirt

- root daemon;
- private socket;
- persistent PTY;
- tmux control mode;
- session lifecycle;
- raw input and output;
- output offsets;
- immediate one-shot execution;
- detached jobs.

Commit and push.

### Checkpoint C — Native operator capabilities

- file APIs;
- resumable transfer;
- Git materialization;
- capability inventory;
- recording and replay;
- session handoff;
- journal and process interfaces.

Commit and push.

### Checkpoint D — Power providers

- IDE;
- browser;
- previews;
- sync;
- remote storage;
- snapshots;
- tunnels;
- tracing;
- panes;
- conditional checkpoint, desktop, and fleet providers.

Commit and push.

### Checkpoint E — Release lane

- immutable packaging;
- service and socket units;
- stage;
- verify;
- activate;
- rollback;
- state-preserving upgrade.

Commit and push.

### Checkpoint F — Production acceptance

- install;
- connect through Horsey;
- execute mandatory acceptance matrix;
- test reconnect and recovery;
- test upgrade and rollback;
- finalize Riding Guide;
- pin exact Quirt revision in Horsey.

The milestone is complete only after Checkpoint F.

## 27. Deliverables

The complete milestone shall deliver:

- Quirt source;
- Quirt protocol;
- Quirt root daemon;
- Horsey MCP integration;
- persistent terminal subsystem;
- immediate execution subsystem;
- file and transfer subsystem;
- recording subsystem;
- provider framework;
- mandatory power providers;
- systemd units;
- immutable release tooling;
- upgrade and rollback;
- tests;
- `RIDING_GUIDE.md`;
- `RIDING_LOG.jsonl`;
- `RIDING_GUIDE.schema.json`;
- architecture decision;
- operator documentation;
- exact source and artifact identities;
- production acceptance evidence;
- Horsey import pin.

## 28. Frozen change-control rule

QES-1 is frozen.

Implementation may:

- correct defects;
- improve performance;
- add tests;
- improve provider compatibility;
- add nonrestrictive capabilities;
- refine internal representation.

Implementation may not silently introduce:

- plan/apply;
- command allowlists;
- path allowlists;
- rootless execution;
- fixed-operation-only access;
- loss of interactive PTY behavior;
- dependence on Termius;
- dependence on GitHub Actions;
- replacement of Quirt with a bounded broker;
- removal of unrestricted root authority.

Any change to a non-negotiable requirement requires:

1. an explicit owner decision;
2. a new architecture-decision record;
3. a specification-version increment;
4. a corresponding Riding Guide entry.

## 29. Final acceptance statement

Quirt is accepted only when Jamie can direct Horsey to open a persistent root terminal, perform unrestricted authorized administration of the VPS, disconnect, return later, attach to the same session, continue work, transfer files, operate repositories and services, use advanced power providers, and complete routine engineering without Termius.

Anything less is incomplete.
