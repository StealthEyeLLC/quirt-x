import { execFile } from "node:child_process";
import { access, readFile, readlink, stat, statfs } from "node:fs/promises";
import { arch, hostname, platform, release } from "node:os";
import { promisify } from "node:util";
import type { QuirtConfig } from "./config.js";
import type { QuirtGitService } from "./git-service.js";
import { QUIRT_OPERATIONS } from "./catalog.js";
import type { QuirtProcessService } from "./process-service.js";
import { QuirtPowerProviderRegistry, type QuirtPowerProviderService } from "./power-provider.js";
import { QUIRT_PROTOCOL_VERSION } from "./protocol.js";
import { QUIRT_STATE_SCHEMA_VERSION, type QuirtStateStore } from "./state.js";
import type { QuirtTmuxController } from "./tmux.js";

const execute = promisify(execFile);

async function exists(path: string): Promise<boolean> { try { await access(path); return true; } catch { return false; } }
async function version(path: string, args: string[] = ["--version"]): Promise<string | null> { try { const result = await execute(path, args, { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 3000, env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" } }); return `${result.stdout}${result.stderr}`.trim().split("\n")[0] ?? null; } catch { return null; } }
async function probe(name: string, path: string, args: string[] = ["--version"]): Promise<Record<string, unknown>> { const installed = await exists(path); const executableVersion = installed ? await version(path, args) : null; return { name, path, state: executableVersion === null ? installed ? "installed" : "unsupported" : "available", installed, version: executableVersion }; }
function osRelease(value: string): Record<string, string> { const output: Record<string, string> = {}; for (const line of value.split("\n")) { const match = /^([A-Z_]+)=(.*)$/u.exec(line); if (match === null) continue; let text = match[2]!; if (text.startsWith("\"") && text.endsWith("\"")) text = text.slice(1, -1).replace(/\\"/gu, "\""); output[match[1]!] = text; } return output; }

export class QuirtCapabilityService {
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly tmux: QuirtTmuxController, private readonly git: QuirtGitService, private readonly processes: QuirtProcessService, private readonly power?: QuirtPowerProviderService) {}

  async inventory(owner: string): Promise<Record<string, unknown>> {
    const [osText, bootId, tmuxVersion, git, init, systemd, shells, filesystem, filesystems, mountInfo, procAvailable, inotify, journalctl, journalSocket] = await Promise.all([
      readFile("/etc/os-release", "utf8").catch(() => ""), this.processes.bootId().catch(() => null), this.tmux.version().catch(() => null), this.git.version(), readFile("/proc/1/comm", "utf8").then(value => value.trim()).catch(() => null), version("/usr/bin/systemctl"), readFile("/etc/shells", "utf8").then(value => value.split("\n").filter(line => line.startsWith("/"))).catch(() => []), statfs("/").catch(() => null), readFile("/proc/filesystems", "utf8").then(value => value.split("\n").map(line => line.trim().split(/\s+/u).at(-1)).filter((item): item is string => typeof item === "string" && item.length > 0)).catch(() => []), readFile("/proc/self/mountinfo", "utf8").then(value => value.split("\n").filter(Boolean).length).catch(() => null), exists("/proc/self/stat"), exists("/proc/sys/fs/inotify/max_user_watches"), version("/usr/bin/journalctl"), exists("/run/systemd/journal/socket")
    ]);
    const [languageRuntimes, packageManagers, containerRuntimes, debuggingTools, networkTools, coreUtilities] = await Promise.all([
      Promise.all([probe("node", process.execPath, ["--version"]), probe("python", "/usr/bin/python3", ["--version"]), probe("bash", "/bin/bash", ["--version"]), probe("zsh", "/usr/bin/zsh", ["--version"])]),
      Promise.all([probe("apt", "/usr/bin/apt", ["--version"]), probe("apt-get", "/usr/bin/apt-get", ["--version"]), probe("dpkg", "/usr/bin/dpkg", ["--version"]), probe("snap", "/usr/bin/snap", ["--version"])]),
      Promise.all([probe("docker", "/usr/bin/docker", ["--version"]), probe("podman", "/usr/bin/podman", ["--version"]), probe("containerd", "/usr/bin/containerd", ["--version"])]),
      Promise.all([probe("gdb", "/usr/bin/gdb", ["--version"]), probe("strace", "/usr/bin/strace", ["--version"]), probe("ltrace", "/usr/bin/ltrace", ["--version"]), probe("perf", "/usr/bin/perf", ["--version"]), probe("bpftrace", "/usr/bin/bpftrace", ["--version"]), probe("tcpdump", "/usr/bin/tcpdump", ["--version"])]),
      Promise.all([probe("ip", "/usr/sbin/ip", ["-V"]), probe("ss", "/usr/bin/ss", ["-V"]), probe("nft", "/usr/sbin/nft", ["--version"]), probe("iptables", "/usr/sbin/iptables", ["--version"]), probe("curl", "/usr/bin/curl", ["--version"]), probe("socat", "/usr/bin/socat", ["-V"]), probe("ssh", "/usr/bin/ssh", ["-V"])]),
      Promise.all([probe("rsync", "/usr/bin/rsync", ["--version"]), probe("tar", "/usr/bin/tar", ["--version"]), probe("gzip", "/usr/bin/gzip", ["--version"]), probe("mount", "/usr/bin/mount", ["--version"]), probe("find", "/usr/bin/find", ["--version"]), probe("grep", "/usr/bin/grep", ["--version"]), probe("sed", "/usr/bin/sed", ["--version"]), probe("ssh", "/usr/bin/ssh", ["-V"])])
    ]);
    const powerProviders = this.power === undefined ? await new QuirtPowerProviderRegistry(this.state).inventory() : await this.power.inventory();
    const os = osRelease(osText); const unavailable = []; const degraded = [];
    if (tmuxVersion === null) degraded.push({ capability: "persistent-tmux", state: "unavailable", reason: "tmux executable is not installed on this host" });
    if (!git.lfsAvailable) degraded.push({ capability: "git-lfs", state: "unavailable", reason: "Git LFS executable is not installed on this host" });
    if (journalctl === null || !journalSocket) unavailable.push({ capability: "journald", state: "unsupported", reason: "journalctl or the journald socket is unavailable" });
    const inventory = {
      inventoryVersion: 1, protocolVersion: QUIRT_PROTOCOL_VERSION, stateSchemaVersion: QUIRT_STATE_SCHEMA_VERSION, supervisorVersion: process.env.QUIRT_COMMIT_SHA ?? "source-build", gatewayCompatibility: { protocolVersions: [QUIRT_PROTOCOL_VERSION], exactPrincipalRequired: true },
      host: { operatingSystem: { id: os.ID ?? platform(), name: os.PRETTY_NAME ?? os.NAME ?? platform(), version: os.VERSION_ID ?? null }, architecture: arch(), kernel: release(), hostname: hostname(), targetIdentity: this.config.targetHost, bootId, initSystem: init, initVersion: systemd },
      runtimes: { node: process.version, shell: this.config.shellPath, shells, languageRuntimes }, packageManagers, containerRuntimes, debuggingTools, networkTools, coreUtilities, terminal: { nativePty: { state: "available", implementation: "node-pty", locallyTested: true }, tmux: { state: tmuxVersion === null ? "unsupported" : "available", version: tmuxVersion, privilegedValidation: "pending-host-integration" }, rawBytes: true, ansi: true, unicodeWidth: true, alternateScreen: true },
      git: { state: git.available ? "available" : "unsupported", version: git.version, lfs: { state: git.lfsAvailable ? "available" : "unsupported", version: git.lfsVersion }, mirrors: true, worktrees: true, credentialMechanisms: ["controlled-askpass", "isolated-ssh-key"] },
      journal: { state: journalctl !== null && journalSocket ? "available" : "unsupported", version: journalctl, socket: journalSocket, machineReadable: true, cursorPolling: true, liveHostTested: false },
      processes: { proc: procAvailable ? "available" : "unsupported", exactIdentity: true, namespaces: procAvailable ? "available" : "unsupported", arbitraryInteractiveAttach: "degraded", quirtOwnedAttach: "available" },
      filesystem: { root: filesystem === null ? null : { type: String(filesystem.type), blockSize: filesystem.bsize, blocks: filesystem.blocks, availableBlocks: filesystem.bavail }, availableTypes: filesystems, visibleMountCount: mountInfo, mountInspection: mountInfo === null ? "unsupported" : "available", inotify: inotify ? "available" : "unsupported", sparseFiles: { state: "unknown", reason: "read-only probe does not create a sparse witness" }, xattrs: { state: "unknown", reason: "read-only capability probe" }, acls: { state: "unknown", reason: "read-only capability probe" } },
      transfers: { digestAlgorithms: ["sha256"], compression: ["none", "gzip"], archives: ["tar"], objectTypes: ["file", "directory", "symlink"], resumable: true, sparsePlacement: "partial-object-supported-final-copy-kernel-dependent", maximumChunkBytes: 1024 * 1024 }, recordings: { formats: ["quirt-json-v1", "asciinema-v2", "html-transcript"], rawBytes: true, indexedTranscript: true, pagedReplay: true, boundedStreamingExport: true },
      operations: [...QUIRT_OPERATIONS], implementedOperationCount: QUIRT_OPERATIONS.length, sourceImplemented: true, locallyTested: true, hostAvailable: { files: true, directories: true, transfers: true, git: git.available, processes: procAvailable, journald: journalctl !== null && journalSocket }, privilegedValidationPending: ["systemd-socket-activation-so-peercred", "tmux-control-mode-adoption"], degraded, unavailable,
      providers: Object.fromEntries(powerProviders.map((provider) => [provider.providerId, provider])), providerSummary: { total: powerProviders.length, sourceImplemented: powerProviders.filter((provider) => provider.sourceImplemented).length, hostAvailable: powerProviders.filter((provider) => provider.hostAvailable).length, deterministicAdapterTested: powerProviders.filter((provider) => provider.deterministicAdapterTested).length }, limitations: ["arbitrary non-Quirt process interactive reattachment requires a supported host provider", "watch continuity across supervisor restart requires rescan", "journald integration uses bounded cursor polling"]
    };
    this.state.native.putObject("quirt_capability_probes", { objectId: "current-host", ownerPrincipalFingerprint: owner, status: unavailable.length > 0 || degraded.length > 0 ? "degraded" : "healthy", data: inventory }); return inventory;
  }

  async status(owner: string): Promise<Record<string, unknown>> { const inventory = await this.inventory(owner); const degraded = inventory.degraded as unknown[]; const unavailable = inventory.unavailable as unknown[]; return { status: unavailable.length > 0 || degraded.length > 0 ? "degraded" : "ready", targetHost: this.config.targetHost, protocolVersion: QUIRT_PROTOCOL_VERSION, stateSchemaVersion: this.state.schemaVersion(), capabilitySummary: { operationCount: QUIRT_OPERATIONS.length, degraded: degraded.length, unavailable: unavailable.length }, privateTransport: { kind: "unix-domain-socket", socketPath: this.config.socketPath, publicListener: false }, unrestrictedRoot: true }; }
}
