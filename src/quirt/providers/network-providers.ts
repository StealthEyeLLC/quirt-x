import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import { publicProviderInstance, type QuirtPowerProviderAdapter, type QuirtPowerProviderContext, type QuirtPowerProviderResult } from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";
import {
  absolutePath, cleanupManagedFailure, createInstance, credentialReferences, integer, noBinary, optionalText, providerGet,
  providerInstance, providerList, readJobLogs, recoverManaged, requiredText, requireExecutable,
  runChecked, startManagedJob, stopManaged, stringList
} from "./provider-helpers.js";

function boundedText(bytes: Buffer, maximum = 4 * 1024 * 1024): { text: string; truncated: boolean } {
  const truncated = bytes.length > maximum;
  return { text: bytes.subarray(0, maximum).toString("utf8"), truncated };
}

function parseJson(bytes: Buffer, noun: string): unknown {
  try { return JSON.parse(bytes.toString("utf8")); } catch { throw new QuirtError("provider_degraded", noun + " returned malformed structured output", true); }
}

export class LinuxNetworkProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "network.linux";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.network;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Network diagnostics");
    switch (operation) {
      case "quirt.network.interfaces": return await this.ip("interfaces", ["-json", "address", "show"], context);
      case "quirt.network.routes": return await this.ip("routes", ["-json", "route", "show", "table", "all"], context);
      case "quirt.network.connections": return await this.sockets("connections", ["-H", "-n", "-a", "-t", "-u"], context);
      case "quirt.network.listeners": return await this.sockets("listeners", ["-H", "-n", "-l", "-t", "-u"], context);
      case "quirt.network.firewall": return await this.firewall(context);
      case "quirt.network.capture": return await this.capture(payload, context);
      default: throw new QuirtError("unknown_operation", "Network operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async ip(kind: string, args: string[], context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/sbin/ip", ["-V"]);
    const result = await runChecked(context, { executable: "/usr/sbin/ip", arguments: args, maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 10_000 });
    const data = parseJson(result.stdout, "ip");
    const operationId = context.state.power.recordNetworkDiagnostic(context.ownerPrincipalFingerprint, kind, { data, targetHost: context.targetHost });
    return { payload: { operationId, targetHost: context.targetHost, data } };
  }

  private async sockets(kind: string, args: string[], context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/ss", ["-V"]);
    const result = await runChecked(context, { executable: "/usr/bin/ss", arguments: args, maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 10_000 });
    const bounded = boundedText(result.stdout);
    const rows = bounded.text.split("\n").filter(Boolean).map((line) => ({ line }));
    const operationId = context.state.power.recordNetworkDiagnostic(context.ownerPrincipalFingerprint, kind, { rowCount: rows.length, truncated: bounded.truncated, digest: createHash("sha256").update(result.stdout).digest("hex") });
    return { payload: { operationId, targetHost: context.targetHost, rows, truncated: bounded.truncated } };
  }

  private async firewall(context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const probe = await context.runtime.probeExecutable("/usr/sbin/nft", ["--version"]);
    if (!probe.available) throw new QuirtError("executable_missing", "nftables inventory executable is unavailable");
    let result;
    try { result = await runChecked(context, { executable: "/usr/sbin/nft", arguments: ["--json", "list", "ruleset"], maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 10_000 }); }
    catch (cause) { if (cause instanceof QuirtError && (cause.code === "authorization_failed" || cause.code === "provider_degraded")) throw new QuirtError("trace_permission_denied", "Firewall inventory permission was denied"); throw cause; }
    const data = parseJson(result.stdout, "nft");
    const operationId = context.state.power.recordNetworkDiagnostic(context.ownerPrincipalFingerprint, "firewall", { data, readOnly: true });
    return { payload: { operationId, targetHost: context.targetHost, data, readOnly: true } };
  }

  private async capture(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/tcpdump", ["--version"]);
    const interfaceName = optionalText(payload.interface, "Capture interface", 128) ?? "any";
    if (!/^[A-Za-z0-9_.:@-]+$/u.test(interfaceName)) throw new QuirtError("invalid_request", "Capture interface is invalid");
    const outputPath = payload.outputPath === undefined ? context.config.stateRoot + "/providers/network/" + context.requestId + ".pcap" : absolutePath(payload.outputPath, "Capture output path");
    await mkdir(dirname(outputPath), { recursive: true, mode: 0o700 });
    const packetLimit = integer(payload.packetLimit, "Capture packet limit", 1000, 1, 10_000_000);
    const filters = stringList(payload.filterArguments, "Capture filter arguments", 128, 4096);
    let record = createInstance(context, {
      providerId: this.providerId,
      configuration: { kind: "capture", interface: interfaceName, packetLimit, outputPath, filters },
      paths: [outputPath],
      state: "starting",
      health: { state: "starting", protectedOutput: true }
    });
    try {
      record = await startManagedJob(context, record, { executable: "/usr/bin/tcpdump", arguments: ["-U", "-n", "-i", interfaceName, "-c", String(packetLimit), "-w", outputPath, "--", ...filters], eventType: "network.capture.started" });
    } catch (cause) {
      if (cause instanceof QuirtError && (cause.code === "authorization_failed" || cause.code === "provider_degraded")) throw new QuirtError("trace_permission_denied", "Network capture permission was denied");
      throw cause;
    }
    const operationId = context.state.power.recordNetworkDiagnostic(context.ownerPrincipalFingerprint, "capture", { instanceId: record.instanceId, outputPath, interface: interfaceName, packetLimit });
    return { payload: { operationId, capture: publicProviderInstance(record), output: { path: outputPath, mediaType: "application/vnd.tcpdump.pcap", protected: true } }, instanceId: record.instanceId };
  }
}

function tunnelReference(references: Readonly<Record<string, string>>, name: string, noun: string): string {
  const value = references[name];
  if (value === undefined) throw new QuirtError("credentials_unavailable", noun + " credential reference is required");
  return absolutePath(value, noun + " credential reference");
}

type TunnelEndpoint = { kind: "tcp"; host: string; port: number } | { kind: "unix"; socketPath: string };

function endpoint(value: unknown, noun: string, defaultHost?: string, allowSocket = false): TunnelEndpoint {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("invalid_request", noun + " endpoint is invalid");
  const item = value as Record<string, unknown>;
  if (item.socketPath !== undefined) {
    if (!allowSocket) throw new QuirtError("backend_unsupported", noun + " Unix socket endpoint is unsupported for this tunnel kind");
    return { kind: "unix", socketPath: absolutePath(item.socketPath, noun + " socket path") };
  }
  const host = optionalText(item.host, noun + " host", 1024) ?? defaultHost;
  if (host === undefined || host.startsWith("-") || /[\s\0]/u.test(host)) throw new QuirtError("invalid_request", noun + " host is invalid");
  const port = integer(item.port, noun + " port", 0, 1, 65535);
  return { kind: "tcp", host, port };
}

export class OpenSshTunnelProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "tunnel.openssh";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.tunnel;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Tunnel");
    switch (operation) {
      case "quirt.tunnel.open": return await this.open(payload, context);
      case "quirt.tunnel.list": return providerList(context, this.providerId, payload, "Tunnel");
      case "quirt.tunnel.get": return providerGet(context, this.providerId, payload, "Tunnel");
      case "quirt.tunnel.pause": return this.signal(payload, context, true);
      case "quirt.tunnel.resume": return this.signal(payload, context, false);
      case "quirt.tunnel.close": return this.close(payload, context);
      default: throw new QuirtError("unknown_operation", "Tunnel operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async open(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/ssh", ["-V"]);
    const requestedKind = payload.kind === "remote" || payload.kind === "reverse" || payload.kind === "local" || payload.kind === "tcp" || payload.kind === "unix" || payload.kind === undefined ? (payload.kind ?? "local") : (() => { throw new QuirtError("backend_unsupported", "Requested tunnel kind is unsupported by the OpenSSH adapter"); })();
    const kind = requestedKind === "remote" || requestedKind === "reverse" ? "remote" : requestedKind === "unix" ? "unix" : "local";
    const sshHost = requiredText(payload.sshHost, "Tunnel SSH host", 1024);
    const sshUser = requiredText(payload.sshUser, "Tunnel SSH user", 256);
    if (sshHost.startsWith("-") || sshUser.startsWith("-") || /[\s\0@]/u.test(sshUser)) throw new QuirtError("invalid_request", "Tunnel SSH identity is invalid");
    const references = credentialReferences(payload.credentialReferences);
    const identityFile = tunnelReference(references, "identityFile", "SSH identity");
    const knownHostsFile = tunnelReference(references, "knownHostsFile", "SSH known-hosts");
    const local = endpoint(payload.localEndpoint, "Tunnel local", "127.0.0.1", kind === "unix");
    const remote = endpoint(payload.remoteEndpoint, "Tunnel remote", undefined, kind === "unix");
    if (kind === "unix" && (local.kind !== "unix" || remote.kind !== "unix")) throw new QuirtError("invalid_request", "Unix tunnel endpoints must both be socket paths");
    if (kind !== "unix" && (local.kind !== "tcp" || remote.kind !== "tcp")) throw new QuirtError("invalid_request", "TCP tunnel endpoints must both be host/port values");
    const publicBinding = local.kind === "tcp" && local.host !== "127.0.0.1" && local.host !== "::1" && local.host !== "localhost";
    if (publicBinding && payload.allowPublicBinding !== true) throw new QuirtError("unsafe_listener", "Tunnel public or wildcard binding requires explicit authorization");
    const forward = local.kind === "unix" && remote.kind === "unix" ? local.socketPath + ":" + remote.socketPath : (local as {host:string;port:number}).host + ":" + (local as {host:string;port:number}).port + ":" + (remote as {host:string;port:number}).host + ":" + (remote as {host:string;port:number}).port;
    const argumentsList = [
      "-N", "-T", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes",
      "-o", "UserKnownHostsFile=" + knownHostsFile, "-o", "IdentitiesOnly=yes", "-i", identityFile,
      kind === "remote" ? "-R" : "-L", forward, sshUser + "@" + sshHost
    ];
    let record = createInstance(context, {
      providerId: this.providerId,
      configuration: { kind, sshHost, sshUser, localEndpoint: local, remoteEndpoint: remote, publicBinding },
      credentialReferences: references,
      ports: local.kind === "tcp" ? [{ protocol: "tcp", bindAddress: local.host, port: local.port, state: "reserved" }] : [],
      state: "starting",
      health: { state: "starting", hostKeyVerification: "strict" }
    });
    try {
      record = await startManagedJob(context, record, { executable: "/usr/bin/ssh", arguments: argumentsList, eventType: "tunnel.ready" });
      await delay(200, undefined, { signal: context.signal });
      const jobId = record.relatedJobs.at(-1);
      if (jobId !== undefined) {
        const job = context.jobs.get(jobId, context.ownerPrincipalFingerprint);
        if (job.status !== "running" && job.status !== "starting") {
          const stderr = context.jobs.read(jobId, context.ownerPrincipalFingerprint, "stderr", 0, 4096).bytes.toString("utf8");
          if (/host key verification failed|remote host identification has changed/iu.test(stderr)) throw new QuirtError("host_key_mismatch", "SSH host-key verification failed");
          throw new QuirtError("tunnel_handshake_failure", "Tunnel process exited during the authenticated handshake", true);
        }
      }
    } catch (cause) {
      const failure = cause instanceof QuirtError && cause.code === "host_key_mismatch"
        ? cause
        : new QuirtError("tunnel_handshake_failure", "Tunnel handshake failed safely", true);
      cleanupManagedFailure(context, record, failure);
      throw failure;
    }
    context.state.power.recordTunnel(record.instanceId, { tunnelType: kind, localEndpoint: local, remoteEndpoint: remote, state: "ready" });
    return { payload: { tunnel: publicProviderInstance(record), hostKeyVerification: "strict" }, instanceId: record.instanceId };
  }

  private signal(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext, pause: boolean): QuirtPowerProviderResult {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Tunnel identity");
    const jobId = record.relatedJobs.at(-1);
    if (jobId === undefined) throw new QuirtError("provider_lost", "Tunnel process identity is unavailable");
    context.jobs.signal(jobId, context.ownerPrincipalFingerprint, pause ? "SIGSTOP" : "SIGCONT");
    record = context.state.power.putInstance({ ...record, state: pause ? "degraded" : "ready", health: { state: pause ? "paused" : "healthy" }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordTunnel(record.instanceId, { tunnelType: String(record.configuration.kind), localEndpoint: record.configuration.localEndpoint as Record<string, unknown>, remoteEndpoint: record.configuration.remoteEndpoint as Record<string, unknown>, state: pause ? "paused" : "ready" });
    context.state.power.appendEvent(record.instanceId, pause ? "tunnel.paused" : "tunnel.resumed", {});
    return { payload: { tunnel: publicProviderInstance(record) }, instanceId: record.instanceId };
  }

  private close(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Tunnel identity");
    const stopped = stopManaged(context, record, payload.force === true);
    context.state.power.recordTunnel(record.instanceId, { tunnelType: String(record.configuration.kind), localEndpoint: record.configuration.localEndpoint as Record<string, unknown>, remoteEndpoint: record.configuration.remoteEndpoint as Record<string, unknown>, state: "closed" });
    return { payload: { tunnel: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }
}

function traceExecutable(type: string): string {
  switch (type) {
    case "strace": return "/usr/bin/strace";
    case "perf": return "/usr/bin/perf";
    case "gdb": return "/usr/bin/gdb";
    case "bpftrace": return "/usr/bin/bpftrace";
    case "tcpdump": return "/usr/bin/tcpdump";
    default: throw new QuirtError("backend_unsupported", "Trace type is unsupported");
  }
}

function traceArguments(type: string, pid: number, outputPath: string, payload: Readonly<Record<string, unknown>>): string[] {
  switch (type) {
    case "strace": return ["-ff", "-tt", "-s", "256", "-p", String(pid), "-o", outputPath];
    case "perf": return ["record", "-o", outputPath, "-p", String(pid)];
    case "gdb": return ["--batch", "--pid", String(pid), "-ex", "set pagination off", "-ex", "set logging file " + JSON.stringify(outputPath), "-ex", "set logging overwrite on", "-ex", "set logging enabled on", "-ex", "thread apply all bt", "-ex", "set logging enabled off", "-ex", "detach", "-ex", "quit"];
    case "bpftrace": return ["-o", outputPath, absolutePath(payload.scriptPath, "bpftrace script path")];
    case "tcpdump": return ["-U", "-n", "-w", outputPath, "-c", String(integer(payload.packetLimit, "Trace packet limit", 1000, 1, 10_000_000))];
    default: throw new QuirtError("backend_unsupported", "Trace type is unsupported");
  }
}

function sameProcessIdentity(left: Readonly<Record<string, unknown>>, right: Readonly<Record<string, unknown>>): boolean {
  return left.pid === right.pid && left.startTimeTicks === right.startTimeTicks && left.bootId === right.bootId &&
    left.executableDevice === right.executableDevice && left.executableInode === right.executableInode;
}

function flameSvg(lines: string[]): Buffer {
  const counts = new Map<string, number>();
  for (const line of lines) {
    const key = line.trim().slice(0, 160);
    if (key.length > 0) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 100);
  const width = 1200, row = 20, height = Math.max(40, top.length * row + 30), maximum = Math.max(1, ...top.map((item) => item[1]));
  const escape = (value: string): string => value.replace(/[&<>"']/gu, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[ch]!));
  const rects = top.map(([name, count], index) => '<rect x="0" y="' + (index * row + 20) + '" width="' + Math.max(1, Math.floor(width * count / maximum)) + '" height="18" fill="#d76b32"/><text x="4" y="' + (index * row + 34) + '" font-size="12">' + escape(name) + " (" + count + ")</text>").join("");
  return Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '" role="img"><title>Quirt bounded trace flame graph</title>' + rects + "</svg>");
}

export class LinuxTraceProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "trace.linux";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.trace;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Tracing");
    switch (operation) {
      case "quirt.trace.start": return await this.start(payload, context);
      case "quirt.trace.list": return providerList(context, this.providerId, payload, "Trace");
      case "quirt.trace.follow": return this.follow(payload, context);
      case "quirt.trace.stop": return this.stop(payload, context);
      case "quirt.trace.report": return await this.report(payload, context);
      case "quirt.trace.flamegraph": return await this.flamegraph(payload, context);
      default: throw new QuirtError("unknown_operation", "Trace operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async start(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const type = requiredText(payload.type, "Trace type", 32);
    const executable = traceExecutable(type);
    await requireExecutable(context, executable, ["--version"]);
    const pid = integer(payload.pid, "Trace target PID", 0, type === "tcpdump" ? 0 : 1, 4_194_304);
    let identity: Readonly<Record<string, unknown>> = { bootIdentity: null, pid: null, networkCapture: true };
    if (type !== "tcpdump") identity = await context.runtime.processIdentity(pid);
    const outputPath = payload.outputPath === undefined ? context.config.stateRoot + "/providers/trace/" + context.requestId + (type === "perf" ? ".data" : type === "tcpdump" ? ".pcap" : ".trace") : absolutePath(payload.outputPath, "Trace output path");
    await mkdir(dirname(outputPath), { recursive: true, mode: 0o700 });
    let record = createInstance(context, { providerId: this.providerId, configuration: { type, pid, outputPath, targetIdentity: identity }, paths: [outputPath], state: "starting", health: { state: "starting", bounded: true } });
    try { record = await startManagedJob(context, record, { executable, arguments: traceArguments(type, pid, outputPath, payload), timeoutMs: type === "perf" ? integer(payload.durationSeconds, "Trace duration", 30, 1, 86400) * 1000 : undefined, eventType: "trace.started" }); }
    catch (cause) {
      if (cause instanceof QuirtError && (cause.code === "authorization_failed" || cause.code === "provider_degraded")) throw new QuirtError("trace_permission_denied", "Trace attachment permission was denied");
      throw cause;
    }
    if (type !== "tcpdump") {
      const observed = await context.runtime.processIdentity(pid);
      if (!sameProcessIdentity(identity, observed)) {
        const jobId = record.relatedJobs.at(-1);
        if (jobId !== undefined) context.jobs.cancel(jobId, context.ownerPrincipalFingerprint, true);
        context.state.power.putInstance({ ...record, state: "failed", failureClassification: "pid_reused", health: { state: "failed" }, cleanupStatus: "complete", lastProbeAt: new Date().toISOString() });
        throw new QuirtError("pid_reused", "Trace target process identity changed during attachment");
      }
    }
    context.state.power.recordTrace(record.instanceId, type, identity, "running");
    context.state.power.appendTraceEvent(record.instanceId, Buffer.from("trace-started"), { type, targetIdentity: identity });
    return { payload: { trace: publicProviderInstance(record), targetIdentity: identity, output: { path: outputPath, protected: true } }, instanceId: record.instanceId };
  }

  private follow(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Trace identity");
    return readJobLogs(context, record, payload, "Trace");
  }

  private stop(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Trace identity");
    const stopped = stopManaged(context, record, payload.force === true);
    context.state.power.recordTrace(record.instanceId, String(record.configuration.type), record.configuration.targetIdentity as Record<string, unknown>, "stopped");
    context.state.power.appendTraceEvent(record.instanceId, Buffer.from("trace-stopped"), { clean: true });
    return { payload: { trace: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }

  private async report(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Trace identity");
    const type = String(record.configuration.type);
    const outputPath = requiredText(record.configuration.outputPath, "Trace output path", 32_768);
    const result = type === "perf"
      ? await runChecked(context, { executable: "/usr/bin/perf", arguments: ["report", "--stdio", "--input", outputPath], maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 60_000 })
      : await runChecked(context, { executable: "/usr/bin/head", arguments: ["-c", String(integer(payload.maximumBytes, "Trace report size", 1024 * 1024, 1, 4 * 1024 * 1024)), outputPath], maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 30_000 });
    const digest = createHash("sha256").update(result.stdout).digest("hex");
    const exportPath = optionalText(payload.exportPath, "Trace report export path", 32_768);
    let exportId: string | null = null;
    if (exportPath !== undefined) {
      const safePath = absolutePath(exportPath, "Trace report export path");
      await mkdir(dirname(safePath), { recursive: true, mode: 0o700 });
      await writeFile(safePath, result.stdout, { mode: 0o600, flag: "wx" });
      exportId = context.state.power.recordTraceExport(record.instanceId, safePath, digest, result.stdout.length);
    }
    return { payload: { instanceId: record.instanceId, digest, sizeBytes: result.stdout.length, exportId }, binary: result.stdout, instanceId: record.instanceId };
  }

  private async flamegraph(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Trace identity");
    if (record.configuration.type !== "perf") throw new QuirtError("backend_unsupported", "Flame graphs require a perf trace");
    const outputPath = requiredText(record.configuration.outputPath, "Trace output path", 32_768);
    const script = await runChecked(context, { executable: "/usr/bin/perf", arguments: ["script", "--input", outputPath], maximumOutputBytes: 8 * 1024 * 1024, timeoutMs: 60_000 });
    const svg = flameSvg(script.stdout.toString("utf8").split("\n"));
    const digest = createHash("sha256").update(svg).digest("hex");
    return { payload: { instanceId: record.instanceId, mediaType: "image/svg+xml", sha256: digest, sizeBytes: svg.length, bounded: true }, binary: svg, instanceId: record.instanceId };
  }
}
