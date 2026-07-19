import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

interface LiveProbe {
  providerId: string;
  executable: string;
  arguments: readonly string[];
  configuration: string;
}

const LIVE_PROBES: readonly LiveProbe[] = Object.freeze([
  { providerId: "terminal.tmux", executable: "/usr/bin/tmux", arguments: ["-V"], configuration: "QUIRT_LIVE_TMUX=1" },
  { providerId: "ide.code-server", executable: "/usr/bin/code-server", arguments: ["--version"], configuration: "QUIRT_LIVE_CODE_SERVER=1" },
  { providerId: "browser.playwright", executable: "/usr/bin/chromium", arguments: ["--version"], configuration: "QUIRT_LIVE_PLAYWRIGHT=1" },
  { providerId: "preview.process", executable: process.execPath, arguments: ["--version"], configuration: "QUIRT_LIVE_PREVIEW=1" },
  { providerId: "sync.syncthing", executable: "/usr/bin/syncthing", arguments: ["--version"], configuration: "QUIRT_LIVE_SYNCTHING=1" },
  { providerId: "storage.rclone", executable: "/usr/bin/rclone", arguments: ["version"], configuration: "QUIRT_LIVE_RCLONE=1" },
  { providerId: "snapshot.restic", executable: "/usr/bin/restic", arguments: ["version"], configuration: "QUIRT_LIVE_RESTIC=1" },
  { providerId: "network.linux", executable: "/usr/sbin/ip", arguments: ["-json", "link", "show"], configuration: "QUIRT_LIVE_NETWORK=1" },
  { providerId: "tunnel.openssh", executable: "/usr/bin/ssh", arguments: ["-V"], configuration: "QUIRT_LIVE_TUNNEL=1" },
  { providerId: "trace.linux", executable: "/usr/bin/strace", arguments: ["--version"], configuration: "QUIRT_LIVE_TRACE=1" },
  { providerId: "checkpoint.criu", executable: "/usr/sbin/criu", arguments: ["check", "--all"], configuration: "QUIRT_LIVE_CRIU=1" },
  { providerId: "desktop.vnc", executable: "/usr/bin/Xvnc", arguments: ["-version"], configuration: "QUIRT_LIVE_DESKTOP=1" },
  { providerId: "fleet.ssh", executable: "/usr/bin/ssh", arguments: ["-V"], configuration: "QUIRT_LIVE_FLEET=1" }
]);

function skipReason(probe: LiveProbe): string | false {
  if (!existsSync(probe.executable)) return "missing executable " + probe.executable;
  const [name, expected] = probe.configuration.split("=");
  if (process.env[name!] !== expected) return "missing explicit live-host configuration " + probe.configuration;
  return false;
}

for (const probe of LIVE_PROBES) {
  test("live host capability probe: " + probe.providerId, { skip: skipReason(probe) }, () => {
    const result = spawnSync(probe.executable, probe.arguments, {
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env }
    });
    assert.equal(result.error, undefined, probe.providerId + " live probe failed to execute");
    assert.equal(result.status, 0, probe.providerId + " live probe failed: " + (result.stderr || result.stdout).slice(0, 512));
  });
}
