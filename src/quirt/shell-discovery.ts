import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { promisify } from "node:util";

const execute = promisify(execFile);

export type QuirtShellAvailability = "installed" | "probe_failed" | "unavailable";

export interface QuirtShellDescriptor {
  shellId: string;
  executablePath: string;
  availability: QuirtShellAvailability;
  version: string | null;
}

const KNOWN_SHELLS = Object.freeze([
  { shellId: "bash", executablePath: "/bin/bash" },
  { shellId: "dash", executablePath: "/bin/dash" },
  { shellId: "zsh", executablePath: "/usr/bin/zsh" },
  { shellId: "fish", executablePath: "/usr/bin/fish" },
  { shellId: "pwsh", executablePath: "/usr/bin/pwsh" },
  { shellId: "nu", executablePath: "/usr/bin/nu" }
] as const);

export async function discoverShell(executablePath: string): Promise<QuirtShellDescriptor | null> {
  const shellId = KNOWN_SHELLS.find(item => item.executablePath === executablePath)?.shellId ?? executablePath.split("/").pop() ?? "shell";
  try {
    await access(executablePath, constants.X_OK);
  } catch {
    return Object.freeze({ shellId, executablePath, availability: "unavailable", version: null });
  }
  try {
    const result = await execute(executablePath, ["--version"], { timeout: 2_000, maxBuffer: 4096 });
    const version = result.stdout.split("\n")[0]?.trim() ?? null;
    return Object.freeze({ shellId, executablePath, availability: "installed", version });
  } catch {
    return Object.freeze({ shellId, executablePath, availability: "probe_failed", version: null });
  }
}

export async function listKnownShells(): Promise<readonly QuirtShellDescriptor[]> {
  const descriptors = await Promise.all(KNOWN_SHELLS.map(item => discoverShell(item.executablePath)));
  return Object.freeze(descriptors.filter((item): item is QuirtShellDescriptor => item !== null));
}

export async function resolveShellPath(requested: string | undefined, defaultPath: string): Promise<string> {
  const path = requested ?? defaultPath;
  const descriptor = await discoverShell(path);
  if (descriptor?.availability === "unavailable") throw new Error(`shell unavailable: ${path}`);
  return path;
}
