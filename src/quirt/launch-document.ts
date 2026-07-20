import { createHash } from "node:crypto";

export type QuirtLaunchForm =
  | { kind: "command"; shellPath: string; commandDigest: string }
  | { kind: "script"; shellPath: string; scriptDigest: string }
  | { kind: "executable"; executable: string; arguments: readonly string[]; shellWrapped: boolean };

export interface QuirtLaunchDocumentInput {
  form: QuirtLaunchForm;
  workingDirectory: string;
  environmentPolicyDigest: string;
  stdinDigest: string | null;
  pty: boolean;
  detach: boolean;
  timeoutMs: number | null;
}

function frame(type: string, value: string | number | boolean): string {
  return `${type}:${typeof value === "string" ? value.length : String(value)}:${value}`;
}

export function digestText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function digestBuffer(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function buildLaunchDocument(input: QuirtLaunchDocumentInput): { digest: string; safeMetadata: Record<string, unknown> } {
  const parts = [
    frame("form", input.form.kind),
    frame("cwd", input.workingDirectory),
    frame("envPolicy", input.environmentPolicyDigest),
    frame("pty", input.pty),
    frame("detach", input.detach),
    frame("timeout", input.timeoutMs ?? "none"),
    frame("stdin", input.stdinDigest ?? "none")
  ];
  const safe: Record<string, unknown> = { form: input.form.kind, workingDirectory: input.workingDirectory, pty: input.pty, detach: input.detach, timeoutMs: input.timeoutMs };
  if (input.form.kind === "command") {
    parts.push(frame("shell", input.form.shellPath), frame("commandDigest", input.form.commandDigest));
    safe.shellPath = input.form.shellPath;
    safe.commandDigest = input.form.commandDigest;
  } else if (input.form.kind === "script") {
    parts.push(frame("shell", input.form.shellPath), frame("scriptDigest", input.form.scriptDigest));
    safe.shellPath = input.form.shellPath;
    safe.scriptDigest = input.form.scriptDigest;
  } else {
    parts.push(frame("executable", input.form.executable), frame("shellWrapped", input.form.shellWrapped));
    for (const [index, argument] of input.form.arguments.entries()) parts.push(frame(`argv${index}`, argument));
    safe.executable = input.form.executable;
    safe.arguments = [...input.form.arguments];
    safe.shellWrapped = input.form.shellWrapped;
  }
  return { digest: createHash("sha256").update(parts.join("\n")).digest("hex"), safeMetadata: safe };
}
