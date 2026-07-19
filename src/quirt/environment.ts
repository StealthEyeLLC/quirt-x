import { QuirtError } from "./error.js";

const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;

function inherited(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value.includes("\0") ? undefined : value;
}

export function quirtEnvironment(shell: string, extra: Readonly<Record<string, string>> = {}): Readonly<Record<string, string>> {
  const base: Record<string, string> = {
    HOME: "/root",
    USER: "root",
    LOGNAME: "root",
    SHELL: shell,
    PATH: inherited("PATH") ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: inherited("LANG") ?? "C.UTF-8",
    TERM: inherited("TERM") ?? "xterm-256color",
    COLORTERM: inherited("COLORTERM") ?? "truecolor"
  };
  for (const name of ["LC_ALL", "LC_CTYPE", "TZ"] as const) {
    const value = inherited(name);
    if (value !== undefined) base[name] = value;
  }
  if (Object.keys(extra).length > 512) throw new QuirtError("invalid_request", "Quirt environment is too large");
  let totalBytes = 0;
  for (const [name, value] of Object.entries(extra)) {
    if (!ENVIRONMENT_NAME.test(name) || value.includes("\0") || Buffer.byteLength(value) > 64 * 1024) throw new QuirtError("invalid_request", "Quirt environment is invalid");
    base[name] = value;
  }
  for (const [name, value] of Object.entries(base)) totalBytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 2;
  if (totalBytes > 256 * 1024) throw new QuirtError("invalid_request", "Quirt environment is too large");
  return Object.freeze(base);
}
