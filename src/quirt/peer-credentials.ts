import { lstatSync, realpathSync } from "node:fs";
import type { Socket } from "node:net";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";

export interface QuirtPeerCredentials { pid: number; uid: number; gid: number; }
export interface QuirtPeerCredentialSource { read(socket: Socket): QuirtPeerCredentials; }

const PEER_SCRIPT = "import json,socket,struct; s=socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM); print(json.dumps(dict(zip(('pid','uid','gid'),struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))))))";
const GROUP_SCRIPT = "import grp,sys; print(grp.getgrnam(sys.argv[1]).gr_gid)";

function descriptor(socket: Socket): number {
  const value = (socket as Socket & { _handle?: { fd?: unknown } })._handle?.fd;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new QuirtError("authentication_failed", "Quirt peer socket descriptor is unavailable");
  return value;
}

export class LinuxQuirtPeerCredentialSource implements QuirtPeerCredentialSource {
  constructor(private readonly pythonPath: string, private readonly timeoutMs = 2000) {}
  read(socket: Socket): QuirtPeerCredentials {
    const result = spawnSync(this.pythonPath, ["-I", "-c", PEER_SCRIPT], {
      stdio: ["ignore", "pipe", "pipe", descriptor(socket)],
      encoding: "utf8",
      timeout: this.timeoutMs,
      maxBuffer: 4096
    });
    if (result.status !== 0 || result.error !== undefined) throw new QuirtError("authentication_failed", "Quirt peer credentials could not be verified");
    try {
      const value = JSON.parse(result.stdout) as Record<string, unknown>;
      const credentials = { pid: Number(value.pid), uid: Number(value.uid), gid: Number(value.gid) };
      if (!Number.isSafeInteger(credentials.pid) || credentials.pid < 2 || !Number.isSafeInteger(credentials.uid) || credentials.uid < 0 || !Number.isSafeInteger(credentials.gid) || credentials.gid < 0) throw new Error("invalid credentials");
      return credentials;
    } catch { throw new QuirtError("authentication_failed", "Quirt peer credentials are invalid"); }
  }
}

export function verifyQuirtGatewayPeer(source: QuirtPeerCredentialSource, socket: Socket, config: QuirtConfig): QuirtPeerCredentials {
  const credentials = source.read(socket);
  if (credentials.uid !== config.gatewayUid) throw new QuirtError("authentication_failed", "Quirt peer UID is not the trusted Gateway");
  return credentials;
}

export interface QuirtSocketIdentity { device: number; inode: number; uid: number; gid: number; mode: number; }

export function resolveQuirtSocketGroupGid(pythonPath: string, group: string, timeoutMs = 2000): number {
  const result = spawnSync(pythonPath, ["-I", "-c", GROUP_SCRIPT, group], { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 });
  const gid = Number(result.stdout.trim());
  if (result.status !== 0 || result.error !== undefined || !Number.isSafeInteger(gid) || gid < 0) throw new QuirtError("configuration_error", "Quirt socket group is unavailable");
  return gid;
}

export function inspectQuirtSocket(path: string, expectedMode: number, expectedGid: number): QuirtSocketIdentity {
  try {
    const parent = dirname(path);
    if (realpathSync(parent) !== parent) throw new Error("noncanonical parent");
    const parentStat = lstatSync(parent);
    const stat = lstatSync(path);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || parentStat.uid !== 0 || (parentStat.mode & 0o022) !== 0) throw new Error("unsafe parent");
    if (!stat.isSocket() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== expectedGid || (stat.mode & 0o777) !== expectedMode) throw new Error("unsafe socket");
    return Object.freeze({ device: stat.dev, inode: stat.ino, uid: stat.uid, gid: stat.gid, mode: stat.mode & 0o777 });
  } catch { throw new QuirtError("supervisor_unavailable", "Quirt Unix socket identity or permissions are unsafe", true); }
}
