import { loadAuthoritySecret, QuirtSupervisorAuthority } from "./authority.js";
import { loadQuirtConfig } from "./config.js";
import { QuirtJobManager } from "./job-manager.js";
import { QuirtOperationDispatcher } from "./operations.js";
import { LinuxQuirtPeerCredentialSource } from "./peer-credentials.js";
import { NodePtyFactory } from "./pty.js";
import { QuirtSessionManager } from "./session-manager.js";
import { QuirtStateStore } from "./state.js";
import { QuirtSupervisorServer } from "./supervisor.js";
import { QuirtTmuxController } from "./tmux.js";

async function main(): Promise<void> {
  const config = loadQuirtConfig(process.env);
  const state = new QuirtStateStore(config.databasePath, { outputChunkBytes: config.outputChunkBytes, outputRetentionBytes: config.outputRetentionBytes });
  const ptys = new NodePtyFactory();
  const tmux = new QuirtTmuxController(config, ptys);
  const sessions = new QuirtSessionManager(config, state, ptys, tmux);
  const jobs = new QuirtJobManager(config, state, ptys);
  const authority = new QuirtSupervisorAuthority(config, loadAuthoritySecret(config.authoritySecretPath), state);
  const operations = new QuirtOperationDispatcher(config, state, sessions, jobs, tmux);
  const supervisor = new QuirtSupervisorServer(config, state, authority, operations, sessions, jobs, new LinuxQuirtPeerCredentialSource(config.pythonPath));
  const tmuxVersion = await tmux.version();
  const recovery = await supervisor.start();
  process.stdout.write(`${JSON.stringify({ event: "quirt.ready", supervisorId: config.supervisorId, protocolVersion: 1, stateSchemaVersion: state.schemaVersion(), tmuxVersion, recovery })}\n`);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await supervisor.stop();
    state.close();
  };
  process.once("SIGTERM", () => { void stop(); });
  process.once("SIGINT", () => { void stop(); });
}

void main().catch(() => {
  process.stderr.write(`${JSON.stringify({ event: "quirt.start_failed", safeError: "Quirt supervisor failed safely" })}\n`);
  process.exitCode = 1;
});
