import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
require("node-pty");

const nonce = `quirt-pty-smoke-${Date.now()}`;
const child = spawn("bash", ["-lc", `printf '%s\\n' '${nonce}'; exit 42`], {
  name: "xterm-color",
  cols: 80,
  rows: 24,
  cwd: process.cwd(),
  env: process.env,
});

let output = "";
child.onData((data) => { output += data; });
await new Promise((resolve, reject) => {
  child.onExit(({ exitCode }) => {
    if (exitCode !== 42) reject(new Error(`unexpected exit code: ${exitCode}`));
    else resolve(undefined);
  });
});
if (!output.includes(nonce)) throw new Error("PTY smoke output missing nonce");
process.stdout.write("pty-smoke-ok\n");
