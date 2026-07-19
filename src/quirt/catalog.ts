import { QUIRT_POWER_OPERATIONS } from "./power-catalog.js";

export const QUIRT_CORE_OPERATIONS = Object.freeze([
  "quirt.status", "quirt.capabilities", "quirt.version", "quirt.exec",
  "quirt.session.open", "quirt.session.list", "quirt.session.get", "quirt.session.attach", "quirt.session.read",
  "quirt.session.write", "quirt.session.resize", "quirt.session.signal", "quirt.session.detach", "quirt.session.close",
  "quirt.job.list", "quirt.job.get", "quirt.job.read", "quirt.job.input", "quirt.job.signal", "quirt.job.cancel", "quirt.job.attach"
] as const);

export const QUIRT_NATIVE_FOUNDATION_OPERATIONS = Object.freeze([
  "quirt.file.read", "quirt.file.write", "quirt.file.patch", "quirt.file.stat", "quirt.file.search",
  "quirt.file.remove", "quirt.file.move", "quirt.file.copy", "quirt.directory.list", "quirt.directory.create",
  "quirt.directory.watch", "quirt.transfer.begin", "quirt.transfer.read", "quirt.transfer.write",
  "quirt.transfer.status", "quirt.transfer.complete", "quirt.transfer.cancel"
] as const);

export const QUIRT_NATIVE_OPERATOR_OPERATIONS = Object.freeze([
  "quirt.session.snapshot", "quirt.session.search", "quirt.session.render",
  "quirt.git.materialize", "quirt.git.mirror", "quirt.git.fetch", "quirt.git.status", "quirt.git.worktree", "quirt.git.verify", "quirt.git.push",
  "quirt.record.start", "quirt.record.stop", "quirt.record.list", "quirt.record.search", "quirt.record.replay", "quirt.record.export",
  "quirt.process.list", "quirt.process.get", "quirt.process.signal", "quirt.process.attach", "quirt.process.tree", "quirt.process.namespaces"
] as const);

export const QUIRT_POWER_FOUNDATION_OPERATIONS = QUIRT_POWER_OPERATIONS;

export const QUIRT_OPERATIONS = Object.freeze([...QUIRT_CORE_OPERATIONS, ...QUIRT_NATIVE_FOUNDATION_OPERATIONS, ...QUIRT_NATIVE_OPERATOR_OPERATIONS, ...QUIRT_POWER_FOUNDATION_OPERATIONS] as const);
export type QuirtOperation = typeof QUIRT_OPERATIONS[number];
