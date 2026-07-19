import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { QuirtGatewaySigner, loadAuthoritySecret, QuirtSupervisorAuthority } from "./authority.js";
import { generateEd25519KeyPair, loadEd25519PrivateKey, loadEd25519PublicKey } from "./authority-key.js";
import { buildKeyRingJson, loadVerificationKeyRing } from "./authority-keyring.js";
import type { QuirtConfig } from "./config.js";
import type { QuirtStateStore } from "./state.js";

export interface QuirtAuthorityRuntime {
  gatewaySigner: QuirtGatewaySigner;
  supervisorAuthority: QuirtSupervisorAuthority;
  gatewayVerificationKeyRing: ReturnType<typeof loadVerificationKeyRing>;
  supervisorVerificationKeyRing: ReturnType<typeof loadVerificationKeyRing>;
}

function writeOwnedFile(path: string, content: string, mode: number): void {
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
}

export function createTestAuthorityRuntime(config: QuirtConfig, state: QuirtStateStore, root: string, now?: () => Date): QuirtAuthorityRuntime {
  const gateway = generateEd25519KeyPair();
  const supervisor = generateEd25519KeyPair();
  const gatewayPrivatePath = join(root, "gateway-signing.key");
  const supervisorPrivatePath = join(root, "supervisor-signing.key");
  const gatewayRingPath = join(root, "gateway-verification-keys.json");
  const supervisorRingPath = join(root, "supervisor-verification-keys.json");
  const uid = process.getuid?.() ?? 0;
  writeOwnedFile(gatewayPrivatePath, gateway.privateKeyPem, 0o600);
  writeOwnedFile(supervisorPrivatePath, supervisor.privateKeyPem, 0o600);
  writeOwnedFile(gatewayRingPath, buildKeyRingJson([{ keyId: gateway.keyId, publicKeyPem: gateway.publicKeyPem, status: "current" }]), 0o644);
  writeOwnedFile(supervisorRingPath, buildKeyRingJson([{ keyId: supervisor.keyId, publicKeyPem: supervisor.publicKeyPem, status: "current" }]), 0o644);
  const hmacSecret = Buffer.alloc(32, 0x4d);
  const authoritySecretPath = config.authoritySecretPath;
  writeFileSync(authoritySecretPath, hmacSecret);
  chmodSync(authoritySecretPath, 0o440);
  const gatewayVerificationKeyRing = loadVerificationKeyRing(gatewayRingPath, uid, 0o644, now);
  const supervisorVerificationKeyRing = loadVerificationKeyRing(supervisorRingPath, uid, 0o644, now);
  const gatewaySigner = new QuirtGatewaySigner({
    gatewayId: config.gatewayId,
    signingPrivateKey: loadEd25519PrivateKey(gatewayPrivatePath, uid, 0o600),
    legacyHmacSecret: hmacSecret,
    legacyHmacEnabled: config.legacyHmacEnabled
  });
  const supervisorAuthority = new QuirtSupervisorAuthority({
    config,
    reservations: state,
    gatewayVerificationKeyRing,
    supervisorSigningKey: loadEd25519PrivateKey(supervisorPrivatePath, uid, 0o600),
    legacyHmacSecret: hmacSecret,
    now
  });
  return { gatewaySigner, supervisorAuthority, gatewayVerificationKeyRing, supervisorVerificationKeyRing };
}

export function loadProductionAuthorityRuntime(config: QuirtConfig, state: QuirtStateStore, now?: () => Date): QuirtAuthorityRuntime {
  const uid = 0;
  const gatewayVerificationKeyRing = loadVerificationKeyRing(config.gatewayVerificationKeyRingPath, uid, 0o444, now);
  const supervisorVerificationKeyRing = loadVerificationKeyRing(config.supervisorVerificationKeyRingPath, uid, 0o444, now);
  const gatewaySigner = new QuirtGatewaySigner({
    gatewayId: config.gatewayId,
    signingPrivateKey: loadEd25519PrivateKey(config.gatewaySigningPrivateKeyPath, uid, 0o400),
    legacyHmacSecret: config.legacyHmacEnabled ? loadAuthoritySecret(config.authoritySecretPath, uid, 0o440) : undefined,
    legacyHmacEnabled: config.legacyHmacEnabled
  });
  const supervisorAuthority = new QuirtSupervisorAuthority({
    config,
    reservations: state,
    gatewayVerificationKeyRing,
    supervisorSigningKey: loadEd25519PrivateKey(config.supervisorSigningPrivateKeyPath, uid, 0o400),
    legacyHmacSecret: config.legacyHmacEnabled ? loadAuthoritySecret(config.authoritySecretPath, uid, 0o440) : undefined,
    now
  });
  return { gatewaySigner, supervisorAuthority, gatewayVerificationKeyRing, supervisorVerificationKeyRing };
}

export function loadAuthorityRuntime(config: QuirtConfig, state: QuirtStateStore, rootForTest: string | null, now?: () => Date): QuirtAuthorityRuntime {
  if (config.mode === "test") {
    if (rootForTest === null) throw new Error("test authority root is required");
    return createTestAuthorityRuntime(config, state, rootForTest, now);
  }
  return loadProductionAuthorityRuntime(config, state, now);
}
