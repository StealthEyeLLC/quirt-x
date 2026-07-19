import { QuirtError } from "./error.js";
import type { QuirtAuthorityAlgorithm } from "./authority-key.js";

export const QUIRT_CAPABILITY_AUTHORITY_ED25519 = "authority.ed25519" as const;
export const QUIRT_CAPABILITY_AUTHORITY_HMAC = "authority.hmac-sha256" as const;
export const QUIRT_CAPABILITY_RECONNECT_REPLAY = "reconnect.request-replay.v1" as const;
export const QUIRT_CAPABILITY_COMPRESSION_NONE = "compression.none" as const;
export const QUIRT_CAPABILITY_MULTIPLEXING = "multiplexing" as const;
export const QUIRT_CAPABILITY_EVENTS = "events" as const;
export const QUIRT_CAPABILITY_RAW_BINARY = "raw-binary" as const;
export const QUIRT_CAPABILITY_REPLAY_OFFSETS = "replay-offsets" as const;

export const QUIRT_BASE_CAPABILITIES = Object.freeze([
  QUIRT_CAPABILITY_MULTIPLEXING,
  QUIRT_CAPABILITY_EVENTS,
  QUIRT_CAPABILITY_RAW_BINARY,
  QUIRT_CAPABILITY_REPLAY_OFFSETS,
  QUIRT_CAPABILITY_RECONNECT_REPLAY,
  QUIRT_CAPABILITY_COMPRESSION_NONE
] as const);

export type QuirtCompressionAlgorithm = "none";

export interface QuirtNegotiatedConnectionContext {
  readonly connectionId: string;
  readonly authorityAlgorithm: QuirtAuthorityAlgorithm;
  readonly compression: QuirtCompressionAlgorithm;
  readonly capabilities: readonly string[];
  readonly supervisorKeyId: string | null;
}

function uniqueSortedCapabilities(values: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string" || value.length < 1 || value.length > 128) throw new QuirtError("invalid_frame", "Quirt capability is invalid");
    if (seen.has(value)) throw new QuirtError("protocol_mismatch", "Quirt capability offer contains duplicates");
    seen.add(value);
  }
  return [...seen].sort();
}

export function gatewayOfferedCapabilities(algorithms: readonly QuirtAuthorityAlgorithm[]): readonly string[] {
  const offers: string[] = [...QUIRT_BASE_CAPABILITIES];
  if (algorithms.includes("ed25519")) offers.push(QUIRT_CAPABILITY_AUTHORITY_ED25519);
  if (algorithms.includes("hmac-sha256")) offers.push(QUIRT_CAPABILITY_AUTHORITY_HMAC);
  return Object.freeze(uniqueSortedCapabilities(offers));
}

export function supervisorSupportedCapabilities(algorithms: readonly QuirtAuthorityAlgorithm[]): readonly string[] {
  return gatewayOfferedCapabilities(algorithms);
}

export function negotiateConnection(input: {
  gatewayOffers: readonly string[];
  supervisorSupports: readonly string[];
  gatewayPreferredAlgorithms: readonly QuirtAuthorityAlgorithm[];
  supervisorSupportedAlgorithms: readonly QuirtAuthorityAlgorithm[];
  legacyHmacEnabled: boolean;
}): { authorityAlgorithm: QuirtAuthorityAlgorithm; compression: QuirtCompressionAlgorithm; capabilities: readonly string[] } {
  const offers = uniqueSortedCapabilities(input.gatewayOffers);
  const supports = new Set(uniqueSortedCapabilities(input.supervisorSupports));
  for (const offer of offers) {
    if (!supports.has(offer)) throw new QuirtError("protocol_mismatch", "Quirt capability negotiation failed");
  }
  if (!offers.includes(QUIRT_CAPABILITY_COMPRESSION_NONE)) throw new QuirtError("protocol_mismatch", "Quirt compression negotiation failed");
  const commonAlgorithms = input.gatewayPreferredAlgorithms.filter(algorithm => input.supervisorSupportedAlgorithms.includes(algorithm));
  if (commonAlgorithms.length === 0) throw new QuirtError("protocol_mismatch", "Quirt authority algorithm negotiation failed");
  let authorityAlgorithm: QuirtAuthorityAlgorithm | null = null;
  if (commonAlgorithms.includes("ed25519") && offers.includes(QUIRT_CAPABILITY_AUTHORITY_ED25519) && supports.has(QUIRT_CAPABILITY_AUTHORITY_ED25519)) {
    authorityAlgorithm = "ed25519";
  } else if (input.legacyHmacEnabled && commonAlgorithms.includes("hmac-sha256") && offers.includes(QUIRT_CAPABILITY_AUTHORITY_HMAC) && supports.has(QUIRT_CAPABILITY_AUTHORITY_HMAC)) {
    authorityAlgorithm = "hmac-sha256";
  }
  if (authorityAlgorithm === null) throw new QuirtError("protocol_mismatch", "Quirt authority algorithm negotiation failed");
  const selected = offers.filter(capability => supports.has(capability));
  return Object.freeze({ authorityAlgorithm, compression: "none", capabilities: Object.freeze(selected) });
}

export function assertWelcomeMatchesNegotiation(input: {
  welcomeCapabilities: readonly string[];
  selectedAuthorityAlgorithm: QuirtAuthorityAlgorithm;
  selectedCompression: QuirtCompressionAlgorithm;
  negotiated: { authorityAlgorithm: QuirtAuthorityAlgorithm; compression: QuirtCompressionAlgorithm; capabilities: readonly string[] };
}): void {
  if (input.selectedAuthorityAlgorithm !== input.negotiated.authorityAlgorithm) throw new QuirtError("authentication_failed", "Quirt negotiated authority algorithm was altered");
  if (input.selectedCompression !== input.negotiated.compression) throw new QuirtError("authentication_failed", "Quirt negotiated compression was altered");
  const welcome = uniqueSortedCapabilities(input.welcomeCapabilities);
  const expected = [...input.negotiated.capabilities];
  if (welcome.length !== expected.length || welcome.some((value, index) => value !== expected[index])) {
    throw new QuirtError("authentication_failed", "Quirt negotiated capabilities were altered");
  }
}
