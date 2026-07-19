import { QUIRT_OPERATIONS } from "./catalog.js";

/**
 * Canonical standalone Quirt operation names.
 *
 * Public MCP registration belongs to the unprivileged gateway and is retained
 * only as historical reference material under reference/operator-boundary/.
 */
export const QUIRT_TOOL_NAMES = Object.freeze([...QUIRT_OPERATIONS]);
