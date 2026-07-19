import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schema = JSON.parse(readFileSync("RIDING_GUIDE.schema.json", "utf8"));
const source = readFileSync("RIDING_LOG.jsonl", "utf8");
if (!source.endsWith("\n")) throw new Error("RIDING_LOG.jsonl must end with a newline");
const lines = source.trimEnd().split("\n");
const entries = lines.map((line, index) => {
  if (line.trim() !== line || line.length === 0) throw new Error(`Riding Log line ${index + 1} is not one physical JSON object`);
  try { return JSON.parse(line); }
  catch { throw new Error(`Riding Log line ${index + 1} is not valid JSON`); }
});

const ajv = new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true });
addFormats(ajv);
const validate = ajv.compile(schema);
const entryIds = new Set();
for (const [index, entry] of entries.entries()) {
  if (!validate(entry)) throw new Error(`Riding Log line ${index + 1}: ${ajv.errorsText(validate.errors)}`);
  if (entryIds.has(entry.entryId)) throw new Error(`Riding Log entry ${entry.entryId} is duplicated`);
  entryIds.add(entry.entryId);
}

process.stdout.write(`validated ${entries.length} Riding Log entries against ${schema.title}\n`);
