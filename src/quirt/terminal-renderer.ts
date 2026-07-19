export interface QuirtTerminalCell { text: string; width: number; attributes: Readonly<Record<string, string | boolean | number | null>>; }
export interface QuirtTerminalRender { rows: string[]; cells: QuirtTerminalCell[][]; cursor: { row: number; column: number; visible: boolean }; alternateScreen: boolean; lossIndicators: string[]; }

interface Screen { cells: QuirtTerminalCell[][]; row: number; column: number; }

function blank(attributes: Readonly<Record<string, string | boolean | number | null>> = {}): QuirtTerminalCell { return { text: " ", width: 1, attributes }; }
function screen(rows: number, columns: number): Screen { return { cells: Array.from({ length: rows }, () => Array.from({ length: columns }, () => blank())), row: 0, column: 0 }; }
function combining(code: number): boolean { return code >= 0x300 && code <= 0x36f || code >= 0x1ab0 && code <= 0x1aff || code >= 0x1dc0 && code <= 0x1dff || code >= 0xfe20 && code <= 0xfe2f; }
function wide(code: number): boolean { return code >= 0x1100 && (code <= 0x115f || code === 0x2329 || code === 0x232a || code >= 0x2e80 && code <= 0xa4cf || code >= 0xac00 && code <= 0xd7a3 || code >= 0xf900 && code <= 0xfaff || code >= 0xfe10 && code <= 0xfe19 || code >= 0xfe30 && code <= 0xfe6f || code >= 0xff00 && code <= 0xff60 || code >= 0x1f300 && code <= 0x1faff || code >= 0x20000 && code <= 0x3fffd); }
function width(value: string): number { const code = value.codePointAt(0) ?? 0; return combining(code) ? 0 : wide(code) ? 2 : 1; }

export class QuirtTerminalRenderer {
  render(bytes: Buffer, rows: number, columns: number, inputLossIndicators: readonly string[] = []): QuirtTerminalRender {
    const normal = screen(rows, columns); const alternate = screen(rows, columns); let active = normal; let alternateScreen = false; let visible = true; let attributes: Record<string, string | boolean | number | null> = {}; const losses = [...inputLossIndicators]; const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes)) losses.push("invalid-or-incomplete-utf8");
    const scroll = () => { active.cells.shift(); active.cells.push(Array.from({ length: columns }, () => blank())); active.row = rows - 1; };
    const newline = () => { active.row += 1; if (active.row >= rows) scroll(); };
    const put = (value: string) => {
      const cellWidth = width(value); if (cellWidth === 0) { const row = active.cells[active.row]!; let prior: QuirtTerminalCell | undefined; for (let column = Math.min(columns - 1, active.column - 1); column >= 0; column -= 1) { if (row[column]?.width !== 0) { prior = row[column]; break; } } if (prior !== undefined) prior.text += value; return; }
      if (active.column >= columns || cellWidth === 2 && active.column === columns - 1) { active.column = 0; newline(); }
      const row = active.cells[active.row]!; row[active.column] = { text: value, width: cellWidth, attributes: Object.freeze({ ...attributes }) }; if (cellWidth === 2 && active.column + 1 < columns) row[active.column + 1] = { text: "", width: 0, attributes: Object.freeze({ ...attributes }) }; active.column += cellWidth;
    };
    const eraseLine = (mode: number) => { const row = active.cells[active.row]!; const start = mode === 1 ? 0 : active.column; const end = mode === 0 ? columns : active.column + 1; for (let index = start; index < end; index += 1) row[index] = blank(attributes); };
    const eraseDisplay = (mode: number) => { if (mode === 2 || mode === 3) { active.cells = screen(rows, columns).cells; active.row = 0; active.column = 0; return; } if (mode === 0) { eraseLine(0); for (let row = active.row + 1; row < rows; row += 1) active.cells[row] = Array.from({ length: columns }, () => blank(attributes)); } else { eraseLine(1); for (let row = 0; row < active.row; row += 1) active.cells[row] = Array.from({ length: columns }, () => blank(attributes)); } };
    for (let index = 0; index < text.length;) {
      const character = text[index]!;
      if (character === "\u001b") {
        if (text[index + 1] === "[") {
          const match = /^\u001b\[([?]?[0-9;:]*)([ -/]?)([@-~])/u.exec(text.slice(index)); if (match === null) { losses.push("incomplete-ansi-sequence"); break; }
          const raw = match[1] ?? ""; const final = match[3]!; const privateMode = raw.startsWith("?"); const values = (privateMode ? raw.slice(1) : raw).split(";").filter(Boolean).map(value => Number(value.split(":")[0])); const first = values[0] ?? 0;
          let supported = true;
          if (final === "H" || final === "f") { active.row = Math.max(0, Math.min(rows - 1, (values[0] ?? 1) - 1)); active.column = Math.max(0, Math.min(columns - 1, (values[1] ?? 1) - 1)); }
          else if (final === "A") active.row = Math.max(0, active.row - (first || 1)); else if (final === "B") active.row = Math.min(rows - 1, active.row + (first || 1)); else if (final === "C") active.column = Math.min(columns - 1, active.column + (first || 1)); else if (final === "D") active.column = Math.max(0, active.column - (first || 1));
          else if (final === "J") eraseDisplay(first); else if (final === "K") eraseLine(first);
          else if (final === "m") {
            for (let position = 0; position < (values.length || 1); position += 1) { const value = values[position] ?? 0; if (value === 0) attributes = {}; else if (value === 1) attributes.bold = true; else if (value === 2) attributes.dim = true; else if (value === 3) attributes.italic = true; else if (value === 4) attributes.underline = true; else if (value === 7) attributes.inverse = true; else if (value === 22) { delete attributes.bold; delete attributes.dim; } else if (value === 23) delete attributes.italic; else if (value === 24) delete attributes.underline; else if (value === 27) delete attributes.inverse; else if (value >= 30 && value <= 37) attributes.foreground = value - 30; else if (value >= 40 && value <= 47) attributes.background = value - 40; else if ((value === 38 || value === 48) && values[position + 1] === 2 && values.slice(position + 2, position + 5).length === 3) { attributes[value === 38 ? "foreground" : "background"] = `${values[position + 2] ?? 0},${values[position + 3] ?? 0},${values[position + 4] ?? 0}`; position += 4; } else losses.push("unsupported-sgr-attribute"); }
          } else if (privateMode && (final === "h" || final === "l")) {
            if (values.includes(1049)) { alternateScreen = final === "h"; active = alternateScreen ? alternate : normal; if (alternateScreen) { active.cells = screen(rows, columns).cells; active.row = 0; active.column = 0; } }
            if (values.includes(25)) visible = final === "h";
            if (values.some(value => value !== 1049 && value !== 25)) supported = false;
          } else supported = false;
          if (!supported) losses.push("unsupported-ansi-sequence");
          index += match[0].length; continue;
        }
        if (text[index + 1] === "]") { const rest = text.slice(index + 2); const bell = rest.indexOf("\u0007"); const st = rest.indexOf("\u001b\\"); const end = bell >= 0 && (st < 0 || bell < st) ? bell : st; const terminator = bell >= 0 && (st < 0 || bell < st) ? 1 : 2; if (end < 0) { losses.push("incomplete-osc-sequence"); break; } const content = rest.slice(0, end); if (content.startsWith("8;")) { const separator = content.indexOf(";", 2); const uri = separator < 0 ? "" : content.slice(separator + 1); if (uri.length === 0) delete attributes.hyperlink; else attributes.hyperlink = uri.slice(0, 8192); } index += 2 + end + terminator; continue; }
        if (["P", "_", "^"].includes(text[index + 1] ?? "")) { const rest = text.slice(index + 2); const end = rest.indexOf("\u001b\\"); if (end < 0) { losses.push("incomplete-terminal-extension"); break; } if (text[index + 1] === "_" && rest.startsWith("G")) losses.push("kitty-image-not-rendered"); if (text[index + 1] === "P" && rest.startsWith("q")) losses.push("sixel-image-not-rendered"); index += 2 + end + 2; continue; }
        if (index + 1 >= text.length) { losses.push("incomplete-ansi-sequence"); break; }
        losses.push("unsupported-ansi-sequence"); index += 2; continue;
      }
      if (character === "\r") active.column = 0; else if (character === "\n") newline(); else if (character === "\b") active.column = Math.max(0, active.column - 1); else if (character === "\t") active.column = Math.min(columns - 1, (Math.floor(active.column / 8) + 1) * 8); else if (character >= " ") { const code = text.codePointAt(index)!; const value = String.fromCodePoint(code); put(value); index += value.length; continue; }
      index += 1;
    }
    const renderedRows = active.cells.map(row => row.map(cell => cell.text).join("").replace(/ +$/u, ""));
    return Object.freeze({ rows: renderedRows, cells: active.cells, cursor: { row: active.row, column: active.column, visible }, alternateScreen, lossIndicators: [...new Set(losses)] });
  }
}
