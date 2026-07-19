import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { QuirtTerminalRenderer } from "./terminal-renderer.js";

describe("Quirt deterministic terminal renderer", () => {
  it("applies SGR attributes, indexed colors, true color, and selective resets", () => {
    const rendered = new QuirtTerminalRenderer().render(Buffer.from("\u001b[1;2;3;4;7;31;44mA\u001b[22;23;24;27mB\u001b[38;2;1;2;3;48;2;4;5;6mC\u001b[0mD"), 4, 20);
    assert.deepEqual(rendered.cells[0]![0]!.attributes, { bold: true, dim: true, italic: true, underline: true, inverse: true, foreground: 1, background: 4 });
    assert.deepEqual(rendered.cells[0]![1]!.attributes, { foreground: 1, background: 4 });
    assert.deepEqual(rendered.cells[0]![2]!.attributes, { foreground: "1,2,3", background: "4,5,6" });
    assert.deepEqual(rendered.cells[0]![3]!.attributes, {});
  });

  it("bounds cursor movement, erases every supported region, wraps, scrolls, and handles controls", () => {
    const renderer = new QuirtTerminalRenderer();
    const moved = renderer.render(Buffer.from("first\nsecond\u001b[2;3H@\u001b[9A\u001b[9B\u001b[9C\u001b[9D\rX\bY\tZ"), 3, 12);
    assert.ok(moved.cursor.row >= 0 && moved.cursor.row < 3); assert.ok(moved.cursor.column >= 0 && moved.cursor.column < 12);
    for (const sequence of ["\u001b[0J", "\u001b[1J", "\u001b[2J", "\u001b[3J", "\u001b[0K", "\u001b[1K", "\u001b[2K"]) {
      const erased = renderer.render(Buffer.from(`one\ntwo${sequence}x`), 2, 5); assert.equal(erased.rows.length, 2);
    }
    const wide = renderer.render(Buffer.from("界e\u0301"), 2, 6); assert.ok(wide.cells.flat().some(cell => cell.width === 0)); assert.equal(wide.cells[0]![2]!.text, "e\u0301");
    const scrolled = renderer.render(Buffer.from("line1\nline2\nline3\nline4"), 2, 6); assert.equal(scrolled.rows.length, 2);
  });

  it("tracks alternate screen, cursor visibility, OSC 8 links, and unsupported image fidelity", () => {
    const renderer = new QuirtTerminalRenderer();
    const alternate = renderer.render(Buffer.from("normal\u001b[?1049h\u001b[?25l\u001b]8;;https://example.invalid\u0007L\u001b]8;;\u0007\u001b_Gpayload\u001b\\\u001bPqpayload\u001b\\\u001b^ignored\u001b\\"), 3, 20);
    assert.equal(alternate.alternateScreen, true); assert.equal(alternate.cursor.visible, false); assert.equal(alternate.cells[0]![0]!.attributes.hyperlink, "https://example.invalid"); assert.ok(alternate.lossIndicators.includes("kitty-image-not-rendered")); assert.ok(alternate.lossIndicators.includes("sixel-image-not-rendered"));
    const normal = renderer.render(Buffer.from("\u001b]8;;https://example.invalid\u001b\\S\u001b]8;;\u001b\\\u001b[?1049hA\u001b[?1049l\u001b[?25hN"), 2, 20); assert.equal(normal.alternateScreen, false); assert.equal(normal.cursor.visible, true); assert.equal(normal.cells[0]![0]!.attributes.hyperlink, "https://example.invalid");
  });

  it("reports invalid UTF-8 and incomplete ANSI, OSC, and terminal-extension sequences", () => {
    const renderer = new QuirtTerminalRenderer();
    assert.equal(renderer.render(Buffer.from("\u0301"), 2, 10).cursor.column, 0); assert.ok(renderer.render(Buffer.from("\u001bX"), 2, 10).lossIndicators.includes("unsupported-ansi-sequence")); assert.ok(renderer.render(Buffer.from("\u001b"), 2, 10).lossIndicators.includes("incomplete-ansi-sequence"));
    assert.ok(renderer.render(Buffer.from("\u001b[5n"), 2, 10).lossIndicators.includes("unsupported-ansi-sequence")); assert.ok(renderer.render(Buffer.from("\u001b[5m"), 2, 10).lossIndicators.includes("unsupported-sgr-attribute"));
    assert.ok(renderer.render(Buffer.from([0xff]), 2, 10).lossIndicators.includes("invalid-or-incomplete-utf8"));
    assert.ok(renderer.render(Buffer.from("\u001b["), 2, 10).lossIndicators.includes("incomplete-ansi-sequence"));
    assert.ok(renderer.render(Buffer.from("\u001b]8;;unterminated"), 2, 10).lossIndicators.includes("incomplete-osc-sequence"));
    assert.ok(renderer.render(Buffer.from("\u001b_Gunterminated"), 2, 10).lossIndicators.includes("incomplete-terminal-extension"));
  });
});
