import { expect, it } from "vitest";
import { readFileSync } from "node:fs";

const css = readFileSync("src/app.css", "utf8");

function luminance(hex: string) {
  const channels = hex.slice(1).match(/../g)!.map((value) => {
    const channel = parseInt(value, 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

it("keeps the host dark label text and status palette at least 8:1 on its control surface", () => {
  const palette = Object.fromEntries([...css.matchAll(/--host-dark-(\w+): (#[\da-f]{6});/g)].map((match) => [match[1], match[2]]));
  for (const foreground of ["text", "muted", "link", "success", "warning", "danger"]) {
    const ratio = (luminance(palette[foreground]) + 0.05) / (luminance(palette.control) + 0.05);
    expect(ratio, `${foreground} on control`).toBeGreaterThanOrEqual(8);
  }
});
