import { describe, expect, it } from "vitest";

describe("release metadata", () => {
  it("embeds the shared product version at build time", () => {
    expect(__APP_VERSION__).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
