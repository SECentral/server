/// <reference types="vitest/config" />
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Single product version, shared with the server (server/VERSION).
const appVersion = readFileSync(new URL("../VERSION", import.meta.url), "utf8").trim();

export default defineConfig({
  base: "/spa/",
  define: { __APP_VERSION__: JSON.stringify(appVersion) },
  plugins: [react()],
  build: {
    outDir: "../public/spa",
    emptyOutDir: true
  },
  server: {
    proxy: {
      "/api": "http://localhost:3000"
    }
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"]
  }
});
