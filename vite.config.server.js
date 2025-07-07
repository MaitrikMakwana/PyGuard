import { defineConfig } from "vite";
import path from "path";

// Server build configuration
export default defineConfig({
  build: {
    lib: {
      entry.resolve(__dirname, "server/node-build.ts"),
      name: "server",
      fileName: "production",
      formats"es"],
    },
    outDir: "dist/server",
    target: "node22",
    ssr,
    rollupOptions: {
      external
        // Node.js built-ins
        "fs",
        "path",
        "url",
        "http",
        "https",
        "os",
        "crypto",
        "stream",
        "util",
        "events",
        "buffer",
        "querystring",
        "child_process",
        // External dependencies that should not be bundled
        "express",
        "cors",
      ],
      output: {
        format: "es",
        entryFileNames: "[name].mjs",
      },
    },
    minify, // Keep readable for debugging
    sourcemap,
  },
  resolve: {
    alias: {
      "@".resolve(__dirname, "./client"),
      "@shared".resolve(__dirname, "./shared"),
    },
  },
  define: {
    "process.env.NODE_ENV": '"production"',
  },
});
