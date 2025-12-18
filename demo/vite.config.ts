import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    // Required for stellar-sdk in browser
    global: "globalThis",
  },
  resolve: {
    alias: {
      // Buffer polyfill
      buffer: "buffer",
    },
    // Ensure symlinks are resolved to prevent duplicate module instances
    preserveSymlinks: false,
    // Force Vite to use a single instance of these packages
    dedupe: ["@stellar/stellar-sdk", "@stellar/stellar-base"],
  },
  optimizeDeps: {
    include: [
      "buffer",
      "@stellar/stellar-sdk",
      "@stellar/stellar-sdk/rpc",
      "@stellar/stellar-base",
    ],
    esbuildOptions: {
      define: {
        global: "globalThis",
      },
    },
  },
  build: {
    commonjsOptions: {
      include: [/node_modules/, /smart-account-kit/, /smart-account-kit-bindings/],
      transformMixedEsModules: true,
    },
  },
});
