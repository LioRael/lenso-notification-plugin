import { resolve } from "node:path";
import stylex from "@stylexjs/unplugin/vite";
import { defineConfig } from "vite";

const runtimeShim = resolve(import.meta.dirname, "src/console-react-runtime-shim.mjs");

export default defineConfig({
  base: "./",
  build: {
    emptyOutDir: true,
    lib: {
      cssFileName: "stylex",
      entry: resolve(import.meta.dirname, "src/index.tsx"),
      fileName: () => "index.js",
      formats: ["es"],
    },
    outDir: resolve(import.meta.dirname, "dist"),
    rolldownOptions: {
      output: {
        assetFileNames: "assets/[name][extname]",
        chunkFileNames: "chunks/[name]-[hash].js",
        entryFileNames: "index.js",
      },
    },
  },
  plugins: [stylex({ devMode: "off", useCSSLayers: true })],
  publicDir: false,
  resolve: {
    alias: [
      { find: /^react\/jsx-runtime$/u, replacement: runtimeShim },
      { find: /^react$/u, replacement: runtimeShim }
    ]
  },
  root: resolve(import.meta.dirname),
});
