import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built files; in development it loads this dev server.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true },
});
