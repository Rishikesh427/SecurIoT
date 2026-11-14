import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // fs.allow lets the dev server read ../contract/fixtures.json for mock mode.
  server: { port: 5173, host: true, fs: { allow: [".."] } },
});
