import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    host: true,
    // fs.allow lets the dev server read ../contract/fixtures.json for mock mode.
    fs: { allow: [".."] },
    // Same as Caddy in production: /api/* goes to the API with the prefix stripped.
    proxy: {
      "/api": { target: "http://localhost:8000", rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
});
