import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Served by the API at /ui (same origin, so session cookies and CSRF work without CORS).
export default defineConfig({ base: "/ui/", plugins: [react()], build: { outDir: "dist", sourcemap: false } });
