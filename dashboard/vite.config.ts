import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
	base: "/static/ledger-dashboard/",
	plugins: [react()],
	build: {
		outDir: "../web/static/ledger-dashboard",
		emptyOutDir: true,
		cssCodeSplit: false,
		rollupOptions: {
			output: {
				entryFileNames: "assets/ledger-dashboard.js",
				chunkFileNames: "assets/[name].js",
				assetFileNames: "assets/ledger-dashboard.[ext]"
			}
		}
	}
});