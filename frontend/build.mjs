// Bundles src/ into dist/ with esbuild. Usage: node build.mjs [--watch]
import { build, context } from "esbuild";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

const watch = process.argv.includes("--watch");
rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/assets", { recursive: true });
cpSync("public", "dist", { recursive: true });

const options = {
  entryPoints: { app: "src/main.jsx" },
  outdir: "dist/assets",
  bundle: true,
  minify: !watch,
  sourcemap: watch,
  jsx: "automatic",
  target: ["es2020"],
  define: { "process.env.NODE_ENV": JSON.stringify(watch ? "development" : "production") },
  logLevel: "info",
};

if (watch) {
  const ctx = await context(options);
  await ctx.watch();
  console.log("Watching for changes...");
} else {
  await build(options);
  // Cloudflare Pages: only /api/* invokes the proxy Function; everything
  // else stays a free static request (SPA fallback to index.html is automatic).
  writeFileSync("dist/_routes.json", JSON.stringify({ version: 1, include: ["/api/*"], exclude: [] }));
}
