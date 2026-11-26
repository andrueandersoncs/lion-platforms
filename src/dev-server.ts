import { join } from "node:path";

const DOCS = join(import.meta.dirname, "../docs");
const PORT = Number(process.env.PORT ?? "4210");

const MIME: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".jpg": "image/jpeg",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

Bun.serve({
  fetch(req) {
    const url = new URL(req.url);
    const rel = url.pathname === "/" ? "/index.html" : url.pathname;
    const file = Bun.file(join(DOCS, rel));
    const ext = rel.slice(rel.lastIndexOf("."));
    return new Response(file, {
      headers: {
        "content-type": MIME[ext] ?? "application/octet-stream",
      },
    });
  },
  port: PORT,
});

console.log(`lion-platforms marketing hub running at http://127.0.0.1:${PORT}`);
