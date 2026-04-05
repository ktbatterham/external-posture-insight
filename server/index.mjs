import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { analyzeUrl, formatErrorMessage } from "../packages/core/dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const publicDir = path.join(projectRoot, "public");
const port = Number(process.env.PORT || 8787);

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function getMimeType(filePath) {
  const ext = path.extname(filePath);
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}

function serveStatic(requestPath, method, response) {
  const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
  const staticTarget = path.join(distDir, cleanPath);
  const publicTarget = path.join(publicDir, cleanPath);
  const fallbackTarget = path.join(distDir, "index.html");
  const preferredPath = fs.existsSync(staticTarget)
    ? staticTarget
    : fs.existsSync(publicTarget)
      ? publicTarget
      : fs.existsSync(fallbackTarget)
        ? fallbackTarget
        : null;

  if (!preferredPath) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Frontend build not found. Run `npm run build` for a production preview.");
    return;
  }

  response.writeHead(200, { "Content-Type": getMimeType(preferredPath) });
  if (method === "HEAD") {
    response.end();
    return;
  }
  fs.createReadStream(preferredPath).pipe(response);
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (requestUrl.pathname === "/api/health") {
    sendJson(response, 200, { ok: true, now: new Date().toISOString() });
    return;
  }

  if (requestUrl.pathname === "/api/analyze") {
    try {
      const target = requestUrl.searchParams.get("url") || "";
      const result = await analyzeUrl(target);
      sendJson(response, 200, result);
    } catch (error) {
      sendJson(response, 400, {
        error: formatErrorMessage(error),
      });
    }
    return;
  }

  if (request.method === "GET" || request.method === "HEAD") {
    serveStatic(requestUrl.pathname, request.method, response);
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
});

server.listen(port, () => {
  console.log(`Secure Header Insight API listening on http://127.0.0.1:${port}`);
});
