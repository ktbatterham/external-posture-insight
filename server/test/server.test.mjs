import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import test from "node:test";
import { once } from "node:events";

const SERVER_ENTRY = new URL("../index.mjs", import.meta.url);

const getFreePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not allocate a test port."));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
    server.on("error", reject);
  });

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const requestRawPath = (baseUrl, requestPath) =>
  new Promise((resolve, reject) => {
    const url = new URL(baseUrl);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: requestPath,
        method: "GET",
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => {
          resolve({ statusCode: response.statusCode || 0, body });
        });
      },
    );
    request.on("error", reject);
    request.end();
  });

function createServerProcess(envOverrides = {}) {
  const child = spawn(process.execPath, [SERVER_ENTRY.pathname], {
    cwd: new URL("../../", import.meta.url).pathname,
    env: {
      ...process.env,
      NODE_ENV: "test",
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  return {
    child,
    getStdout: () => stdout,
    getStderr: () => stderr,
  };
}

async function startServer(envOverrides = {}) {
  const port = await getFreePort();
  const serverProcess = createServerProcess({
    PORT: String(port),
    ...envOverrides,
  });

  const started = await Promise.race([
    once(serverProcess.child.stdout, "data"),
    once(serverProcess.child, "exit").then(([code]) => {
      throw new Error(`Server exited before startup with code ${code}.\n${serverProcess.getStdout()}\n${serverProcess.getStderr()}`);
    }),
    wait(5000).then(() => {
      throw new Error(`Timed out waiting for server startup.\n${serverProcess.getStdout()}\n${serverProcess.getStderr()}`);
    }),
  ]);

  const firstChunk = String(started[0] || "");
  if (!firstChunk.includes("server_started")) {
    await wait(100);
  }

  return {
    ...serverProcess,
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    async stop() {
      if (serverProcess.child.exitCode !== null) {
        return;
      }
      serverProcess.child.kill("SIGTERM");
      await once(serverProcess.child, "exit");
    },
  };
}

test("server blocks production startup without explicit auth or opt-in", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "",
    ALLOW_UNAUTHENTICATED: "false",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /server_start_blocked/);
});

test("server blocks production startup in multi-instance mode without distributed limiter opt-in", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "test-secret",
    DEPLOYMENT_MODE: "multi-instance",
    ALLOW_INMEMORY_RATE_LIMITER_IN_MULTI_INSTANCE: "false",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /DEPLOYMENT_MODE=multi-instance/i);
});

test("analyze endpoint requires API key when configured", async () => {
  const server = await startServer({
    API_KEY: "test-secret",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://example.com")}`);
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.match(payload.error, /API key/i);
  } finally {
    await server.stop();
  }
});

test("health endpoint includes deployment and rate-limit metadata", async () => {
  const server = await startServer({
    DEPLOYMENT_MODE: "single-instance",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/health`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.ok, true);
    assert.equal(payload.deploymentMode, "single-instance");
    assert.equal(payload.rateLimit.backend, "in-memory");
    assert.equal(payload.rateLimit.maxRequests, 30);
  } finally {
    await server.stop();
  }
});

test("analyze endpoint returns a sanitized error for invalid targets", async () => {
  const server = await startServer();

  try {
    const response = await fetch(
      `${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://user:pass@example.com")}`,
    );
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.error, "Unable to analyze that target. Please check the URL and try again.");
    assert.doesNotMatch(JSON.stringify(payload), /embedded credentials|user:pass|stack/i);
  } finally {
    await server.stop();
  }
});

test("analyze endpoint rejects unsupported methods", async () => {
  const server = await startServer();

  try {
    const response = await fetch(
      `${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://example.com")}`,
      { method: "POST" },
    );
    const payload = await response.json();

    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET, HEAD");
    assert.match(payload.error, /Method not allowed/i);
  } finally {
    await server.stop();
  }
});

test("rate limiting ignores spoofed forwarded headers unless trust proxy is enabled", async () => {
  const server = await startServer();

  try {
    let limitedResponse = null;
    for (let index = 0; index < 31; index += 1) {
      const response = await fetch(
        `${server.baseUrl}/api/analyze?url=${encodeURIComponent(`https://localhost-${index}.example.com`)}`,
        {
          headers: {
            "X-Forwarded-For": `198.51.100.${index}`,
          },
        },
      );
      if (response.status === 429) {
        limitedResponse = response;
        break;
      }
    }

    assert.ok(limitedResponse, "Expected spoofed forwarded headers to be ignored for rate limiting.");
    assert.equal(limitedResponse.status, 429);
    assert.equal(limitedResponse.headers.get("retry-after"), "900");
  } finally {
    await server.stop();
  }
});

test("trusted proxy mode uses forwarded headers for client attribution", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    for (let index = 0; index < 31; index += 1) {
      const response = await fetch(
        `${server.baseUrl}/api/analyze?url=${encodeURIComponent(`https://localhost-${index}.example.com`)}`,
        {
          headers: {
            "X-Forwarded-For": `198.51.100.${index}`,
          },
        },
      );
      assert.equal(response.status, 400);
    }
  } finally {
    await server.stop();
  }
});

test("rate limiting supports environment overrides", async () => {
  const server = await startServer({
    RATE_LIMIT_WINDOW_MS: "2000",
    RATE_LIMIT_MAX_REQUESTS: "2",
  });

  try {
    const one = await fetch(`${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://localhost-1.example.com")}`);
    const two = await fetch(`${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://localhost-2.example.com")}`);
    const three = await fetch(`${server.baseUrl}/api/analyze?url=${encodeURIComponent("https://localhost-3.example.com")}`);

    assert.equal(one.status, 400);
    assert.equal(two.status, 400);
    assert.equal(three.status, 429);
    assert.equal(three.headers.get("retry-after"), "2");
  } finally {
    await server.stop();
  }
});

test("static serving rejects encoded traversal paths", async () => {
  const server = await startServer();

  try {
    const response = await requestRawPath(server.baseUrl, "/%2e%2e/%2e%2e/package.json");
    assert.equal(response.statusCode, 400);
    assert.match(response.body, /invalid request path/i);
  } finally {
    await server.stop();
  }
});
