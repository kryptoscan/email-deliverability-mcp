#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { envList, systemDns } from "./dns.ts";
import { buildServer } from "./server.ts";

// The same tools over Streamable HTTP, for a public endpoint. Stateless: every POST gets a
// fresh server, so nothing is kept between requests. Meant to run behind a TLS proxy.
//
// Environment (in addition to DNS_SERVERS / BLOCKLIST_DNS, see index.ts):
//   PORT            listen port (default 3300), on HOST (default 127.0.0.1)
//   MCP_PATH        endpoint path (default /mcp)
//   TRUST_PROXY=1   take the client IP from X-Forwarded-For (only behind your own proxy)
//   RATE_LIMIT      requests per client IP per 10 minutes (default 120)
//   GLOBAL_LIMIT    requests per hour across all clients (default 5000)

const PORT = Number(process.env.PORT ?? 3300);
const HOST = process.env.HOST ?? "127.0.0.1";
const MCP_PATH = process.env.MCP_PATH ?? "/mcp";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const RATE_LIMIT = Number(process.env.RATE_LIMIT ?? 120);
const GLOBAL_LIMIT = Number(process.env.GLOBAL_LIMIT ?? 5000);
const MAX_BODY = 256 * 1024;

const dnsServers = envList(process.env.DNS_SERVERS);
const blocklistServers = envList(process.env.BLOCKLIST_DNS);
const deps = {
  dns: systemDns(dnsServers),
  blocklistDns: systemDns(blocklistServers.length ? blocklistServers : dnsServers),
  privateBlocklistResolver: blocklistServers.length > 0,
};

// Fixed-window counters: per client IP (10 minutes) and overall (1 hour).
export function limiter(perClient: number, global: number, now = () => Date.now()) {
  const clients = new Map<string, { n: number; reset: number }>();
  let total = { n: 0, reset: 0 };
  return (ip: string): { ok: boolean; retryAfter: number } => {
    const t = now();
    if (t >= total.reset) total = { n: 0, reset: t + 3600_000 };
    let c = clients.get(ip);
    if (!c || t >= c.reset) {
      c = { n: 0, reset: t + 600_000 };
      clients.set(ip, c);
      if (clients.size > 50_000) for (const [k, v] of clients) if (t >= v.reset) clients.delete(k);
    }
    if (c.n >= perClient) return { ok: false, retryAfter: Math.ceil((c.reset - t) / 1000) };
    if (total.n >= global) return { ok: false, retryAfter: Math.ceil((total.reset - t) / 1000) };
    c.n++;
    total.n++;
    return { ok: true, retryAfter: 0 };
  };
}
const allow = limiter(RATE_LIMIT, GLOBAL_LIMIT);

const clientIp = (req: IncomingMessage) =>
  (TRUST_PROXY ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() : "") || req.socket.remoteAddress || "unknown";

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
}
const rpcError = (message: string) => ({ jsonrpc: "2.0", error: { code: -32000, message }, id: null });

async function readJson(req: IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw Object.assign(new Error("Request too large"), { status: 413 });
    chunks.push(chunk as Buffer);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Invalid JSON"), { status: 400 }); }
}

const http = createServer(async (req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  if (req.method === "GET" && path === "/health") return send(res, 200, { ok: true });
  if (path !== MCP_PATH) return send(res, 404, { error: "Not found" });
  // Stateless: no server-to-client streams (GET) and no sessions to end (DELETE).
  if (req.method !== "POST") return send(res, 405, rpcError("Method not allowed; POST JSON-RPC to this URL."), { allow: "POST" });

  const verdict = allow(clientIp(req));
  if (!verdict.ok) return send(res, 429, rpcError("Rate limit reached; try again later."), { "retry-after": String(verdict.retryAfter) });

  let body: unknown;
  try { body = await readJson(req); }
  catch (err) { return send(res, (err as { status?: number }).status ?? 400, rpcError((err as Error).message)); }

  const server = buildServer(deps);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => { void transport.close(); void server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    if (!res.headersSent) send(res, 500, rpcError("Internal error"));
    console.error("request failed:", (err as Error).message);
  }
});

http.listen(PORT, HOST, () => console.log(`email-deliverability-mcp listening on http://${HOST}:${PORT}${MCP_PATH}`));
