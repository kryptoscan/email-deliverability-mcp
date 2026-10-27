#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { envList, systemDns } from "./dns.ts";
import { buildServer } from "./server.ts";

// Environment:
//   DNS_SERVERS    resolvers for normal lookups (default: the system's)
//   BLOCKLIST_DNS  a recursive resolver you run, for blocklist lookups. Spamhaus refuses
//                  queries from public resolvers, so without one its result is "unknown".
const dnsServers = envList(process.env.DNS_SERVERS);
const blocklistServers = envList(process.env.BLOCKLIST_DNS);

const server = buildServer({
  dns: systemDns(dnsServers),
  blocklistDns: systemDns(blocklistServers.length ? blocklistServers : dnsServers),
  privateBlocklistResolver: blocklistServers.length > 0,
});
await server.connect(new StdioServerTransport());
