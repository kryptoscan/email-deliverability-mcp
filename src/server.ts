import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Dns } from "./dns.ts";
import { checkDomain } from "./domain.ts";
import { checkHeaders } from "./headers.ts";
import { checkSendingIp } from "./ip.ts";

export const VERSION = "0.1.0";

const json = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 1) }] });
const fail = (err: unknown) => ({ content: [{ type: "text" as const, text: (err as Error).message }], isError: true });
// Every tool only reads public DNS or text it's given.
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

export type Deps = { dns: Dns; blocklistDns: Dns; privateBlocklistResolver: boolean };

export function buildServer({ dns, blocklistDns, privateBlocklistResolver }: Deps) {
  const server = new McpServer(
    { name: "email-deliverability", version: VERSION },
    { instructions: "Tools for diagnosing email deliverability: a domain's DNS records, a sending IP's reputation basics, and a received message's headers. Report problems with their fixes, most serious first." },
  );

  server.registerTool("check_domain", {
    title: "Check a domain's email DNS",
    description: "Check a domain's SPF (including the 10-DNS-lookup limit), DMARC policy and reporting, DKIM keys on common selectors, and MX records. Returns problems ranked by severity with the fix for each, plus the email services the domain uses.",
    inputSchema: {
      domain: z.string().min(3).max(253).describe("The domain, e.g. example.com (a URL or email address's domain also works)."),
      dkim_selectors: z.array(z.string().max(63)).max(10).optional()
        .describe("Extra DKIM selectors to look for, e.g. from the s= value of a message's DKIM-Signature header."),
    },
    annotations: READ_ONLY,
  }, async ({ domain, dkim_selectors }) => {
    try { return json(await checkDomain(dns, domain.includes("@") ? domain.split("@").pop()! : domain, dkim_selectors)); }
    catch (err) { return fail(err); }
  });

  server.registerTool("check_sending_ip", {
    title: "Check a sending IP",
    description: "Check a mail server's IP: reverse DNS (PTR) and whether it resolves back to the IP, and listings on Spamhaus ZEN, Barracuda, SpamCop, PSBL, Mailspike and UCEPROTECT level 1. A refused Spamhaus query is reported as unknown, never as a listing.",
    inputSchema: { ip: z.string().min(2).max(45).describe("IPv4 or IPv6 address of the sending server.") },
    annotations: READ_ONLY,
  }, async ({ ip }) => {
    try { return json(await checkSendingIp(dns, blocklistDns, ip, privateBlocklistResolver)); }
    catch (err) { return fail(err); }
  });

  server.registerTool("check_email_headers", {
    title: "Check email headers",
    description: "Check a received email's headers against Gmail's and Yahoo's bulk sender requirements: SPF, DKIM and DMARC results, From domain alignment, one-click unsubscribe (and whether DKIM covers it), TLS, reverse DNS and Message-ID. Use the full headers as the recipient got them (Gmail: Show original).",
    inputSchema: { headers: z.string().min(10).max(200_000).describe("The raw message headers (the body may be included; it's ignored).") },
    annotations: READ_ONLY,
  }, async ({ headers }) => {
    try { return json(checkHeaders(headers)); }
    catch (err) { return fail(err); }
  });

  return server;
}
