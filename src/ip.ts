import { isIP } from "node:net";
import { orEmpty, type Dns } from "./dns.ts";

// Reputation basics for a sending IP: reverse DNS (and whether it confirms forward) and
// the major DNS blocklists, read carefully.

export const BLOCKLISTS = [
  { zone: "zen.spamhaus.org", name: "Spamhaus ZEN" },
  { zone: "b.barracudacentral.org", name: "Barracuda" },
  { zone: "bl.spamcop.net", name: "SpamCop" },
  { zone: "psbl.surriel.com", name: "PSBL" },
  { zone: "bl.mailspike.net", name: "Mailspike" },
  // Level 1 lists this IP only. Levels 2 and 3 list whole provider networks, so we don't use them.
  { zone: "dnsbl-1.uceprotect.net", name: "UCEPROTECT level 1" },
];

// What Spamhaus ZEN's answers mean (https://www.spamhaus.org/faqs/dnsbl-usage/).
const ZEN_CODES: Record<string, string> = {
  "127.0.0.2": "SBL: a known spam source", "127.0.0.3": "SBL CSS: snowshoe spam or compromised host",
  "127.0.0.4": "XBL: infected or exploited host", "127.0.0.5": "XBL", "127.0.0.6": "XBL", "127.0.0.7": "XBL",
  "127.0.0.9": "DROP: hijacked network",
  "127.0.0.10": "PBL (ISP): a dynamic or end-user IP that shouldn't send mail directly",
  "127.0.0.11": "PBL (Spamhaus): an IP range not meant to send mail directly",
};

export type ListResult = { list: string; zone: string; state: "clean" | "listed" | "refused" | "error"; answer?: string; meaning?: string };

export async function checkBlocklists(dns: Dns, ip: string): Promise<ListResult[]> {
  const reversed = ip.split(".").reverse().join(".");
  return Promise.all(BLOCKLISTS.map(async ({ zone, name }): Promise<ListResult> => {
    try {
      const answers = await dns.resolve4(`${reversed}.${zone}`);
      // Spamhaus answers 127.255.255.x when it refuses the query (public or unregistered resolver).
      // That's "we didn't get an answer", not a listing; naive checkers get this wrong.
      if (answers.some((a) => a.startsWith("127.255.255."))) return { list: name, zone, state: "refused", answer: answers.join(", ") };
      const listed = answers.filter((a) => /^127\.0\.\d+\.\d+$/.test(a) && a !== "127.0.0.1");
      if (!listed.length) return { list: name, zone, state: "clean" };
      const meaning = zone === "zen.spamhaus.org" ? listed.map((a) => ZEN_CODES[a] ?? a).join("; ") : undefined;
      return { list: name, zone, state: "listed", answer: listed.join(", "), ...(meaning ? { meaning } : {}) };
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code === "ENOTFOUND" || code === "ENODATA") return { list: name, zone, state: "clean" };
      return { list: name, zone, state: "error", answer: code ?? (err as Error).message };
    }
  }));
}

// Forward-confirmed reverse DNS: the IP's PTR name must resolve back to the same IP.
export async function checkReverseDns(dns: Dns, ip: string) {
  const names = (await orEmpty(dns.reverse(ip))).map((n) => n.replace(/\.$/, "").toLowerCase());
  const confirmed: string[] = [];
  for (const name of names) {
    const addrs = await orEmpty(isIP(ip) === 6 ? dns.resolve6(name) : dns.resolve4(name));
    if (addrs.includes(ip)) confirmed.push(name);
  }
  return { ptr_names: names, forward_confirmed: confirmed.length > 0, confirmed_names: confirmed };
}

export async function checkSendingIp(dns: Dns, blocklistDns: Dns, ip: string, usingPrivateResolver: boolean) {
  const version = isIP(ip.trim());
  if (!version) throw new Error(`"${ip}" is not an IP address`);
  ip = ip.trim();
  const reverseDns = await checkReverseDns(dns, ip);
  const notes: string[] = [];
  if (!reverseDns.ptr_names.length) notes.push("No reverse DNS (PTR). Gmail and most receivers reject or spam-folder mail from IPs without one. Ask the IP's provider to set a PTR to your mail server's hostname.");
  else if (!reverseDns.forward_confirmed) notes.push(`Reverse DNS points to ${reverseDns.ptr_names.join(", ")}, but that name doesn't resolve back to ${ip}. Add an A/AAAA record so they match (forward-confirmed reverse DNS).`);

  let blocklists: ListResult[] | null = null;
  if (version === 4) {
    blocklists = await checkBlocklists(blocklistDns, ip);
    const listed = blocklists.filter((b) => b.state === "listed");
    if (listed.length) notes.push(`Listed on ${listed.map((b) => b.list).join(", ")}. Find the cause (compromised account, bad list, open relay) before requesting delisting on each list's site.`);
    if (blocklists.some((b) => b.state === "refused")) notes.push(usingPrivateResolver
      ? "A blocklist refused the query even from your BLOCKLIST_DNS resolver; check that it's a recursive resolver of your own."
      : "Spamhaus refuses queries from public DNS resolvers (like 8.8.8.8 or 1.1.1.1), so that result is unknown, not a listing. Set BLOCKLIST_DNS to a recursive resolver you run (for example unbound on 127.0.0.1) to check it.");
  } else {
    notes.push("Blocklist checks here cover IPv4 only.");
  }
  return { ip, reverse_dns: reverseDns, blocklists, notes };
}
