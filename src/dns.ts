import { Resolver } from "node:dns/promises";

// The DNS calls the checks need. Tests pass a fake; the server uses the system resolver
// (or the servers in DNS_SERVERS).
export interface Dns {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  reverse(ip: string): Promise<string[]>;
}

export function systemDns(servers: string[] = []): Dns {
  const r = new Resolver({ timeout: 5000, tries: 2 });
  if (servers.length) r.setServers(servers);
  return r;
}

// "Doesn't exist" answers are a normal result for these checks, not an error.
export const isMissing = (err: unknown) => ["ENOTFOUND", "ENODATA", "NXDOMAIN"].includes((err as { code?: string }).code ?? "");

export async function txt(dns: Dns, name: string): Promise<string[]> {
  try {
    return (await dns.resolveTxt(name)).map((chunks) => chunks.join(""));
  } catch (err) {
    if (isMissing(err)) return [];
    throw err;
  }
}

export async function orEmpty<T>(p: Promise<T[]>): Promise<T[]> {
  try {
    return await p;
  } catch (err) {
    if (isMissing(err)) return [];
    throw err;
  }
}

export const envList = (v: string | undefined) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
