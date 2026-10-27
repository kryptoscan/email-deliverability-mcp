import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Dns } from "../src/dns.ts";
import { checkDomain, spfLookups } from "../src/domain.ts";
import { checkHeaders, orgDomain } from "../src/headers.ts";
import { checkBlocklists, checkSendingIp } from "../src/ip.ts";

const notFound = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });

// A fake resolver: TXT/A/AAAA/MX/PTR records by name; anything else doesn't exist.
function fakeDns(z: { txt?: Record<string, string[]>; a?: Record<string, string[]>; aaaa?: Record<string, string[]>;
  mx?: Record<string, string[]>; ptr?: Record<string, string[]> }): Dns {
  const get = <T>(m: Record<string, T[]> | undefined, k: string) => { const v = m?.[k]; if (!v?.length) throw notFound(); return v; };
  return {
    async resolveTxt(n) { return get(z.txt, n).map((t) => [t]); },
    async resolveMx(n) { return get(z.mx, n).map((exchange, priority) => ({ exchange, priority })); },
    async resolve4(n) { return get(z.a, n); },
    async resolve6(n) { return get(z.aaaa, n); },
    async reverse(ip) { return get(z.ptr, ip); },
  };
}

const KEY = "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyz";

describe("check_domain", () => {
  it("a well-configured domain has no serious problems and its services are detected", async () => {
    const dns = fakeDns({
      mx: { "good.test": ["aspmx.l.google.com."] },
      txt: {
        "good.test": ["v=spf1 include:_spf.google.com include:sendgrid.net ~all", "google-site-verification=x"],
        "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
        "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
        "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"],
        "_dmarc.good.test": ["v=DMARC1; p=quarantine; rua=mailto:d@good.test"],
        "google._domainkey.good.test": [`v=DKIM1; k=rsa; ${KEY}`],
      },
    });
    const r = await checkDomain(dns, "https://www.Good.test/pricing");
    assert.equal(r.domain, "good.test");
    assert.equal(r.summary, "No problems found");
    assert.equal(r.spf.dns_lookups, 3);
    assert.deepEqual(r.dkim.selectors_found, ["google"]);
    assert.deepEqual(r.services_detected.sort(), ["Google Workspace", "SendGrid"]);
  });

  it("flags missing DMARC, two SPF records and missing DKIM, most serious first", async () => {
    const dns = fakeDns({ mx: { "bad.test": ["mx.bad.test"] }, txt: { "bad.test": ["v=spf1 a ~all", "v=spf1 mx -all"] } });
    const r = await checkDomain(dns, "bad.test");
    assert.equal(r.spf.status, "multiple");
    assert.equal(r.dmarc.status, "missing");
    assert.equal(r.summary, "2 serious problems found");
    assert.ok(r.issues.some((i) => /DKIM/.test(i.problem) && i.severity === "medium"));
    assert.match(r.issues.find((i) => /DMARC/.test(i.problem))!.fix, /_dmarc\.bad\.test/);
  });

  it("counts nested SPF lookups past the limit, without looping on a cycle", async () => {
    const txt: Record<string, string[]> = { "many.test": ["v=spf1 include:a.test include:loop.test mx a ~all"],
      "loop.test": ["v=spf1 include:many.test ~all"] };
    txt["a.test"] = ["v=spf1 " + Array.from({ length: 9 }, (_, i) => `include:n${i}.test`).join(" ") + " ~all"];
    for (let i = 0; i < 9; i++) txt[`n${i}.test`] = ["v=spf1 ip4:192.0.2.0/24 ~all"];
    const r = await checkDomain(fakeDns({ txt }), "many.test");
    assert.equal(r.spf.status, "too many lookups");
    assert.equal(r.spf.dns_lookups, 14);
    assert.equal((await spfLookups(fakeDns({ txt }), txt["loop.test"][0], new Set(["loop.test"]))).count, 14);
  });

  it("treats +all as too permissive and p=none as monitoring only", async () => {
    const r = await checkDomain(fakeDns({ txt: { "open.test": ["v=spf1 +all"], "_dmarc.open.test": ["v=DMARC1; p=none"] } }), "open.test");
    assert.equal(r.spf.status, "too permissive");
    assert.equal(r.dmarc.status, "monitoring only");
    assert.ok(r.issues.some((i) => /rua/.test(i.problem)));
  });

  it("doesn't report DKIM keys on a domain that answers every name", async () => {
    const dns = fakeDns({ txt: {} });
    dns.resolveTxt = async (n) => (n.includes("._domainkey.") ? [[`v=DKIM1; ${KEY}`]] : (() => { throw notFound(); })());
    const r = await checkDomain(dns, "wild.test");
    assert.equal(r.dkim.wildcard, true);
    assert.deepEqual(r.dkim.selectors_found, []);
  });

  it("rejects things that aren't domains", async () => {
    await assert.rejects(checkDomain(fakeDns({}), "not a domain"), /not a domain name/);
  });
});

describe("check_sending_ip", () => {
  it("reads listed, refused and clean correctly", async () => {
    const dns = fakeDns({ a: {
      "9.2.0.192.zen.spamhaus.org": ["127.255.255.254"],     // refused: public resolver
      "9.2.0.192.b.barracudacentral.org": ["127.0.0.2"],     // listed
    } });
    const states = Object.fromEntries((await checkBlocklists(dns, "192.0.2.9")).map((s) => [s.zone, s.state]));
    assert.equal(states["zen.spamhaus.org"], "refused");
    assert.equal(states["b.barracudacentral.org"], "listed");
    assert.equal(states["bl.spamcop.net"], "clean");
  });

  it("explains Spamhaus codes and the public-resolver problem", async () => {
    const listed = fakeDns({ a: { "9.2.0.192.zen.spamhaus.org": ["127.0.0.3"] } });
    const r = await checkSendingIp(listed, listed, "192.0.2.9", false);
    assert.match(r.blocklists!.find((b) => b.state === "listed")!.meaning!, /SBL CSS/);
    const refused = fakeDns({ a: { "9.2.0.192.zen.spamhaus.org": ["127.255.255.254"] } });
    const r2 = await checkSendingIp(refused, refused, "192.0.2.9", false);
    assert.ok(r2.notes.some((n) => /unknown, not a listing/.test(n) && /BLOCKLIST_DNS/.test(n)));
  });

  it("checks that reverse DNS resolves back to the IP", async () => {
    const ok = fakeDns({ ptr: { "192.0.2.9": ["mta1.good.test."] }, a: { "mta1.good.test": ["192.0.2.9"] } });
    assert.equal((await checkSendingIp(ok, ok, "192.0.2.9", true)).reverse_dns.forward_confirmed, true);
    const mismatch = fakeDns({ ptr: { "192.0.2.9": ["host.example.net"] }, a: { "host.example.net": ["198.51.100.1"] } });
    const r = await checkSendingIp(mismatch, mismatch, "192.0.2.9", true);
    assert.equal(r.reverse_dns.forward_confirmed, false);
    assert.ok(r.notes.some((n) => /doesn't resolve back/.test(n)));
    const none = await checkSendingIp(fakeDns({}), fakeDns({}), "192.0.2.9", true);
    assert.ok(none.notes.some((n) => /No reverse DNS/.test(n)));
  });

  it("rejects things that aren't IPs", async () => {
    await assert.rejects(checkSendingIp(fakeDns({}), fakeDns({}), "mail.example.com", false), /not an IP address/);
  });
});

describe("check_email_headers", () => {
  const good = [
    "Received: by 2002:a05:6a10:1 with SMTP id a;", "        Tue, 27 Oct 2026 02:22:50 -0700",
    "Received: from mta1.good.test (mta1.good.test. [192.0.2.9])", "        by mx.google.com with ESMTPS id x", "        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);",
    "Authentication-Results: mx.google.com;", "       dkim=pass header.i=@good.test header.s=mp1;",
    '       spf=pass (google.com: domain of b@send.good.test designates 192.0.2.9) smtp.mailfrom="b@send.good.test";',
    "       dmarc=pass (p=QUARANTINE) header.from=good.test",
    "DKIM-Signature: v=1; a=rsa-sha256; d=good.test; s=mp1;", " h=from:subject:list-unsubscribe:list-unsubscribe-post; b=x",
    "List-Unsubscribe: <https://good.test/u/1>,", " <mailto:u@good.test>", "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
    "From: Good <news@good.test>", "Message-ID: <1@good.test>", "", "body",
  ].join("\r\n");

  it("passes a compliant message", () => {
    const r = checkHeaders(good);
    assert.equal(r.summary, "Meets every requirement visible in headers");
    assert.equal(r.checks.find((c) => c.check === "Reverse DNS")!.detail, "The sending server has reverse DNS: mta1.good.test");
  });

  it("catches misalignment, a mailto-only unsubscribe and missing reverse DNS", () => {
    const bad = ["Received: from web01 ([203.0.113.9]) by mx.google.com with SMTP id x;",
      "Authentication-Results: mx.google.com; dkim=pass header.i=@esp.example; spf=pass smtp.mailfrom=b@bounce.esp.example; dmarc=fail header.from=shop.test",
      "List-Unsubscribe: <mailto:u@shop.test>", "From: deals@shop.test"].join("\n");
    const r = checkHeaders(bad);
    const status = Object.fromEntries(r.checks.map((c) => [c.check, c.status]));
    assert.equal(status["From domain alignment"], "fail");
    assert.equal(status["One-click unsubscribe"], "fail");
    assert.equal(status["Reverse DNS"], "fail");
    assert.equal(status["Message-ID"], "fail");
    assert.equal(status["TLS"], "warn");
  });

  it("handles two-level public suffixes when aligning", () => {
    assert.equal(orgDomain("mail.shop.co.uk"), "shop.co.uk");
    assert.equal(orgDomain("send.example.com"), "example.com");
  });

  it("rejects text that isn't headers", () => {
    assert.throws(() => checkHeaders("hello there, this is not an email"), /No From or Received/);
  });
});
