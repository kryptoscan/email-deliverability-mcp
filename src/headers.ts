// Check a received email's headers against Gmail's and Yahoo's sender requirements:
// SPF, DKIM, DMARC, From alignment, one-click unsubscribe, TLS, reverse DNS and Message-ID.
// Reads what the receiving mailbox provider concluded (its Authentication-Results header).

const GUIDE = "https://ownmailserver.com/guides";

type Header = { name: string; value: string };

// Header block -> headers in order, folded lines joined. Stops at the first blank line.
export function parseHeaders(raw: string): Header[] {
  const text = raw.replace(/\r\n/g, "\n");
  const end = text.search(/\n\s*\n/);
  const block = end < 0 ? text : text.slice(0, end);
  return block.split(/\n(?![ \t])/).flatMap((line) => {
    const i = line.indexOf(":");
    return i > 0 ? [{ name: line.slice(0, i).trim().toLowerCase(), value: line.slice(i + 1).replace(/\n[ \t]+/g, " ").trim() }] : [];
  });
}

// Organizational domain, approximately: the last two labels, or three for names like example.co.uk.
export function orgDomain(d: string) {
  const p = d.toLowerCase().replace(/\.$/, "").split(".");
  if (p.length > 2 && p[p.length - 1].length === 2 && p[p.length - 2].length <= 3) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}
const aligned = (a: string, b: string) => !!a && !!b && orgDomain(a) === orgDomain(b);
const domainOf = (addr: string | undefined) => (/@([^>\s;]+)/.exec(addr ?? "")?.[1] ?? "").toLowerCase().replace(/[>.]+$/, "");

export type Check = { check: string; status: "pass" | "fail" | "warn"; detail: string; guide: string };

export function checkHeaders(raw: string) {
  const h = parseHeaders(raw);
  const all = (n: string) => h.filter((x) => x.name === n).map((x) => x.value);
  const one = (n: string) => all(n)[0];
  if (!one("from") && !one("received")) throw new Error("No From or Received headers found. Pass the full header block of a received message (Gmail: Show original).");

  const fromDomain = domainOf(one("from"));
  // The topmost Authentication-Results is the one the recipient's mailbox provider added.
  const ar = one("authentication-results") ?? "";
  const result = (method: string) => (new RegExp(`\\b${method}=(\\w+)`, "i").exec(ar)?.[1] ?? "").toLowerCase();
  const spf = result("spf"), dkim = result("dkim"), dmarc = result("dmarc");
  const mailFrom = (/smtp\.mailfrom=("?)([^\s;"]+)\1/i.exec(ar)?.[2] ?? one("return-path") ?? "").replace(/[<>]/g, "");
  const mailFromDomain = mailFrom.includes("@") ? domainOf(mailFrom) : mailFrom.toLowerCase();
  const dkimDomains = [...ar.matchAll(/dkim=pass[^;]*?header\.(?:d|i)=@?([^\s;]+)/gi)].map((m) => m[1].toLowerCase());
  const sigs = all("dkim-signature").map((v) => ({
    d: (/\bd=([^;\s]+)/.exec(v)?.[1] ?? "").toLowerCase(),
    h: (/\bh=([^;]+)/.exec(v)?.[1] ?? "").replace(/\s+/g, "").toLowerCase().split(":"),
  }));
  const lu = one("list-unsubscribe") ?? "";
  const lup = one("list-unsubscribe-post") ?? "";
  const received = all("received");
  // The newest hop that names a sending server (Gmail adds internal "by …" hops above it).
  const lastHop = received.find((r) => /^from\s/i.test(r)) ?? received[0] ?? "";
  const tls = /\b(ESMTPS|ESMTPSA|LMTPS|TLS1|TLSv1|version=TLS)/i.test(lastHop);
  // Gmail writes "from helo.name (ptr.name. [1.2.3.4])"; a name before the [ip] means reverse DNS exists.
  const ptr = /\(([a-z0-9.-]+\.[a-z]{2,})\.?\s*\[[0-9a-f.:]+\]\)/i.exec(lastHop)?.[1];
  const noPtr = /\(\s*\[[0-9a-f.:]+\]\)|unknown\s*\[/i.test(lastHop);

  const checks: Check[] = [];
  const add = (check: string, status: Check["status"], detail: string, guide: string) => checks.push({ check, status, detail, guide });

  if (!ar) {
    add("Authentication results", "warn", "No Authentication-Results header. Use the headers of a message as the recipient's mailbox received it.", `${GUIDE}/why-are-my-emails-going-to-spam`);
  } else {
    add("SPF", spf === "pass" ? "pass" : spf ? "fail" : "warn", spf ? `spf=${spf} for ${mailFromDomain || "the envelope sender"}` : "No SPF result reported", `${GUIDE}/how-to-set-up-spf-record`);
    add("DKIM", dkim === "pass" ? "pass" : dkim ? "fail" : "warn", dkim ? `dkim=${dkim}${dkimDomains.length ? ` (signed by ${dkimDomains.join(", ")})` : ""}` : "No DKIM result reported; every message should be DKIM-signed", `${GUIDE}/how-to-set-up-dkim`);
    add("DMARC", dmarc === "pass" ? "pass" : "fail", dmarc ? `dmarc=${dmarc}` : "No DMARC result: the From domain probably has no DMARC record, which Gmail and Yahoo require from bulk senders", `${GUIDE}/how-to-set-up-dmarc`);
    const anyAligned = (spf === "pass" && aligned(mailFromDomain, fromDomain)) || dkimDomains.some((d) => aligned(d, fromDomain));
    add("From domain alignment", anyAligned ? "pass" : "fail", anyAligned
      ? `The From domain (${fromDomain}) matches a passing SPF or DKIM domain`
      : `Neither the passing SPF domain (${mailFromDomain || "?"}) nor the DKIM domain (${dkimDomains.join(", ") || "none"}) matches the From domain (${fromDomain || "?"}); DMARC needs one to align`, `${GUIDE}/how-to-set-up-dmarc`);
  }

  if (!lu) {
    add("One-click unsubscribe", "warn", "No List-Unsubscribe header. Required for marketing and promotional mail to Gmail and Yahoo, not for receipts or password resets", `${GUIDE}/gmail-yahoo-bulk-sender-requirements`);
  } else {
    const https = /<https:\/\/[^>]+>/i.test(lu);
    const post = /List-Unsubscribe=One-Click/i.test(lup);
    const signed = sigs.some((s) => aligned(s.d, fromDomain) && s.h.includes("list-unsubscribe") && (!post || s.h.includes("list-unsubscribe-post")));
    add("One-click unsubscribe", https && post ? (signed ? "pass" : "warn") : "fail",
      !https ? "List-Unsubscribe has no https:// link; one-click unsubscribe (RFC 8058) needs an https URL that accepts POST"
        : !post ? "List-Unsubscribe-Post: List-Unsubscribe=One-Click is missing"
        : signed ? "Both List-Unsubscribe headers are present and covered by the From domain's DKIM signature"
        : "Both headers are present, but the From domain's DKIM signature doesn't appear to cover them (check its h= list)", `${GUIDE}/gmail-yahoo-bulk-sender-requirements`);
  }

  if (received.length) {
    add("TLS", tls ? "pass" : "warn", tls ? "The last hop into the mailbox used TLS" : "No sign of TLS on the last hop (look for ESMTPS or a TLS version in the Received header)", `${GUIDE}/gmail-yahoo-bulk-sender-requirements`);
    add("Reverse DNS", ptr ? "pass" : noPtr ? "fail" : "warn", ptr ? `The sending server has reverse DNS: ${ptr}` : noPtr ? "The sending IP has no reverse DNS; Gmail requires a PTR that resolves back to the IP" : "Couldn't read reverse DNS from the Received header", `${GUIDE}/reverse-dns-ptr-record-email`);
  }
  add("Message-ID", one("message-id") ? "pass" : "fail", one("message-id") ? "Present" : "Missing; every message needs a Message-ID header (RFC 5322)", `${GUIDE}/why-are-my-emails-going-to-spam`);

  const fails = checks.filter((c) => c.status === "fail").length;
  return {
    from_domain: fromDomain || null,
    summary: fails ? `${fails} requirement${fails > 1 ? "s" : ""} not met` : checks.some((c) => c.status === "warn") ? "No failures; some items to check" : "Meets every requirement visible in headers",
    checks,
    not_visible_in_headers: "Spam complaint rate: Gmail requires under 0.3% (aim for under 0.1%); see Google Postmaster Tools.",
  };
}
