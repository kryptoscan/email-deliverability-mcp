import { orEmpty, txt, type Dns } from "./dns.ts";

// SPF, DKIM, DMARC and MX for one domain, with what to fix and why.

export const COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3",
  "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "protonmail2", "fm1", "fm2", "sendgrid", "mailgun",
  "mg", "resend", "postmark", "pm", "amazonses", "sig1", "mp1", "everlytickey1", "cm"];

// Services recognised from SPF includes and MX hosts.
const SERVICES: [string, string][] = [
  ["sendgrid.net", "SendGrid"], ["mailgun.org", "Mailgun"], ["servers.mcsv.net", "Mailchimp"],
  ["mandrillapp.com", "Mailchimp Transactional"], ["amazonses.com", "Amazon SES"], ["mtasv.net", "Postmark"],
  ["sparkpostmail.com", "SparkPost"], ["sendinblue.com", "Brevo"], ["brevo.com", "Brevo"], ["mailjet.com", "Mailjet"],
  ["resend.com", "Resend"], ["constantcontact.com", "Constant Contact"], ["hubspotemail.net", "HubSpot"],
  ["_spf.salesforce.com", "Salesforce"], ["mail.zendesk.com", "Zendesk"], ["_spf.google.com", "Google Workspace"],
  ["google.com", "Google Workspace"], ["googlemail.com", "Google Workspace"], ["protection.outlook.com", "Microsoft 365"],
  ["zoho.com", "Zoho Mail"], ["zoho.eu", "Zoho Mail"], ["secureserver.net", "GoDaddy"], ["emailsrvr.com", "Rackspace"],
  ["ownmailserver.com", "OwnMailServer"],
];

export type Severity = "high" | "medium" | "low";
export type Issue = { severity: Severity; problem: string; fix: string };

const SPF_LIMIT = 10;

// RFC 7208 counts include, a, mx, ptr, exists and redirect toward the 10-lookup limit,
// including those inside included records.
export async function spfLookups(dns: Dns, record: string, seen: Set<string>, depth = 0): Promise<{ count: number; includes: string[] }> {
  const includes: string[] = [];
  if (depth > 10) return { count: 0, includes };
  let count = 0;
  for (const raw of record.trim().split(/\s+/).slice(1)) {
    const term = raw.replace(/^[+\-~?]/, "").toLowerCase();
    const nested = /^(include:|redirect=)(.+)$/.exec(term);
    if (nested) {
      count++;
      const target = nested[2];
      includes.push(target);
      if (seen.has(target)) continue;
      seen.add(target);
      const sub = (await txt(dns, target)).find((r) => /^v=spf1(\s|$)/i.test(r));
      if (sub) {
        const r = await spfLookups(dns, sub, seen, depth + 1);
        count += r.count;
        includes.push(...r.includes);
      }
    } else if (/^(a|mx|ptr|exists)([:/]|$)/.test(term)) {
      count++;
    }
  }
  return { count, includes };
}

async function hasDkimKey(dns: Dns, name: string) {
  return (await txt(dns, name)).some((r) => /(^|;)\s*p=[A-Za-z0-9+/=]{20,}/.test(r.replace(/\s+/g, "")));
}

export async function checkDomain(dns: Dns, rawDomain: string, extraSelectors: string[] = []) {
  const domain = rawDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split(/[/?#]/)[0].replace(/\.$/, "");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) throw new Error(`"${rawDomain}" is not a domain name`);
  const issues: Issue[] = [];
  const add = (severity: Severity, problem: string, fix: string) => issues.push({ severity, problem, fix });

  const [mxRecords, rootTxt, dmarcTxt] = await Promise.all([
    orEmpty(dns.resolveMx(domain)), txt(dns, domain), txt(dns, `_dmarc.${domain}`)]);
  const mx = mxRecords.sort((a, b) => a.priority - b.priority).map((m) => m.exchange.replace(/\.$/, "").toLowerCase());
  if (!mx.length) add("medium", "No MX records, so this domain can't receive email: replies and bounce reports are lost.",
    "Publish MX records for the domain (or a mail-receiving subdomain used as the return path).");

  // SPF
  const spfRecords = rootTxt.filter((r) => /^v=spf1(\s|$)/i.test(r));
  const spf = { records: spfRecords, status: "missing", dns_lookups: 0, includes: [] as string[] };
  if (spfRecords.length > 1) {
    spf.status = "multiple";
    add("high", "More than one SPF record: SPF fails (permerror) until they're merged.", "Merge them into a single v=spf1 record listing every service that sends for the domain.");
  } else if (spfRecords.length === 1) {
    const r = spfRecords[0];
    const lookups = await spfLookups(dns, r, new Set([domain]));
    spf.dns_lookups = lookups.count;
    spf.includes = lookups.includes;
    if (/(^|\s)\+?all(\s|$)/i.test(r)) {
      spf.status = "too permissive";
      add("high", "SPF ends with +all, which authorises every server on the internet to send as this domain.", "End the record with ~all or -all.");
    } else if (lookups.count > SPF_LIMIT) {
      spf.status = "too many lookups";
      add("high", `SPF needs ${lookups.count} DNS lookups; the limit is ${SPF_LIMIT}, so many receivers treat it as a failure (permerror).`,
        "Remove includes for services you no longer use, or replace includes with ip4:/ip6: ranges where the provider allows it.");
    } else if (/(^|\s)[-~]all(\s|$)/i.test(r)) {
      spf.status = "ok";
    } else {
      spf.status = "weak";
      add("medium", "SPF doesn't end with -all or ~all, so it doesn't tell receivers to reject other senders.", "End the record with ~all (or -all once you're sure every sender is listed).");
    }
  } else {
    add("high", "No SPF record: receivers can't tell which servers may send for this domain.", "Publish one TXT record starting v=spf1 listing your sending services, ending with ~all.");
  }

  // DMARC
  const dmarcRecords = dmarcTxt.filter((r) => /^v=dmarc1/i.test(r.trim()));
  const dmarc = { record: dmarcRecords[0] ?? null, status: "missing", policy: null as string | null, reporting: false };
  if (dmarcRecords.length > 1) {
    dmarc.status = "multiple";
    add("high", "More than one DMARC record: receivers ignore DMARC entirely.", `Keep a single TXT record at _dmarc.${domain}.`);
  } else if (dmarcRecords.length === 1) {
    const tags = Object.fromEntries(dmarcRecords[0].split(";").map((p) => p.split("=").map((s) => s.trim().toLowerCase()))
      .filter((p) => p.length === 2 && p[0]));
    dmarc.policy = tags.p ?? null;
    dmarc.reporting = "rua" in tags;
    if (dmarc.policy === "quarantine" || dmarc.policy === "reject") dmarc.status = "ok";
    else if (dmarc.policy === "none") {
      dmarc.status = "monitoring only";
      add("low", "DMARC is p=none: it meets Gmail's and Yahoo's requirement but doesn't stop spoofing.",
        "Once reports show all your legitimate mail passing, move to p=quarantine, then p=reject.");
    } else {
      dmarc.status = "invalid";
      add("high", "The DMARC record has no valid policy (p=none, quarantine or reject).", `Publish e.g. "v=DMARC1; p=none; rua=mailto:dmarc@${domain}".`);
    }
    if (!dmarc.reporting && dmarc.status !== "invalid") add("low", "DMARC has no rua= reporting address, so you never see who sends as this domain.", "Add rua=mailto:<an address you read> to the record.");
  } else {
    add("high", "No DMARC record. Gmail and Yahoo require one from bulk senders, and the domain is easy to spoof.",
      `Publish a TXT record at _dmarc.${domain}: "v=DMARC1; p=none; rua=mailto:dmarc@${domain}".`);
  }

  // DKIM: keys live under selectors only the sender knows, so probe common ones. A domain that
  // answers every name (wildcard) can't be probed meaningfully.
  const selectors = [...new Set([...extraSelectors.map((s) => s.trim().toLowerCase()).filter(Boolean), ...COMMON_DKIM_SELECTORS])];
  const wildcard = await hasDkimKey(dns, `zz-probe-7f3a._domainkey.${domain}`);
  const found = wildcard ? [] : (await Promise.all(selectors.map(async (s) => ((await hasDkimKey(dns, `${s}._domainkey.${domain}`)) ? s : null))))
    .filter((s): s is string => !!s);
  const dkim = { selectors_found: found, selectors_checked: wildcard ? 0 : selectors.length, wildcard };
  if (!wildcard && !found.length) add("medium", "No DKIM key found on common selectors. The sender may use a custom selector.",
    "Check the s= value in a sent message's DKIM-Signature header and pass it as dkim_selectors, or set up DKIM signing with your provider.");

  const services = [...new Set([...spf.includes, ...mx].flatMap((h) =>
    SERVICES.filter(([suffix]) => h === suffix || h.endsWith("." + suffix)).map(([, name]) => name)))];

  const high = issues.filter((i) => i.severity === "high").length;
  return {
    domain,
    summary: high ? `${high} serious problem${high > 1 ? "s" : ""} found` : issues.length ? "No serious problems; some improvements possible" : "No problems found",
    issues,
    spf, dkim, dmarc, mx,
    services_detected: services,
  };
}
