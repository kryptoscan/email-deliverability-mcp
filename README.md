# email-deliverability-mcp

An MCP server that lets Claude (or any MCP client) diagnose email deliverability:

- **`check_domain`**: SPF (including the 10-DNS-lookup limit), DMARC policy and reporting, DKIM keys on common selectors, and MX records, with a ranked list of problems and the fix for each. It also names the email services a domain uses (Google Workspace, SendGrid, Amazon SES and others).
- **`check_sending_ip`**: reverse DNS (PTR) and whether it resolves back to the IP, plus listings on Spamhaus ZEN, Barracuda, SpamCop, PSBL, Mailspike and UCEPROTECT level 1.
- **`check_email_headers`**: paste a received message's headers and check them against Gmail's and Yahoo's sender requirements: SPF, DKIM, DMARC, From alignment, one-click unsubscribe (and whether DKIM covers it), TLS, reverse DNS and Message-ID.

Every tool is read-only: it reads public DNS or the text you give it. Nothing is sent anywhere else, and no account or API key is needed.

## Install

Requires Node.js 20 or later.

**Claude Code**

```sh
claude mcp add email-deliverability -- npx -y email-deliverability-mcp
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "email-deliverability": {
      "command": "npx",
      "args": ["-y", "email-deliverability-mcp"]
    }
  }
}
```

**Docker**

```sh
docker build -t email-deliverability-mcp .
docker run -i --rm email-deliverability-mcp
```

## Things to ask

- "Check example.com's email setup and tell me what to fix first."
- "Why might our emails from shop.example be going to spam?" (then paste a message's headers)
- "Is 192.0.2.25 on any blocklists? Does its reverse DNS look right?"
- "Does this email meet Gmail's bulk sender rules?"
- "Our SPF record fails sometimes. Are we over the lookup limit?"

## Configuration

| Variable | Default | What it does |
|---|---|---|
| `BLOCKLIST_DNS` | the system resolver | Comma-separated IPs of a recursive resolver **you run**, used for blocklist lookups. |
| `DNS_SERVERS` | the system resolver | Comma-separated resolver IPs for all other lookups. |

### Why `BLOCKLIST_DNS` matters

Spamhaus refuses queries that arrive through big public resolvers (8.8.8.8, 1.1.1.1 and the like) and answers `127.255.255.x` instead. Many blocklist checkers misread that as "listed". This server reports it as **refused**, meaning unknown, and says so. To get a real Spamhaus answer, point `BLOCKLIST_DNS` at a recursive resolver of your own, such as [unbound](https://nlnetlabs.nl/projects/unbound/) on `127.0.0.1`.

## How the checks work

- **SPF lookups** follow `include:` and `redirect=` recursively and count every `include`, `a`, `mx`, `ptr`, `exists` and `redirect` term, as RFC 7208 does. More than 10 is a permanent error at most receivers.
- **DKIM** keys sit under selectors that only the sender knows, so the server probes about 30 common ones. Pass your own with `dkim_selectors` (find it in the `s=` value of a message's `DKIM-Signature` header). Domains that answer every name (wildcard DNS) are detected and not reported as having keys.
- **Header checks** read the topmost `Authentication-Results` header, which is what the recipient's mailbox provider concluded, and the newest `Received` hop that names the sending server.
- **Alignment** compares organizational domains with a simple rule (the last two labels, or three for names like `example.co.uk`). It's not a full Public Suffix List lookup, so unusual suffixes may be misjudged.

## Development

```sh
npm install
npm test          # unit tests with a fake DNS resolver
npm run build     # compiles to dist/
```

## About

Built by [OwnMailServer](https://ownmailserver.com), which runs dedicated email sending for businesses that send 250,000 to 1,000,000 emails a month: your own server and IP, a Resend-style API and SMTP, managed warm-up and daily monitoring. OwnMailServer accounts also get a [Claude connector](https://ownmailserver.com/claude-email-connector) for their own sending data: delivery stats, bounces, complaints and message history.

The same checks are available as free web tools: the [email health checker](https://ownmailserver.com/tools/email-checker) and the [bulk sender checker](https://ownmailserver.com/tools/bulk-sender-checker).

## License

MIT
