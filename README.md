# Email Domain Health Audit

A small CLI tool to quickly assess the technical health of email domains:

- SPF / DMARC / DKIM
- MX records
- IP addresses from SPF
- RBL / DNSBL checks for IP reputation
- PTR (reverse DNS)
- One-line summary per domain: what’s fine and what’s broken

The main goal: get a clear, compact report that answers **“where is it OK, and where are the problems?”** for deliverability and reputation.

---

## Features

For each domain, the tool checks:

### MX

- Checks if MX records exist.
- Shows the number of MX hosts found:
  - `OK (N)` — N MX hosts
  - `missing` — no MX records
  - `error` — DNS error while querying MX

---

### SPF

- Looks for `v=spf1` TXT records.
- Evaluates basic SPF status:
  - `OK` — SPF exists and doesn’t look obviously weak.
  - `weak` — SPF uses weak policy (`all`, `+all`, `?all`, etc.).
  - `multiple` — more than one SPF record (formally invalid).
  - `missing` — no SPF record.
- Extracts **explicit `ip4:` addresses** (only single IPs, CIDR ranges are skipped).

---

### DMARC

- Looks for `_dmarc.<domain>` TXT records with `v=DMARC1`.
- Extracts policy `p=`:
  - `p=none` — monitoring only.
  - `p=quarantine`.
  - `p=reject`.
  - `missing` — no DMARC record.
  - `unknown` — DMARC exists but `p=` could not be interpreted.
- Detects whether `rua=` is present (aggregate report address) — used internally for evaluation, not shown in the main table.

---

### DKIM

- Attempts to find DKIM TXT records by trying a list of **common selectors**, for example:
  - `default._domainkey.<domain>`
  - `selector1._domainkey.<domain>`
  - `mail._domainkey.<domain>`
- DKIM status:
  - `OK` — at least one `v=DKIM1` record found using these selectors.
  - `unknown` — nothing found for the tried selectors.

> Important: `unknown` does **not** mean DKIM is absent.  
> It means “no DKIM was found among the guessed selectors”. Real selectors may be different.

---

### IPs from SPF

- Collects IP addresses from `ip4:` mechanisms in SPF.
- Only single IPs are used (`ip4:1.2.3.4`).
- CIDR ranges like `ip4:1.2.3.0/24` are skipped and not expanded.

---

### RBL / DNSBL checks (IP reputation)

For each IP from SPF, the script checks the following DNSBLs:

- `zen.spamhaus.org`
- `bl.spamcop.net`
- `dnsbl.sorbs.net`

In the report you get:

- How many IPs are listed vs total (`❌ X/N in RBL`).
- Exact IPs and which lists they appear in, e.g.:

  ```text
  51.23.25.22(zen.spamhaus.org)
  ```
---

### PTR (reverse DNS)

For each IP from SPF:

Performs a PTR lookup (reverse DNS).

Summarizes result:

✅ all — all IPs have PTR.

❌ none — no IP has PTR.

⚠ N missing — some IPs have no PTR.

n/a — no IPs to check (no ip4: in SPF).

Missing or partial PTR is often a reputation and deliverability red flag.


---

### Overall Status

The tool computes an overall status per domain using SPF, DMARC, MX, RBL and PTR:

✅ OK

⚠ WARN

❌ FAIL

The logic (simplified):

FAIL if:

SPF is missing, or

DMARC is missing, or

any IP from SPF is listed in RBL.

WARN if:

SPF is weak or multiple, or

DMARC is p=none, or

MX is missing/error, or

PTR is missing for all or some IPs.

OK if:

No FAIL reasons, no WARN reasons,

and DNS / reputation look healthy.

The Comment column contains a short explanation like:

  ```text
SPF missing; DMARC missing

3 IP in RBL

DMARC p=none; PTR missing for some IPs
```
