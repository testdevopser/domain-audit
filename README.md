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
  41.83.20.21(zen.spamhaus.org), 37.28.51.24(zen.spamhaus.org)
  ```

---

### PTR (reverse DNS)

For each IP from SPF:

- Performs a PTR lookup (reverse DNS).
- Summarizes result:
  - `✅ all` — all IPs have PTR.
  - `❌ none` — no IP has PTR.
  - `⚠ N missing` — some IPs have no PTR.
  - `n/a` — no IPs to check (no `ip4:` in SPF).

Missing or partial PTR is often a reputation and deliverability red flag.

---

### Overall Status

The tool computes an overall status per domain using SPF, DMARC, MX, RBL and PTR:

- `✅ OK`
- `⚠ WARN`
- `❌ FAIL`

The logic (simplified):

- **FAIL** if:
  - SPF is `missing`, or
  - DMARC is `missing`, or
  - any IP from SPF is listed in RBL.
- **WARN** if:
  - SPF is `weak` or `multiple`, or
  - DMARC is `p=none`, or
  - MX is `missing`/`error`, or
  - PTR is missing for all or some IPs.
- **OK** if:
  - No FAIL reasons, no WARN reasons,
  - and DNS / reputation look healthy.

The **Comment** column contains a short explanation like:

- `SPF missing; DMARC missing`
- `3 IP in RBL`
- `DMARC p=none; PTR missing for some IPs`

---

## Requirements

- Python 3.8+
- Python packages:

```bash
pip install dnspython prettytable
```

The script needs DNS access (UDP/53) to perform lookups.

---



## Usage

1. Create a file with domains, for example `domains.txt`:

```text
domain.com
second.com
another.com
else.com
# lines starting with # are comments
```

2. Run the script:

```bash
python3 audit_domains.py domains.txt
```

3. You’ll get a summary table, something like:

```text
+-------------+---------+---------+-----------+---------+------------+---------------------+-----------------------------------------------+-----------+-----------+-----------------------------+
| Domain      | MX      | SPF     | DMARC     | DKIM    | IP from SPF| RBL by IP           | Bad IPs                                       | PTR       | Overall   | Comment                     |
+-------------+---------+---------+-----------+---------+------------+---------------------+-----------------------------------------------+-----------+-----------+-----------------------------+
| somedd.com  | OK (3)  | OK      | p=reject  | unknown | 3          | ❌ 3/3 in RBL       | 71.93.250.26(zen.spamhaus.org), ...          | ⚠ 1 missing| ❌ FAIL  | 3 IP in RBL; PTR missing... |
| mommmin.com | OK (2)  | OK      | p=none    | OK      | 2          | ✅ all 2 clean      | —                                             | ✅ all    | ⚠ WARN    | DMARC p=none                |
| anorher.n...| missing | missing | missing   | unknown | 0          | n/a                 | —                                             | n/a       | ❌ FAIL   | SPF missing; DMARC missing  |
+-------------+---------+---------+-----------+---------+------------+---------------------+-----------------------------------------------+-----------+-----------+-----------------------------+
```

---

## Columns Explained

### Domain

The domain you passed in `domains.txt`.

---

### MX

- `OK (N)` — MX records exist, N hosts found.
- `missing` — no MX records found.
- `error` — DNS error during MX lookup.

---

### SPF

- `OK` — a single SPF record found, policy is not obviously weak.
- `weak` — uses `all` or `+all`/`?all` (too permissive).
- `multiple` — multiple SPF records (invalid configuration).
- `missing` — no SPF (`v=spf1`) record found.

---

### DMARC

- `p=none` — monitoring only.
- `p=quarantine` — suspicious mail should go to spam.
- `p=reject` — suspicious mail should be rejected.
- `unknown` — DMARC exists but `p=` couldn’t be parsed.
- `missing` — no DMARC record.

---

### DKIM

- `OK` — at least one `v=DKIM1` record found for a set of commonly-used selectors.
- `unknown` — no DKIM found among tried selectors.

> For a domain like `gmail.com`, DKIM will typically show as `unknown`, because Google uses custom selectors (e.g. `20230601._domainkey.gmail.com`). Without real emails and headers, selectors cannot be reliably discovered.

---

### IP from SPF

Number of IPs extracted from `ip4:` mechanisms in SPF (single IPs only, no range expansion).

---

### RBL by IP

- `n/a` — no IP found in SPF.
- `✅ all N clean` — none of the N IPs are listed in the checked RBLs.
- `❌ X/N in RBL` — X out of N IPs are listed in at least one RBL.

---

### Bad IPs

Detailed list of “bad” IPs and where they are listed, for example:

```text
21.13.250.24(zen.spamhaus.org,bl.spamcop.net)
27.28.81.21(zen.spamhaus.org)
```

If no IPs are listed, you’ll see `—`.

The width of this column is limited in the table and long content will wrap onto multiple lines, so the table doesn’t explode horizontally.

---

### PTR

- `n/a` — no IPs to check.
- `✅ all` — every IP from SPF has PTR.
- `❌ none` — no IP from SPF has PTR.
- `⚠ N missing` — some IPs have PTR, N do not.

---

### Overall

- `✅ OK`  
  All critical records present, no IPs in RBL, no major DNS issues.
- `⚠ WARN`  
  Non-critical but important issues, such as:
  - weak or multiple SPF;
  - DMARC in `p=none` mode;
  - missing/errored MX;
  - partial or missing PTR for IPs.
- `❌ FAIL`  
  Serious issues affecting deliverability / reputation:
  - missing SPF and/or DMARC;
  - any IP listed in RBL.

The **Comment** column briefly explains why the domain ended up with WARN/FAIL.

---

## Configuration

You can customize a few things inside the script:

### RBL Lists

In the header of the script:

```python
DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]
```

Add or remove DNSBLs depending on what you use in your environment.

---

### DKIM selectors (best-effort guessing)

```python
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail", "smtp",
    "mx", "k1", "mail1", "s1", "s2", "dkim",
]
```

For your own domains, it can be useful to add the selectors you actually use (`dkim1`, `outbound`, etc.).

---

## Limitations

- **SPF parsing**
  - The script **does not** expand `include:`, `a`, `mx`, or CIDR ranges like `ip4:x.x.x.x/yy`.
  - Only plain `ip4:1.2.3.4` entries are used for IP and RBL checks.
- **DKIM detection**
  - Without reading real email headers (and extracting `s=` from `DKIM-Signature`), selectors cannot be reliably discovered.
  - Status `unknown` means: “No DKIM found among guessed selectors” — **not** “DKIM is missing”.
- **RBL usage**
  - Making large numbers of queries to DNSBLs may violate their usage policies.
  - Don’t run massive audits with thousands of IPs at high frequency.
- **Network/DNS**
  - The script depends entirely on DNS resolution.  
  - Network issues or DNS misconfiguration will show up as `missing`/`error`/`unknown`.

---

## Possible Extensions

Ideas for future improvements:

- Export results as **CSV / JSON**.
- Extra detailed view per IP (PTR, full RBL listing in a separate table).
- Optional expansion of SPF `include:` / `a` / `mx`.
- Import DKIM selectors from real email headers (log/feed).
- CLI flags to filter:
  - show only `FAIL` or `WARN` domains;
  - show only domains with RBL hits.
- Integration with Telegram / email alerts and cron.

---

## License

Add your preferred license here (MIT, Apache-2.0, GPL-3.0, etc.).
