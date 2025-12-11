#!/usr/bin/env python3
"""
Email domain health checker.

Usage:
    python3 audit_domains.py domains.txt

domains.txt: one domain per line, "#" for comments.
"""

import sys
from typing import List, Tuple, Dict, Optional

import dns.resolver
import dns.reversename
from prettytable import PrettyTable


DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]

# Популярные DKIM-селекторы (best effort, не истина в последней инстанции)
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail", "smtp",
    "mx", "k1", "mailo", "s1", "s2", "dkim",
]


def load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def check_mx(domain: str) -> Tuple[str, List[str]]:
    """
    Проверка MX-записей.
    Возвращает:
        status: "OK", "missing", "error"
        hosts: список MX-хостов (строки)
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return "missing", []
    except Exception:
        return "error", []

    hosts: List[str] = []
    for rdata in answers:
        host = str(rdata.exchange).rstrip(".")
        hosts.append(host)

    if not hosts:
        return "missing", []

    return "OK", hosts


def parse_spf(domain: str) -> Tuple[str, Optional[str], List[str]]:
    """
    Возвращает (spf_status, raw_spf, ip4_list)

    spf_status:
        - "missing"
        - "multiple"
        - "weak"
        - "OK"
    raw_spf:
        текст SPF (первая найденная запись) или None
    ip4_list:
        список ip4: (только одиночные адреса, без диапазовов)
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return "missing", None, []
    except Exception:
        return "missing", None, []

    spf_records: List[str] = []
    for rdata in answers:
        try:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except AttributeError:
            txt = rdata.to_text().strip('"')
        if txt.lower().startswith("v=spf1"):
            spf_records.append(txt)

    if not spf_records:
        return "missing", None, []

    raw_spf = spf_records[0]

    if len(spf_records) > 1:
        status = "multiple"
    else:
        status = "OK"

    parts = raw_spf.split()
    ip4_list: List[str] = []
    weak = False

    for part in parts:
        pl = part.lower()

        if pl.startswith("ip4:"):
            value = part[4:]
            if "/" in value:
                # Диапазоны можно учитывать отдельно, но для RBL берём только одиночные IP
                continue
            ip4_list.append(value)

        # "слабый" SPF по all
        if pl.endswith("all"):
            if not (pl.startswith("-all") or pl.startswith("~all")):
                weak = True

    if status == "OK" and weak:
        status = "weak"

    return status, raw_spf, ip4_list


def parse_dmarc(domain: str) -> Tuple[str, Optional[str], bool]:
    """
    Возвращает (dmarc_status, raw_dmarc, rua_present)

    dmarc_status:
        - "missing"
        - "p=none"
        - "p=quarantine"
        - "p=reject"
        - "unknown"
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return "missing", None, False
    except Exception:
        return "missing", None, False

    dmarc_records: List[str] = []
    for rdata in answers:
        try:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except AttributeError:
            txt = rdata.to_text().strip('"')
        if txt.lower().startswith("v=dmarc1"):
            dmarc_records.append(txt)

    if not dmarc_records:
        return "missing", None, False

    raw = dmarc_records[0]
    tags: Dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()

    p = tags.get("p", "").lower()
    if p == "none":
        status = "p=none"
    elif p == "quarantine":
        status = "p=quarantine"
    elif p == "reject":
        status = "p=reject"
    else:
        status = "unknown"

    rua_present = "rua" in tags and bool(tags["rua"])
    return status, raw, rua_present


def check_dkim(domain: str) -> Tuple[str, List[str]]:
    """
    Перебираем набор популярных селекторов и ищем DKIM.
    Возвращает (dkim_status, selectors_found):

    dkim_status:
        - "OK"       — нашли хотя бы один DKIM-запись
        - "unknown"  — ничего не нашли (селектор неизвестен, это не ошибка)
    """
    found_selectors: List[str] = []

    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

        for rdata in answers:
            try:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            except AttributeError:
                txt = rdata.to_text().strip('"')
            if "v=DKIM1" in txt:
                found_selectors.append(selector)
                break

    if found_selectors:
        return "OK", found_selectors
    else:
        return "unknown", []


def check_dnsbl(ip: str) -> List[str]:
    """
    Проверка одного IP по всем DNSBL.
    Возвращает список DNSBL, где IP найден.
    """
    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_in: List[str] = []

    for dnsbl in DNSBL_LISTS:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            dns.resolver.resolve(query, "A")
            listed_in.append(dnsbl)
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass

    return listed_in


def check_ptr(ip: str) -> Tuple[bool, List[str]]:
    """
    Проверка PTR (reverse DNS).
    Возвращает (has_ptr, hostnames)
    """
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR")
    except Exception:
        return False, []

    hosts: List[str] = []
    for rdata in answers:
        hosts.append(str(rdata.target).rstrip("."))
    return bool(hosts), hosts


def build_overall_status(
    spf_status: str,
    dmarc_status: str,
    dkim_status: str,
    mx_status: str,
    ip_count: int,
    ip_listed_count: int,
    ptr_all_ok: bool,
    ptr_some_missing: bool,
) -> Tuple[str, str]:
    """
    Определяем общий статус домена и короткий комментарий.

    overall (без иконок): "OK" / "WARN" / "FAIL"
    """
    fail_reasons: List[str] = []
    warn_reasons: List[str] = []

    # SPF / DMARC
    if spf_status == "missing":
        fail_reasons.append("SPF missing")
    elif spf_status in ("weak", "multiple"):
        warn_reasons.append(f"SPF {spf_status}")

    if dmarc_status == "missing":
        fail_reasons.append("DMARC missing")
    elif dmarc_status == "p=none":
        warn_reasons.append("DMARC p=none")

    # DKIM: "unknown" не считаем проблемой, это просто «не знаем селектор»
    # Если позже появится реальный статус "missing", можно будет сюда добавить warn/fail.

    # MX
    if mx_status == "missing":
        warn_reasons.append("MX missing")
    elif mx_status == "error":
        warn_reasons.append("MX error")

    # RBL
    if ip_count > 0 and ip_listed_count > 0:
        fail_reasons.append(f"{ip_listed_count} IP in RBL")

    # PTR
    if ip_count > 0:
        if not ptr_all_ok and not ptr_some_missing:
            warn_reasons.append("PTR missing for all IPs")
        elif ptr_some_missing:
            warn_reasons.append("PTR missing for some IPs")

    if fail_reasons:
        overall = "FAIL"
        comment = "; ".join(fail_reasons[:3])
    elif warn_reasons:
        overall = "WARN"
        comment = "; ".join(warn_reasons[:3])
    else:
        overall = "OK"
        if ip_count == 0:
            comment = "SPF/DMARC OK, no ip4 in SPF"
        else:
            comment = "All key records present, IPs clean"

    return overall, comment


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} domains.txt")
        sys.exit(1)

    domains_file = sys.argv[1]
    domains = load_domains(domains_file)
    if not domains:
        print("[ERROR] No domains found in file")
        sys.exit(1)

    table = PrettyTable()
    table.field_names = [
        "Domain",
        "MX",
        "SPF",
        "DMARC",
        "DKIM",
        "IP from SPF",
        "RBL by IP",
        "Bad IPs",
        "PTR",
        "Overall",
        "Comment",
    ]

    # чтобы Bad IPs не разъезжались
    table.max_width["Bad IPs"] = 35
    table.align["Bad IPs"] = "l"

    for domain in domains:
        # MX
        mx_status, mx_hosts = check_mx(domain)
        if mx_status == "OK":
            mx_display = f"OK ({len(mx_hosts)})"
        else:
            mx_display = mx_status

        # SPF
        spf_status, spf_raw, ip4_list = parse_spf(domain)

        # DMARC
        dmarc_status, dmarc_raw, rua_present = parse_dmarc(domain)

        # DKIM
        dkim_status, dkim_selectors = check_dkim(domain)
        dkim_display = dkim_status  # "OK" или "unknown"

        ip_count = len(ip4_list)


        # DNSBL / PTR per IP
        ip_listed_count = 0
        ptr_ok_count = 0
        ptr_total = 0
        bad_ip_details: List[str] = []

        for ip in ip4_list:
            listed_in = check_dnsbl(ip)
            if listed_in:
                ip_listed_count += 1
                # полные имена RBL, как вернул check_dnsbl
                bad_ip_details.append(f"{ip}({','.join(listed_in)})")

            has_ptr, hosts = check_ptr(ip)
            ptr_total += 1
            if has_ptr:
                ptr_ok_count += 1


        # RBL summary
        if ip_count == 0:
            rbl_summary = "n/a"
        else:
            if ip_listed_count == 0:
                rbl_summary = f"✅ all {ip_count} clean"
            else:
                rbl_summary = f"❌ {ip_listed_count}/{ip_count} in RBL"

        # Bad IPs summary
        if bad_ip_details:
            bad_ips_summary = ", ".join(bad_ip_details)
        else:
            bad_ips_summary = "—"

        # PTR summary
        if ip_count == 0:
            ptr_summary = "n/a"
            ptr_all_ok = False
            ptr_some_missing = False
        else:
            if ptr_ok_count == ptr_total and ptr_total > 0:
                ptr_summary = "✅ all"
                ptr_all_ok = True
                ptr_some_missing = False
            elif ptr_ok_count == 0:
                ptr_summary = "❌ none"
                ptr_all_ok = False
                ptr_some_missing = False
            else:
                ptr_summary = f"⚠ {ptr_total - ptr_ok_count} missing"
                ptr_all_ok = False
                ptr_some_missing = True

        overall, comment = build_overall_status(
            spf_status=spf_status,
            dmarc_status=dmarc_status,
            dkim_status=dkim_status,
            mx_status=mx_status,
            ip_count=ip_count,
            ip_listed_count=ip_listed_count,
            ptr_all_ok=ptr_all_ok,
            ptr_some_missing=ptr_some_missing,
        )

        # добавляем иконки в Overall
        if overall == "OK":
            overall_display = "✅ OK"
        elif overall == "FAIL":
            overall_display = "❌ FAIL"
        else:
            overall_display = "⚠ WARN"

        spf_display = spf_status
        dmarc_display = dmarc_status

        table.add_row([
            domain,
            mx_display,
            spf_display,
            dmarc_display,
            dkim_display,
            str(ip_count),
            rbl_summary,
            bad_ips_summary,
            ptr_summary,
            overall_display,
            comment,
        ])

    print(table)


if __name__ == "__main__":
    main()
