#!/usr/bin/env python3
"""
Email domain health checker.

Usage:
    python3 audit_domains.py domains.txt [--csv report.csv] [--debug]

domains.txt: one domain per line, "#" for comments.
"""

import argparse
import csv
import sys
import time
from typing import List, Tuple, Dict, Optional, Set, Callable
import ipaddress

import dns.exception
import dns.resolver
import dns.reversename
from prettytable import PrettyTable


DNSBL_LISTS = [
#    "zen.spamhaus.org",
#    "bl.spamcop.net",
#    "dnsbl.sorbs.net",
#    "dnsbl.uceprotect.net",
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "cbl.abuseat.org",
            "b.barracudacentral.org",
            "dnsbl.sorbs.net",
            "psbl.surriel.com",
            "bl.mailspike.net",
            "dnsbl.dronebl.org",
            "spam.dnsbl.sorbs.net",
            "dnsbl-1.uceprotect.net",
            "db.wpbl.info",
            "rbl.spamlab.com",
            "dnsbl-2.uceprotect.net",

]

# Популярные DKIM-селекторы (best effort, не истина в последней инстанции)
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail", "smtp",
    "mx", "k1", "mail1", "s1", "s2", "dkim", "email", "selector",
]

DNS_TIMEOUT = 3.0
DNS_LIFETIME = 5.0
DNS_RETRIES = 2
RBL_DELAY_SECONDS = 0.1
SPF_MAX_IPS_PER_NETWORK = 32  # ограничиваем раскрытие крупных сетей

ResolveResult = Tuple[str, Optional[dns.resolver.Answer], Optional[Exception]]
DNS_CACHE: Dict[Tuple[str, str], ResolveResult] = {}
RBL_CACHE: Dict[str, List[str]] = {}


def load_domains(path: str) -> List[str]:
    seen: Set[str] = set()
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = line
            if domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
    return domains


def make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    return resolver


def resolve_dns(
    resolver: dns.resolver.Resolver,
    name: str,
    rdtype: str,
    tries: int,
    debug: bool,
) -> ResolveResult:
    key = (name.lower(), rdtype.upper())
    if key in DNS_CACHE:
        return DNS_CACHE[key]

    last_exc: Optional[Exception] = None
    for attempt in range(tries):
        try:
            answers = resolver.resolve(name, rdtype)
            result: ResolveResult = ("ok", answers, None)
            DNS_CACHE[key] = result
            return result
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            result = ("missing", None, None)
            DNS_CACHE[key] = result
            return result
        except dns.exception.Timeout as exc:
            last_exc = exc
        except Exception as exc:
            last_exc = exc

    if debug and last_exc:
        print(f"[DEBUG] DNS {name} {rdtype} failed after {tries} tries: {last_exc}", file=sys.stderr)
    result = ("error", None, last_exc)
    DNS_CACHE[key] = result
    return result


def check_mx(domain: str, resolver: dns.resolver.Resolver, debug: bool) -> Tuple[str, List[str]]:
    """
    Проверка MX-записей.
    Возвращает:
        status: "OK", "missing", "error"
        hosts: список MX-хостов (строки)
    """
    status, answers, _ = resolve_dns(resolver, domain, "MX", DNS_RETRIES, debug)
    if status == "error":
        return "error", []
    if answers is None:
        return "missing", []

    hosts: List[str] = []
    for rdata in answers:
        host = str(rdata.exchange).rstrip(".")
        hosts.append(host)

    if not hosts:
        return "missing", []

    return "OK", hosts


def _extract_spf_records(domain: str, resolver: dns.resolver.Resolver, debug: bool) -> List[str]:
    """
    Возвращает все TXT-записи SPF (v=spf1 ...) для домена или пустой список.
    """
    status, answers, _ = resolve_dns(resolver, domain, "TXT", DNS_RETRIES, debug)
    if status == "error" or answers is None:
        return []

    spf_records: List[str] = []
    for rdata in answers:
        try:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except AttributeError:
            txt = rdata.to_text().strip('"')
        if txt.lower().startswith("v=spf1"):
            spf_records.append(txt)
    return spf_records


def _collect_spf_ip4_from_record(
    record: str,
    resolver: dns.resolver.Resolver,
    debug: bool,
    visited_domains: Set[str],
    seen_ips: Set[str],
    progress_log: Optional[Callable[[str], None]] = None,
) -> List[str]:
    """
    Разбирает одну SPF-запись и рекурсивно раскрывает include/redirect.
    Возвращает список IPv4 (без дублей, в порядке обнаружения).
    """
    collected: List[str] = []
    parts = record.split()

    for part in parts:
        clean_part = part.lstrip("+-~?")
        clean_lower = clean_part.lower()

        if clean_lower.startswith("ip4:"):
            value = clean_part[4:]
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                if debug:
                    print(f"[DEBUG] Invalid ip4 value in SPF '{value}': {exc}", file=sys.stderr)
                continue

            if network.version != 4:
                continue

            if network.prefixlen == 32:
                ip_text = str(network.network_address)
                if ip_text not in seen_ips:
                    seen_ips.add(ip_text)
                    if progress_log:
                        progress_log(f"SPF: add ip4 {ip_text}")
                    collected.append(ip_text)
            else:
                if network.num_addresses > SPF_MAX_IPS_PER_NETWORK:
                    if debug:
                        print(
                            f"[DEBUG] Skip ip4 network {network} (too many addresses: {network.num_addresses})",
                            file=sys.stderr,
                        )
                    continue
                for ip_addr in network:
                    ip_text = str(ip_addr)
                    if ip_text not in seen_ips:
                        seen_ips.add(ip_text)
                        if progress_log:
                            progress_log(f"SPF: add ip4 {ip_text}")
                        collected.append(ip_text)

        elif clean_lower.startswith("include:"):
            include_domain = clean_part[8:]
            if include_domain and include_domain not in visited_domains:
                if progress_log:
                    progress_log(f"SPF: include -> {include_domain}")
                collected.extend(
                    collect_spf_ip4(
                        include_domain,
                        resolver,
                        debug,
                        visited_domains,
                        seen_ips,
                        progress_log=progress_log,
                    )
                )
        elif clean_lower.startswith("redirect=") or clean_lower.startswith("redirect:"):
            if "=" in clean_part:
                redirect_domain = clean_part.split("=", 1)[1]
            else:
                redirect_domain = clean_part.split(":", 1)[1] if ":" in clean_part else ""
            if redirect_domain and redirect_domain not in visited_domains:
                if progress_log:
                    progress_log(f"SPF: redirect -> {redirect_domain}")
                collected.extend(
                    collect_spf_ip4(
                        redirect_domain,
                        resolver,
                        debug,
                        visited_domains,
                        seen_ips,
                        progress_log=progress_log,
                    )
                )

    return collected


def collect_spf_ip4(
    domain: str,
    resolver: dns.resolver.Resolver,
    debug: bool,
    visited_domains: Optional[Set[str]] = None,
    seen_ips: Optional[Set[str]] = None,
    progress_log: Optional[Callable[[str], None]] = None,
) -> List[str]:
    """
    Собирает все IPv4 из SPF (включая include/redirect), ограничивая большие сети.
    """
    visited = visited_domains if visited_domains is not None else set()
    ips_seen = seen_ips if seen_ips is not None else set()

    if domain in visited:
        return []
    visited.add(domain)

    spf_records = _extract_spf_records(domain, resolver, debug)
    if not spf_records:
        return []

    if progress_log:
        progress_log(f"SPF: processing {domain}")

    collected: List[str] = []
    for record in spf_records:
        collected.extend(
            _collect_spf_ip4_from_record(
                record,
                resolver,
                debug,
                visited,
                ips_seen,
                progress_log=progress_log,
            )
        )

    return collected


def parse_spf(domain: str, resolver: dns.resolver.Resolver, debug: bool) -> Tuple[str, Optional[str], List[str]]:
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
        список ip4: (только одиночные адреса после раскрытия include/redirect)
    """
    spf_records = _extract_spf_records(domain, resolver, debug)

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

def parse_dmarc(
    domain: str,
    resolver: dns.resolver.Resolver,
    debug: bool,
) -> Tuple[str, Optional[str], bool, Optional[str]]:
    """
    Возвращает (dmarc_status, raw_dmarc, rua_present, inherited_from)

    dmarc_status:
        - "missing"
        - "p=none"
        - "p=quarantine"
        - "p=reject"
        - "unknown"
        - "multiple"   # несколько DMARC-записей с разными p=
    raw_dmarc:
        - все DMARC-записи, склеенные через " | "
    rua_present:
        - True, если хотя бы в одной записи есть rua=
    inherited_from:
        - домен, у которого нашли DMARC, если для сабдомена он отсутствует
    """
    def _lookup_dmarc(target_domain: str) -> Tuple[str, Optional[str], bool]:
        dmarc_domain = f"_dmarc.{target_domain}"
        status_local, answers, _ = resolve_dns(resolver, dmarc_domain, "TXT", DNS_RETRIES, debug)
        if status_local == "error":
            return "missing", None, False
        if answers is None:
            return "missing", None, False

        dmarc_records: List[str] = []
        for rdata in answers:
            try:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            except AttributeError:
                txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=DMARC1".lower()):
                dmarc_records.append(txt)

        if not dmarc_records:
            return "missing", None, False

        policies: List[str] = []
        rua_present_any = False

        for raw in dmarc_records:
            tags: Dict[str, str] = {}
            for part in raw.split(";"):
                part = part.strip()
                if not part or "=" not in part:
                    continue
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

            p = tags.get("p", "").lower()
            if p:
                policies.append(p)

            if "rua" in tags and tags["rua"]:
                rua_present_any = True

        unique_policies = set(policies)

        if not unique_policies:
            status_resolved = "unknown"
        elif len(unique_policies) == 1:
            p = next(iter(unique_policies))
            if p == "none":
                status_resolved = "p=none"
            elif p == "quarantine":
                status_resolved = "p=quarantine"
            elif p == "reject":
                status_resolved = "p=reject"
            else:
                status_resolved = "unknown"
        else:
            status_resolved = "multiple"

        raw_combined_local = " | ".join(dmarc_records)
        return status_resolved, raw_combined_local, rua_present_any

    status, raw_combined, rua_present = _lookup_dmarc(domain)
    inherited_from: Optional[str] = None

    # DMARC отсутствует у сабдомена — пытаемся найти у родительского домена
    if status == "missing":
        labels = domain.split(".")
        if len(labels) > 2:
            for i in range(1, len(labels) - 1):
                parent_domain = ".".join(labels[i:])
                parent_status, parent_raw, parent_rua = _lookup_dmarc(parent_domain)
                if parent_status != "missing":
                    status = parent_status
                    raw_combined = parent_raw
                    rua_present = parent_rua
                    inherited_from = parent_domain
                    break

    return status, raw_combined, rua_present, inherited_from


def check_dkim(
    domain: str,
    resolver: dns.resolver.Resolver,
    debug: bool,
    selectors: List[str],
) -> Tuple[str, List[str]]:
    """
    Перебираем набор популярных селекторов и ищем DKIM.
    Возвращает (dkim_status, selectors_found):

    dkim_status:
        - "OK"       — нашли хотя бы один DKIM-запись
        - "unknown"  — ничего не нашли (селектор неизвестен, это не ошибка)
    """
    found_selectors: List[str] = []

    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        status, answers, _ = resolve_dns(resolver, name, "TXT", DNS_RETRIES, debug)
        if status != "ok":
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


def check_dnsbl(
    ip: str,
    resolver: dns.resolver.Resolver,
    debug: bool,
    rbl_delay: float,
) -> List[str]:
    """
    Проверка одного IP по всем DNSBL.
    Возвращает список DNSBL, где IP найден.
    """
    if ip in RBL_CACHE:
        return RBL_CACHE[ip]

    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_in: List[str] = []

    for dnsbl in DNSBL_LISTS:
        query = f"{reversed_ip}.{dnsbl}"
        status, answers, _ = resolve_dns(resolver, query, "A", DNS_RETRIES, debug)
        if status == "ok" and answers:
            listed_in.append(dnsbl)
        elif status == "error" and debug:
            print(f"[DEBUG] RBL lookup failed for {ip} at {dnsbl}", file=sys.stderr)
        if rbl_delay > 0:
            time.sleep(rbl_delay)

    RBL_CACHE[ip] = listed_in
    return listed_in


def check_ptr(ip: str, resolver: dns.resolver.Resolver, debug: bool) -> Tuple[bool, List[str]]:
    """
    Проверка PTR (reverse DNS).
    Возвращает (has_ptr, hostnames)
    """
    try:
        rev = dns.reversename.from_address(ip)
    except Exception as exc:
        if debug:
            print(f"[DEBUG] Failed to build reverse name for {ip}: {exc}", file=sys.stderr)
        return False, []

    status, answers, _ = resolve_dns(resolver, str(rev), "PTR", DNS_RETRIES, debug)
    if status != "ok" or answers is None:
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
    dmarc_inherited_from: Optional[str],
) -> Tuple[str, str]:
    """
    Определяем общий статус домена и короткий комментарий.

    overall (без иконок): "GOOD" / "FINE" / "WARN" / "FAIL"
    """
    fail_reasons: List[str] = []
    warn_reasons: List[str] = []
    fine_reasons: List[str] = []

    # SPF / DMARC
    if spf_status == "missing":
        fail_reasons.append("SPF missing")
    elif spf_status in ("weak", "multiple"):
        warn_reasons.append(f"SPF {spf_status}")

    if dmarc_inherited_from:
        fine_reasons.append(f"DMARC inherited ({dmarc_status}) from {dmarc_inherited_from}")
    elif dmarc_status == "missing":
        fail_reasons.append("DMARC missing")
    elif dmarc_status == "p=none":
        fine_reasons.append("DMARC p=none")
    elif dmarc_status == "multiple":
        # несколько разных DMARC-записей — это ошибка конфигурации
        fail_reasons.append("DMARC multiple records")
    # "p=quarantine", "p=reject" и "unknown" тут считаем норм/терпимо


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
    elif fine_reasons:
        overall = "FINE"
        comment = "; ".join(fine_reasons[:3])
    else:
        overall = "GOOD"
        if ip_count == 0:
            comment = "SPF/DMARC OK, no ip4 in SPF"
        else:
            comment = "All key records present, IPs clean"

    return overall, comment


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit email domain DNS health.")
    parser.add_argument("domains_file", help="Path to file with domains (one per line)")
    parser.add_argument("--csv", dest="csv_path", help="Optional path to export CSV report")
    parser.add_argument("--debug", action="store_true", help="Print DNS errors to stderr")
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print per-domain progress while processing",
    )
    parser.add_argument(
        "--no-rbl",
        action="store_true",
        help="Skip DNSBL checks (faster, no load on DNSBL providers)",
    )
    parser.add_argument(
        "--dkim-selector",
        action="append",
        dest="dkim_selectors",
        help="Extra DKIM selectors to check (without '._domainkey'), can be repeated",
    )
    parser.add_argument(
        "--rbl-delay",
        type=float,
        default=RBL_DELAY_SECONDS,
        help=f"Delay between RBL queries in seconds (default: {RBL_DELAY_SECONDS})",
    )
    args = parser.parse_args()

    domains = load_domains(args.domains_file)
    if not domains:
        print("[ERROR] No domains found in file")
        sys.exit(1)

    def progress_log(message: str) -> None:
        """Emit progress messages when --progress is enabled."""
        if args.progress:
            print(f"[progress] {message}", file=sys.stderr, flush=True)

    # Пользовательские селекторы + дефолтные (без дублей, с сохранением порядка)
    dkim_selectors_to_try: List[str] = list(
        dict.fromkeys((args.dkim_selectors or []) + COMMON_DKIM_SELECTORS)
    )

    resolver = make_resolver()

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
    table.max_width["Comment"] = 35
    table.align["Bad IPs"] = "l"

    csv_rows: List[List[str]] = []

    for domain in domains:
        progress_log(f"{domain}: start")
        # MX
        mx_status, mx_hosts = check_mx(domain, resolver, args.debug)
        if mx_status == "OK":
            mx_display = f"OK ({len(mx_hosts)})"
        else:
            mx_display = mx_status

        # SPF
        spf_status, _, _ = parse_spf(domain, resolver, args.debug)
        # собираем все ip4 из SPF с учётом include/redirect
        spf_ip4 = collect_spf_ip4(domain, resolver, args.debug, progress_log=progress_log)
        progress_log(f"{domain}: SPF {spf_status}, ip4 found: {len(spf_ip4)}")

        # DMARC
        dmarc_status, dmarc_raw, rua_present, dmarc_inherited_from = parse_dmarc(domain, resolver, args.debug)

        # DKIM
        dkim_status, dkim_selectors = check_dkim(
            domain,
            resolver,
            args.debug,
            selectors=dkim_selectors_to_try,
        )
        if dkim_status == "OK" and dkim_selectors:
            dkim_display = f"OK ({','.join(dkim_selectors)})"
        else:
            dkim_display = dkim_status  # "OK" или "unknown"

        ip_count = len(spf_ip4)


        # DNSBL / PTR per IP
        ip_listed_count = 0
        ptr_ok_count = 0
        ptr_total = 0
        bad_ip_details: List[str] = []

        if args.no_rbl and spf_ip4:
            progress_log(f"{domain}: RBL checks skipped (--no-rbl)")

        for ip in spf_ip4:
            if not args.no_rbl:
                progress_log(f"{domain}: RBL check {ip}")
                listed_in = check_dnsbl(ip, resolver, args.debug, args.rbl_delay)
                if listed_in:
                    ip_listed_count += 1
                    # полные имена RBL, как вернул check_dnsbl
                    bad_ip_details.append(f"{ip}({','.join(listed_in)})")
            progress_log(f"{domain}: PTR check {ip}")
            has_ptr, hosts = check_ptr(ip, resolver, args.debug)
            ptr_total += 1
            if has_ptr:
                ptr_ok_count += 1


        # RBL summary
        if args.no_rbl:
            rbl_summary = "skipped"
        else:
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
            dmarc_inherited_from=dmarc_inherited_from,
        )

        # добавляем иконки в Overall
        if overall == "GOOD":
            overall_display = "✅ GOOD"
        elif overall == "FINE":
            overall_display = "ℹ FINE"
        elif overall == "FAIL":
            overall_display = "❌ FAIL"
        else:
            overall_display = "⚠ WARN"

        spf_display = spf_status
        if dmarc_inherited_from:
            dmarc_display = f"{dmarc_status} (from {dmarc_inherited_from})"
        else:
            dmarc_display = dmarc_status

        row = [
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
        ]
        table.add_row(row)
        csv_rows.append(row)

        progress_log(f"{domain} processed ({overall_display})")

    print(table)

    if args.csv_path:
        with open(args.csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(table.field_names)
            writer.writerows(csv_rows)
        print(f"[INFO] CSV report saved to {args.csv_path}")


if __name__ == "__main__":
    main()
