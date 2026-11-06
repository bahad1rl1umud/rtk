#!/usr/bin/env python3
"""RTK — Red Team Kit v3.0
Authorized security assessment workflow: passive OSINT, scoped recon,
findings management, CVSS v3.1 scoring, and HTML reporting.
Python 3.8+; standard library only.
"""
from __future__ import annotations
import argparse
import datetime as dt
import html
import ipaddress
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit
from urllib.request import Request, urlopen

VERSION = "3.0.0"
USER_AGENT = {"User-Agent": f"RTK/{VERSION} (authorized-security-assessment)"}
SESSION = {"eng": None}
STATUSES = ("Open", "In Progress", "Fixed", "Accepted Risk", "False Positive")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
COLORS = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m", "m": "\033[35m", "c": "\033[36m", "0": "\033[0m", "bold": "\033[1m"}

if os.name == "nt":
    os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BANNER = f"""{COLORS['r']}{COLORS['bold']}
██████╗ ████████╗██╗  ██╗
██╔══██╗╚══██╔══╝██║ ██╔╝
██████╔╝   ██║   █████╔╝
██╔══██╗   ██║   ██╔═██╗
██║  ██║   ██║   ██║  ██╗
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
{COLORS['0']}Red Team Kit v{VERSION} | OSINT → Recon → Findings → Report{COLORS['c']}
⚠ Yalnız yazılı icazəli testlər üçün{COLORS['0']}"""


def p(message, color="c"):
    print(f"{COLORS.get(color, '')}{message}{COLORS['0']}")


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def normalize_host(value):
    """Extract and normalize a hostname/IP from a host or URL; reject malformed input."""
    raw = str(value).strip()
    if not raw:
        raise ValueError("boş host")
    candidate = raw if "://" in raw else "//" + raw
    parsed = urlsplit(candidate)
    host = parsed.hostname
    if not host:
        raise ValueError(f"host müəyyən edilmədi: {value}")
    host = host.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError(f"yanlış hostname: {value}")
    return host


def scope_entry_matches(host, entry):
    """CIDR entries match IPs; domain entries match themselves and subdomains."""
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    try:
        scope_host = normalize_host(entry)
    except ValueError:
        return False
    try:
        ipaddress.ip_address(host)
        return host == scope_host
    except ValueError:
        return host == scope_host or host.endswith("." + scope_host)


def in_scope(target, scope):
    try:
        host = normalize_host(target)
    except ValueError:
        return False
    return any(scope_entry_matches(host, str(item).strip()) for item in scope if str(item).strip())


def engagement_path(name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) != 1 or str(path) in (".", ""):
        raise ValueError("engagement adı sadə qovluq adı olmalıdır; path traversal qəbul edilmir")
    return path


def load_meta(eng):
    path = engagement_path(eng) / "scope.json"
    if not path.is_file():
        raise FileNotFoundError(f"{path} tapılmadı; əvvəlcə init işlət")
    with path.open(encoding="utf-8") as f:
        meta = json.load(f)
    if not isinstance(meta.get("scope"), list) or not meta["scope"]:
        raise ValueError("scope.json daxilində scope boşdur və ya yanlışdır")
    return meta


def save_meta(eng, meta):
    path = engagement_path(eng) / "scope.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def guard(target, eng):
    meta = load_meta(eng)
    try:
        host = normalize_host(target)
    except ValueError as exc:
        p(f"[✗] Scope Guard: {exc}", "r")
        raise SystemExit(2)
    if not in_scope(host, meta["scope"]):
        p(f"[✗] SCOPE GUARD: '{target}' scope daxilində deyil. Əməliyyat dayandırıldı.", "r")
        p("    Scope: " + ", ".join(meta["scope"]), "y")
        raise SystemExit(2)
    p(f"[✓] Scope Guard: {host} təsdiqləndi", "g")
    return host


def need_eng(args):
    if not getattr(args, "eng", None):
        args.eng = SESSION["eng"]
    if not args.eng:
        p("[!] Engagement seçilməyib: -e <ad> yaz və ya shell-də 'use <ad>' işlət", "y")
        raise SystemExit(2)
    load_meta(args.eng)


def dispatch(args):
    if hasattr(args, "eng"):
        need_eng(args)
    args.func(args)


def cmd_init(args):
    path = engagement_path(args.name)
    raw_scope = [x.strip() for x in args.targets.split(",") if x.strip()]
    if not raw_scope:
        raise ValueError("ən azı bir scope hədəfi daxil et")
    normalized = []
    for item in raw_scope:
        try:
            # Keep CIDR notation intact; validate it before accepting.
            normalized.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            normalized.append(normalize_host(item))
    if len(set(normalized)) != len(normalized):
        normalized = list(dict.fromkeys(normalized))
    path.mkdir(parents=False, exist_ok=True)
    scope_file = path / "scope.json"
    if scope_file.exists() and not args.force:
        p(f"[!] '{args.name}' artıq mövcuddur (--force ilə yenilə)", "y")
        return
    meta = {"name": args.name, "client": args.client, "created": now_iso(), "scope": normalized,
            "findings": [], "schema_version": 2}
    save_meta(args.name, meta)
    SESSION["eng"] = args.name
    p(f"[+] Engagement: {path}/ | Müştəri: {args.client} | Scope: {', '.join(normalized)}", "g")


def fetch_json(url, timeout=25):
    req = Request(url, headers=USER_AGENT)
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def fetch_text(url, timeout=25):
    req = Request(url, headers=USER_AGENT)
    with urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def src_crtsh(domain):
    try:
        data = fetch_json(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", 35)
        names = set()
        for row in data:
            for item in row.get("name_value", "").splitlines():
                item = item.strip().lower().lstrip("*.")
                if item and "@" not in item:
                    try:
                        names.add(normalize_host(item))
                    except ValueError:
                        continue
        return sorted(names)
    except Exception as exc:
        return {"error": str(exc)}


def src_wayback(domain):
    try:
        data = fetch_json(f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}/*&output=json&collapse=urlkey&limit=500", 45)
        return sorted({row[2] for row in data[1:] if len(row) > 2})
    except Exception as exc:
        return {"error": str(exc)}


def src_hackertarget(domain):
    try:
        text = fetch_text(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", 25)
        return sorted({line.split(",", 1)[0].strip() for line in text.splitlines() if "," in line})
    except Exception as exc:
        return {"error": str(exc)}


def src_github(domain, token=None):
    result = {"repos": [], "users": [], "code": [], "errors": []}
    headers = dict(USER_AGENT)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    def gh(url):
        with urlopen(Request(url, headers=headers), timeout=25) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    for kind, key, formatter in (
        ("repositories", "repos", lambda x: f"{x.get('full_name','')} — {(x.get('description') or '')[:100]}"),
        ("users", "users", lambda x: f"{x.get('login','')} ({x.get('html_url','')})")):
        try:
            payload = gh(f"https://api.github.com/search/{kind}?q={quote(domain)}&per_page=10")
            result[key] = [formatter(x) for x in payload.get("items", [])]
        except Exception as exc:
            result["errors"].append(f"{kind}: {exc}")
    if token:
        try:
            payload = gh(f"https://api.github.com/search/code?q={quote(domain)}&per_page=10")
            result["code"] = [f"{x.get('repository', {}).get('full_name','')} / {x.get('path','')}" for x in payload.get("items", [])]
        except Exception as exc:
            result["errors"].append(f"code: {exc}")
    return result


def src_linkedin(domain):
    q = quote_plus
    return {"employees_dorks": [f"https://www.google.com/search?q=site:linkedin.com/in+*{q(domain)}",
                                f"https://www.bing.com/search?q=site%3Alinkedin.com%2Fin+{q(domain)}"],
            "emails_dorks": [f"https://www.google.com/search?q=%22{q('@' + domain)}%22+-site:{q(domain)}",
                             f"https://hunter.io/search/{quote(domain)}"]}


def cmd_osint(args):
    target = guard(args.target, args.eng)
    p(f"[*] Passiv OSINT: {target}", "m")
    data = {"domain": target, "date": now_iso()}
    sources = [("crtsh_subdomains", "crt.sh", lambda: src_crtsh(target)),
               ("wayback_urls", "Wayback", lambda: src_wayback(target)),
               ("hackertarget_hosts", "HackerTarget", lambda: src_hackertarget(target)),
               ("github", "GitHub", lambda: src_github(target, args.token)),
               ("linkedin", "LinkedIn dorks", lambda: src_linkedin(target))]
    for key, label, fn in sources:
        p(f"    [+] {label} ...", "b")
        data[key] = fn()
        if isinstance(data[key], dict) and "error" in data[key]:
            p(f"        Mənbə xətası: {data[key]['error']}", "y")
    out = engagement_path(args.eng) / f"osint_{target}.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    p(f"[+] OSINT nəticələri: {out}", "g")
    urls = data.get("wayback_urls", [])
    if isinstance(urls, list):
        interesting = [u for u in urls if any(k in u.lower() for k in (".git", ".env", "admin", "backup", "config", "dump", "sql", "log"))]
        if interesting:
            p(f"[i] Yoxlanmalı köhnə URL-lər ({len(interesting)}):", "y")
            for item in interesting[:15]: print("    " + item)
    for link in data.get("linkedin", {}).get("employees_dorks", []):
        print("    " + link)


def run_tool(argv, logfile, timeout=900):
    """Run an installed recon utility without a shell; preserve stdout/stderr and exit code."""
    exe = argv[0]
    if not shutil.which(exe):
        p(f"[!] '{exe}' quraşdırılmayıb — bu mərhələ keçildi", "y")
        return ""
    p("[+] $ " + shlex.join(argv), "b")
    try:
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, check=False)
        with Path(logfile).open("a", encoding="utf-8") as log:
            log.write(f"\n### {now_iso()} | exit={result.returncode}\n")
            log.write(result.stdout or "")
            if result.stderr:
                log.write("\n[stderr]\n" + result.stderr)
        if result.returncode:
            p(f"[!] {exe} exit code: {result.returncode}; loga bax", "y")
        return result.stdout or ""
    except subprocess.TimeoutExpired:
        p(f"[!] {exe}: vaxt limiti bitdi", "y")
        with Path(logfile).open("a", encoding="utf-8") as log:
            log.write(f"\n### {now_iso()} | TIMEOUT after {timeout}s\n")
        return ""
    except OSError as exc:
        p(f"[!] {exe} başladılmadı: {exc}", "y")
        return ""


def cmd_recon(args):
    eng = engagement_path(args.eng)
    target = guard(args.target, args.eng)
    log_dir = eng / "logs"
    log_dir.mkdir(exist_ok=True)
    p(f"[*] Recon başlayır: {target}", "m")
    sub_output = run_tool(["subfinder", "-d", target, "-all", "-silent"], log_dir / f"sub_{target}.log", args.timeout)
    subs = {target}
    subs.update(x.strip().lower() for x in sub_output.splitlines() if x.strip())
    osint_file = eng / f"osint_{target}.json"
    if osint_file.exists():
        try:
            osint = json.loads(osint_file.read_text(encoding="utf-8"))
            for item in osint.get("crtsh_subdomains", []):
                if isinstance(item, str): subs.add(item)
        except (OSError, json.JSONDecodeError) as exc:
            p(f"[!] OSINT faylı oxunmadı: {exc}", "y")
    safe = set()
    for item in subs:
        try:
            host = normalize_host(item)
            if in_scope(host, load_meta(args.eng)["scope"]): safe.add(host)
        except ValueError:
            continue
    removed = len(subs) - len(safe)
    if removed: p(f"[!] {removed} scope-xarici/yanlış host kənarlaşdırıldı", "y")
    sub_file = eng / f"all_subs_{target}.txt"
    sub_file.write_text("\n".join(sorted(safe)) + ("\n" if safe else ""), encoding="utf-8")
    p(f"[+] Scope daxilində host: {len(safe)} → {sub_file}", "g")
    if safe:
        run_tool(["httpx", "-l", str(sub_file), "-title", "-tech-detect", "-status-code", "-silent", "-rl", str(args.rate_limit)], log_dir / f"httpx_{target}.log", args.timeout)
        run_tool(["nuclei", "-l", str(sub_file), "-t", "exposures/", "-severity", "medium,high,critical", "-rl", str(args.rate_limit), "-silent"], log_dir / f"nuclei_{target}.log", args.timeout)
        if args.content_scan:
            # Content discovery is opt-in and runs only on the explicitly scoped base host.
            wordlist = args.wordlist
            run_tool(["feroxbuster", "-u", f"https://{target}", "-w", wordlist, "-x", "php,asp,jsp,json,html", "--depth", "2", "--rate-limit", str(args.rate_limit), "--quiet"], log_dir / f"content_{target}.log", args.timeout)
    else:
        p("[!] Scope daxilində host tapılmadı; aktiv alətlər başladılmadı", "y")
    p(f"[*] Recon tamamlandı. Log qovluğu: {log_dir}/", "g")


# CVSS v3.1 Base Score calculator
CVSS_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .20},
          "AC": {"L": .77, "H": .44},
          "PR": {"U": {"N": .85, "L": .62, "H": .27}, "C": {"N": .85, "L": .68, "H": .50}},
          "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def cvss_roundup(value):
    # CVSS v3.1 Roundup: nearest tenth, always rounding upward.
    return math.ceil((value - 1e-10) * 10) / 10


def cvss(metrics):
    m = {str(k).upper(): str(v).upper() for k, v in metrics.items()}
    scope = m.get("S", "U")
    try:
        av, ac, ui = CVSS_W["AV"][m["AV"]], CVSS_W["AC"][m["AC"]], CVSS_W["UI"][m["UI"]]
        pr = CVSS_W["PR"][scope][m["PR"]]
        c, i, a = (CVSS_W["CIA"][m[k]] for k in "CIA")
    except KeyError as exc:
        raise ValueError(f"yanlış CVSS metric/dəyəri: {exc}")
    iss = 1 - (1-c) * (1-i) * (1-a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - .029) - 3.25 * ((iss - .02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)
    return cvss_roundup(base)


def severity(score):
    return "NONE" if score == 0 else "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def cmd_add_finding(args):
    meta = load_meta(args.eng)
    # Validate the finding host against scope; URL paths are allowed, off-scope hosts are not.
    host = guard(args.target, args.eng)
    metrics = {"av": args.av, "ac": args.ac, "pr": args.pr, "ui": args.ui, "s": args.s,
               "c": args.c, "i": args.i, "a": args.a}
    score = cvss(metrics)
    finding = {"id": uuid.uuid4().hex[:8], "title": args.title.strip(), "target": args.target,
               "host": host, "cvss": {k: v.upper() for k, v in metrics.items()}, "score": score,
               "severity": severity(score), "status": "Open", "created": now_iso(),
               "poc": args.poc, "impact": args.impact, "fix": args.fix, "evidence": args.evidence}
    meta.setdefault("findings", []).append(finding)
    save_meta(args.eng, meta)
    p(f"[+] Finding [{finding['id']}]: {finding['title']} → {finding['severity']} ({score})", "g")


def cmd_findings(args):
    meta = load_meta(args.eng)
    findings = meta.get("findings", [])
    if args.id:
        findings = [f for f in findings if f.get("id") == args.id]
    if not findings:
        p("[i] Finding yoxdur / uyğun ID tapılmadı", "y"); return
    for f in findings:
        print(f"[{f.get('id','legacy')}] {f.get('severity','?'):8} {f.get('score','?'):>4} | {f.get('status','Open'):15} | {f.get('title','Untitled')} | {f.get('target','')}")


def cmd_finding_update(args):
    meta = load_meta(args.eng)
    for finding in meta.get("findings", []):
        if finding.get("id") == args.id:
            finding["status"] = args.status
            finding["updated"] = now_iso()
            save_meta(args.eng, meta)
            p(f"[+] {args.id} status → {args.status}", "g")
            return
    p(f"[!] Finding ID tapılmadı: {args.id}", "y")


def severity_to_sarif_level(sev):
    """RTK severity → SARIF level çevrilməsi."""
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "NONE": "none"}.get(sev, "warning")


def cmd_export_sarif(args):
    """SARIF 2.1.0 formatında export — GitHub/VS Code uyğun."""
    meta = load_meta(args.eng)
    findings = meta.get("findings", [])
    sarif_results = []
    for f in findings:
        sarif_results.append({
            "ruleId": f"RTK-{f.get('severity', 'NONE')}",
            "level": severity_to_sarif_level(f.get("severity", "NONE")),
            "message": {
                "text": f"{f.get('title', 'Untitled')} — {f.get('impact', 'no impact recorded')}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("target", "")},
                }
            }],
            "properties": {
                "cvss_score": f.get("score", 0),
                "severity": f.get("severity", "NONE"),
                "status": f.get("status", "Open"),
                "id": f.get("id", ""),
                "fix": f.get("fix", ""),
                "poc": f.get("poc", ""),
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RTK",
                    "version": VERSION,
                    "informationUri": "https://github.com/USER/rtk",
                    "rules": [
                        {"id": f"RTK-{s}", "name": s,
                         "shortDescription": {"text": f"{s} severity finding"}}
                        for s in SEVERITIES
                    ],
                }
            },
            "results": sarif_results,
        }],
    }
    out = engagement_path(args.eng) / "report.sarif"
    out.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    p(f"[+] SARIF export: {out} ({len(sarif_results)} finding)", "g")


def cmd_report(args):
    meta = load_meta(args.eng)
    findings = sorted(meta.get("findings", []), key=lambda f: float(f.get("score", 0)), reverse=True)
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    rows = []
    for index, finding in enumerate(findings, 1):
        sev = finding.get("severity", "NONE")
        color = {"CRITICAL":"#c0392b", "HIGH":"#e67e22", "MEDIUM":"#d4ac0d", "LOW":"#27ae60", "NONE":"#95a5a6"}.get(sev, "#95a5a6")
        detail = "<br>".join([f"<b>{label}:</b> {html.escape(str(finding.get(key) or '—'))}" for label, key in (("Impact","impact"),("Fix","fix"),("PoC","poc"),("Evidence","evidence"))])
        rows.append(f"<tr class='main' onclick=\"this.nextElementSibling.classList.toggle('show')\"><td>{index}</td><td>{html.escape(str(finding.get('title','')))}</td><td><span class='sev' style='background:{color}'>{html.escape(sev)}</span></td><td>{finding.get('score',0)}</td><td>{html.escape(str(finding.get('status','Open')))}</td><td><code>{html.escape(str(finding.get('target','')))}</code></td></tr><tr class='detail'><td colspan='6'>{detail}</td></tr>")
    cards = "".join(f"<div class='card'><b>{counts[s]}</b><small>{s}</small></div>" for s in SEVERITIES)
    page = f"""<!doctype html><html lang='az'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RTK {VERSION} Report</title><style>
body{{font-family:system-ui,sans-serif;margin:32px;background:#0d1117;color:#c9d1d9}}h1{{color:#ff5555}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}}.card{{background:#161b22;padding:14px 22px;border-radius:9px;min-width:90px}}.card b{{display:block;font-size:25px}}.card small{{color:#8b949e}}table{{border-collapse:collapse;width:100%;margin-top:18px}}td,th{{border:1px solid #30363d;padding:10px;text-align:left}}th{{background:#21262d}}.main{{cursor:pointer}}.main:hover{{background:#1c2128}}.sev{{padding:3px 9px;border-radius:5px;color:#111;font-weight:700}}.detail{{display:none}}.detail.show{{display:table-row}}.detail td{{background:#161b22;line-height:1.8}}code{{color:#79c0ff}}footer{{color:#8b949e;margin-top:28px}}</style></head><body>
<h1>RTK — {html.escape(str(meta.get('client','')))} Pentest Report</h1><p>Engagement: <b>{html.escape(str(meta.get('name','')))}</b> | Generated: {html.escape(now_iso())} | Scope: {html.escape(', '.join(meta.get('scope',[])))}</p>
<div class='cards'>{cards}</div><table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Target</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<footer>RTK v{VERSION} · CVSS v3.1 Base Score · Yalnız yazılı icazəli təhlükəsizlik qiymətləndirmələri üçün</footer></body></html>"""
    out = engagement_path(args.eng) / "report.html"
    out.write_text(page, encoding="utf-8")
    p(f"[+] HTML hesabat yaradıldı: {out}", "g")


def build_parser():
    parser = argparse.ArgumentParser(prog="rtk", description=f"Red Team Kit v{VERSION}")
    parser.add_argument("--banner", action="store_true", help="əmrdən əvvəl banner göstər")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="engagement və scope yarat")
    init.add_argument("name"); init.add_argument("-c", "--client", required=True); init.add_argument("-t", "--targets", required=True)
    init.add_argument("--force", action="store_true"); init.set_defaults(func=cmd_init)
    osint = sub.add_parser("osint", help="passiv OSINT: crt.sh, Wayback, HackerTarget, GitHub, LinkedIn")
    osint.add_argument("-e", "--eng", default=None); osint.add_argument("-t", "--target", required=True); osint.add_argument("--token", help="GitHub token; code search üçün")
    osint.set_defaults(func=cmd_osint)
    recon = sub.add_parser("recon", help="scope daxilində aktiv recon")
    recon.add_argument("-e", "--eng", default=None); recon.add_argument("-t", "--target", required=True)
    recon.add_argument("--rate-limit", type=int, default=5, help="httpx/nuclei/feroxbuster üçün sorğu limiti (default: 5)")
    recon.add_argument("--timeout", type=int, default=900, help="hər alət üçün timeout saniyəsi")
    recon.add_argument("--content-scan", action="store_true", help="feroxbuster content discovery-ni ayrıca aktiv et")
    recon.add_argument("--wordlist", default="/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt")
    recon.set_defaults(func=cmd_recon)
    finding = sub.add_parser("finding", help="yeni finding əlavə et")
    finding.add_argument("-e", "--eng", default=None); finding.add_argument("--title", required=True); finding.add_argument("--target", required=True)
    finding.add_argument("--poc", default=""); finding.add_argument("--impact", default=""); finding.add_argument("--fix", default=""); finding.add_argument("--evidence", default="")
    finding.add_argument("--av", choices=["N","A","L","P"], default="N"); finding.add_argument("--ac", choices=["L","H"], default="L")
    finding.add_argument("--pr", choices=["N","L","H"], default="N"); finding.add_argument("--ui", choices=["N","R"], default="N")
    finding.add_argument("--s", choices=["U","C"], default="U", help="CVSS Scope: U|C")
    for metric in ("c", "i", "a"):
        finding.add_argument(f"--{metric}", choices=["H","L","N"], default="L")
    finding.set_defaults(func=cmd_add_finding)
    listing = sub.add_parser("findings", help="finding-ləri siyahıla")
    listing.add_argument("-e", "--eng", default=None); listing.add_argument("--id", help="yalnız konkret finding ID")
    listing.set_defaults(func=cmd_findings)
    update = sub.add_parser("finding-update", help="finding statusunu dəyiş")
    update.add_argument("-e", "--eng", default=None); update.add_argument("--id", required=True); update.add_argument("--status", choices=STATUSES, required=True)
    update.set_defaults(func=cmd_finding_update)
    report = sub.add_parser("report", help="HTML hesabat yarat")
    report.add_argument("-e", "--eng", default=None); report.set_defaults(func=cmd_report)    
    sarif = sub.add_parser("export-sarif", help="SARIF 2.1.0 formatında export (GitHub/VS Code)")
    sarif.add_argument("-e", "--eng", default=None)
    sarif.set_defaults(func=cmd_export_sarif)
    return parser


def shell(parser):
    print(BANNER)
    p("Əmrlər: init, use, osint, recon, finding, findings, finding-update, report | help, clear, exit", "c")
    try:
        import readline  # noqa: F401
    except ImportError:
        pass
    while True:
        prompt = f"\n{COLORS['r']}{COLORS['bold']}rtk{COLORS['0']}"
        if SESSION["eng"]: prompt += f"({COLORS['c']}{SESSION['eng']}{COLORS['0']})"
        try:
            line = input(prompt + " > ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not line: continue
        if line.lower() in ("exit", "quit", "q"): break
        if line.lower() in ("help", "?"): parser.print_help(); continue
        if line.lower() in ("clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear"); continue
        try:
            argv = shlex.split(line)
            if argv[0] == "use":
                if len(argv) == 1: p(f"[*] Aktiv engagement: {SESSION['eng'] or '—'}")
                else:
                    load_meta(argv[1]); SESSION["eng"] = argv[1]; p(f"[+] Aktiv engagement: {argv[1]}", "g")
                continue
            args = parser.parse_args(argv)
            dispatch(args)
        except SystemExit:
            continue
        except Exception as exc:
            p(f"[!] Xəta: {exc}", "y")


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        shell(parser); return
    args = parser.parse_args()
    if args.banner: print(BANNER)
    try:
        dispatch(args)
    except KeyboardInterrupt:
        p("[!] Əməliyyat dayandırıldı", "y")
    except Exception as exc:
        p(f"[!] Xəta: {exc}", "r")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
