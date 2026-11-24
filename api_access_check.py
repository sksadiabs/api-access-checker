#!/usr/bin/env python3
"""
api_access_check.py - a beginner-friendly API access control checker.

What it does (plain English):
  You describe a few "users" (roles) and the API endpoints they should or
  should not be able to reach. The script sends each request as each role
  and checks the answer:
    - Should be allowed, but got blocked?          -> noted (possible bug)
    - Should be blocked, but got data back?        -> FINDING (access control issue)
    - Should be blocked and was blocked?           -> PASS

Safety rules built in:
  * It only talks to hosts you list in "allowed_hosts" in your config.
  * It skips POST/PUT/PATCH/DELETE unless you set "allow_write_requests": true.
  * Use it only on systems you own or are authorized in writing to test
    (for example OWASP Juice Shop, crAPI, or your own lab).

Only the Python standard library is used, so there is nothing to install.

Usage:
  python3 api_access_check.py config.json
  python3 api_access_check.py config.json --dry-run     # show requests, send nothing
  python3 api_access_check.py config.json --report out.md
"""

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"[!] Could not read config file '{path}': {e}")

    for key in ("base_url", "allowed_hosts", "roles", "endpoints"):
        if key not in cfg:
            sys.exit(f"[!] Config is missing required key: '{key}'")
    return cfg


def check_host_allowed(base_url, allowed_hosts):
    host = urllib.parse.urlparse(base_url).hostname
    if host not in allowed_hosts:
        sys.exit(
            f"[!] Refusing to run: host '{host}' is not in allowed_hosts "
            f"{allowed_hosts}. Add it only if you are authorized to test it."
        )


def send_request(method, url, token, body, timeout):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(300).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return None, f"connection error: {e.reason}"


def verdict(expected, status):
    """Turn an expectation plus an HTTP status into a result label."""
    if status is None:
        return "ERROR"
    got_data = 200 <= status < 300
    blocked = status in (401, 403)

    if expected == "allow":
        if got_data:
            return "PASS"
        if blocked:
            return "UNEXPECTED BLOCK"      # maybe a bug, maybe a wrong expectation
        return "CHECK"                      # 404, 500, etc. - look at it by hand

    # expected == "deny"
    if got_data:
        return "FINDING"                    # the important one
    if blocked:
        return "PASS"
    return "CHECK"


def build_url(base_url, path, path_vars):
    filled = path.format_map(path_vars)
    return base_url.rstrip("/") + "/" + filled.lstrip("/")


def run_checks(cfg, dry_run=False, delay=0.2, timeout=10):
    base_url = cfg["base_url"]
    roles = cfg["roles"]              # e.g. {"anonymous": null, "user_a": "token"}
    allow_writes = cfg.get("allow_write_requests", False)
    results = []

    for ep in cfg["endpoints"]:
        method = ep.get("method", "GET").upper()
        name = ep.get("name", f"{method} {ep['path']}")
        body = ep.get("body")
        default_vars = ep.get("path_vars", {})
        overrides = ep.get("path_vars_by_role", {})
        expect_map = ep.get("expect", {})

        if method in WRITE_METHODS and not allow_writes:
            results.append({"endpoint": name, "role": "-", "status": "-",
                            "expected": "-", "result": "SKIPPED (write method; "
                            "set allow_write_requests to true to run)"})
            continue
        if method not in READ_METHODS | WRITE_METHODS:
            results.append({"endpoint": name, "role": "-", "status": "-",
                            "expected": "-", "result": f"SKIPPED (unknown method {method})"})
            continue

        for role, expected in expect_map.items():
            if role not in roles:
                results.append({"endpoint": name, "role": role, "status": "-",
                                "expected": expected,
                                "result": "SKIPPED (role not defined in config)"})
                continue

            path_vars = dict(default_vars)
            path_vars.update(overrides.get(role, {}))
            try:
                url = build_url(base_url, ep["path"], path_vars)
            except KeyError as e:
                results.append({"endpoint": name, "role": role, "status": "-",
                                "expected": expected,
                                "result": f"SKIPPED (missing path variable {e})"})
                continue

            if dry_run:
                print(f"[dry-run] {method} {url} as {role} (expect {expected})")
                continue

            status, snippet = send_request(method, url, roles[role], body, timeout)
            result = verdict(expected, status)
            results.append({"endpoint": name, "role": role, "status": status,
                            "expected": expected, "result": result,
                            "url": url, "snippet": snippet[:120]})
            print(f"  {result:<16} {method:<6} {url}  as {role:<10} -> {status}")
            time.sleep(delay)

    return results


def write_report(results, path, base_url):
    lines = [
        "# API Access Control Check",
        "",
        f"- Target: `{base_url}`",
        f"- Run at: {datetime.datetime.now().isoformat(timespec='seconds')}",
        "",
        "| Result | Endpoint | Role | Expected | HTTP status |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r['result']} | {r['endpoint']} | {r['role']} | "
                     f"{r['expected']} | {r['status']} |")

    findings = [r for r in results if r["result"] == "FINDING"]
    lines += ["", "## Findings (expected blocked, but data came back)", ""]
    if not findings:
        lines.append("None.")
    for r in findings:
        lines.append(f"- **{r['endpoint']}** reachable as `{r['role']}` "
                     f"(HTTP {r['status']}). URL: `{r.get('url', '')}`")
        lines.append(f"  - Response start: `{r.get('snippet', '')}`")

    lines += ["", "Labels: PASS = matched expectation. FINDING = access control issue to "
              "verify and report. UNEXPECTED BLOCK = check whether your expectation "
              "is right. CHECK = look at the response by hand."]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check API access control rules.")
    parser.add_argument("config", help="path to your JSON config file")
    parser.add_argument("--report", default="access_report.md", help="where to save the report")
    parser.add_argument("--dry-run", action="store_true", help="print requests without sending")
    parser.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    args = parser.parse_args()

    cfg = load_config(args.config)
    check_host_allowed(cfg["base_url"], cfg["allowed_hosts"])

    print(f"Checking {cfg['base_url']} ...")
    results = run_checks(cfg, dry_run=args.dry_run, delay=args.delay)
    if args.dry_run:
        return 0

    findings = write_report(results, args.report, cfg["base_url"])
    counts = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    print("\nSummary:", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    print(f"Report saved to {args.report}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
