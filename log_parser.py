#!/usr/bin/env python3
"""Cloud Log Triage Tool.

Reads CloudTrail-style JSON events, applies detection rules mapped to
MITRE ATT&CK, scores each finding, and prints a prioritized triage list.
Runs on sample/simulated data by default; it is a learning lab, not a
production detection system.
"""
import argparse
import ipaddress
import json
import sys
from collections import Counter
from pathlib import Path

LOGGING_EVASION = {
    "DeleteTrail", "StopLogging", "UpdateTrail", "PutEventSelectors",
    "DeleteFlowLogs", "DeleteDetector",
}
IAM_CHANGES = {
    "CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy",
    "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "UpdateAssumeRolePolicy",
}
LEVELS = [(80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (0, "LOW")]
REPEATED_FAILURE_THRESHOLD = 3


def level(score):
    return next(name for floor, name in LEVELS if score >= floor)


def actor(event):
    ident = event.get("userIdentity") or {}
    return ident.get("userName") or ident.get("arn") or ident.get("type", "unknown")


def is_failure(event):
    login = (event.get("responseElements") or {}).get("ConsoleLogin")
    return bool(event.get("errorCode")) or login == "Failure"


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def is_external(ip):
    """True for a valid IP outside private ranges (sample TEST-NET IPs count as external)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:  # e.g. an AWS service name instead of an IP
        return False
    return not any(addr in net for net in INTERNAL_NETWORKS)


def score_event(event):
    """Return the highest-scoring finding for one event, or None."""
    name = event.get("eventName", "")
    ident_type = (event.get("userIdentity") or {}).get("type")
    mfa = (event.get("additionalEventData") or {}).get("MFAUsed")
    candidates = []

    if name in LOGGING_EVASION:
        candidates.append((90, "Logging tampering attempt", "T1562.008"))
    if ident_type == "Root":
        candidates.append((70, "Root account activity", "T1078.004"))
    if name == "ConsoleLogin" and not is_failure(event) and mfa == "No":
        candidates.append((60, "Console login without MFA", "T1078.004"))
    if name in IAM_CHANGES:
        candidates.append((55, "IAM identity or permission change", "T1098"))
    if is_failure(event):
        technique = "T1110" if name == "ConsoleLogin" else "-"
        candidates.append((20, "Failed or denied action", technique))

    if not candidates:
        return None
    score, rule, technique = max(candidates)
    ip = event.get("sourceIPAddress", "")
    if is_external(ip):
        score = min(100, score + 10)
    return {
        "score": score, "severity": level(score), "rule": rule,
        "technique": technique, "time": event.get("eventTime"),
        "actor": actor(event), "action": name, "sourceIp": ip,
    }


def correlate_failures(events):
    """Flag IPs with repeated failures (possible brute force / probing)."""
    counts = Counter(e.get("sourceIPAddress") for e in events if is_failure(e))
    findings = []
    for ip, count in counts.items():
        if ip and count >= REPEATED_FAILURE_THRESHOLD:
            score = 70 if is_external(ip) else 50
            findings.append({
                "score": score, "severity": level(score),
                "rule": f"{count} failed events from one IP", "technique": "T1110",
                "time": None, "actor": "multiple", "action": "multiple", "sourceIp": ip,
            })
    return findings


def load_events(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Could not read {path}: {exc}")
    return data.get("Records", []) if isinstance(data, dict) else data


def main():
    parser = argparse.ArgumentParser(description="Prioritize CloudTrail-style events.")
    parser.add_argument("input", nargs="?", default="sample_events.json")
    parser.add_argument("--min-score", type=int, default=0, help="hide findings below this score")
    parser.add_argument("--output", help="write findings to a JSON file")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = [f for f in map(score_event, events) if f] + correlate_failures(events)
    findings = sorted((f for f in findings if f["score"] >= args.min_score),
                      key=lambda f: f["score"], reverse=True)

    print(f"Processed {len(events)} events, {len(findings)} findings\n")
    for f in findings:
        print(f"[{f['severity']:<8}] {f['score']:>3}  {f['time'] or '-':<21} "
              f"{f['actor']:<10} {f['action']:<16} {f['sourceIp']:<15} "
              f"{f['rule']} ({f['technique']})")
    summary = Counter(f["severity"] for f in findings)
    print("\nSummary:", ", ".join(f"{name}={summary.get(name, 0)}" for _, name in LEVELS))

    if args.output:
        Path(args.output).write_text(json.dumps(findings, indent=2))
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
