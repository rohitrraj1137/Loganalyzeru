#!/usr/bin/env python3
"""
SSH Auth Log Analyzer
Flags IP addresses with repeated failed SSH logins (possible brute-force).

Usage:
    python ssh_log_analyzer.py /var/log/auth.log
    python ssh_log_analyzer.py /var/log/auth.log --threshold 3
    python ssh_log_analyzer.py sample_auth.log --threshold 5 --top 10

Note: reading /var/log/auth.log usually needs sudo. On RHEL/CentOS/Fedora
the file is /var/log/secure instead.
"""

import argparse
import re
import sys
from collections import defaultdict

# Matches lines such as:
#   Sep 20 10:15:32 host sshd[1234]: Failed password for root from 1.2.3.4 port 5555 ssh2
#   Sep 20 10:15:32 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2
FAILED_RE = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s[\d:]+)\s.*sshd\[\d+\]:\s"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F\.:]+)"
)

# Matches: Accepted password for bob from 1.2.3.4 port 5555 ssh2
ACCEPTED_RE = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s[\d:]+)\s.*sshd\[\d+\]:\s"
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\da-fA-F\.:]+)"
)


def analyze(path):
    failed_count = defaultdict(int)
    failed_users = defaultdict(set)
    first_seen = {}
    last_seen = {}
    successes = defaultdict(list)  # ip -> [(time, user)]
    total_lines = 0

    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                total_lines += 1

                m = FAILED_RE.search(line)
                if m:
                    ip, user, t = m["ip"], m["user"], m["time"]
                    failed_count[ip] += 1
                    failed_users[ip].add(user)
                    first_seen.setdefault(ip, t)
                    last_seen[ip] = t
                    continue

                m = ACCEPTED_RE.search(line)
                if m:
                    successes[m["ip"]].append((m["time"], m["user"]))
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {path}")
    except PermissionError:
        sys.exit(f"Error: permission denied reading {path} (try sudo)")

    return total_lines, failed_count, failed_users, first_seen, last_seen, successes


def main():
    parser = argparse.ArgumentParser(description="Flag repeated failed SSH logins.")
    parser.add_argument("logfile", help="Path to auth log (e.g. /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts needed to flag an IP (default: 5)")
    parser.add_argument("--top", type=int, default=0,
                        help="Only show the top N offenders (default: all)")
    args = parser.parse_args()

    total, failed, users, first, last, successes = analyze(args.logfile)

    flagged = sorted(
        ((ip, c) for ip, c in failed.items() if c >= args.threshold),
        key=lambda x: x[1],
        reverse=True,
    )
    if args.top:
        flagged = flagged[: args.top]

    print(f"Lines scanned        : {total}")
    print(f"IPs with failures    : {len(failed)}")
    print(f"Total failed logins  : {sum(failed.values())}")
    print(f"Threshold            : {args.threshold}")
    print("-" * 60)

    if not flagged:
        print("No IPs exceeded the threshold.")
        return

    print(f"{'IP ADDRESS':<20}{'FAILS':<8}{'USERS TRIED':<13}FIRST -> LAST")
    for ip, count in flagged:
        print(f"{ip:<20}{count:<8}{len(users[ip]):<13}{first[ip]} -> {last[ip]}")

    # Most dangerous case: an IP that failed many times and then got in.
    compromised = [ip for ip, _ in flagged if ip in successes]
    if compromised:
        print("\n[!] WARNING: these flagged IPs also had a SUCCESSFUL login:")
        for ip in compromised:
            for t, user in successes[ip]:
                print(f"    {ip} logged in as '{user}' at {t}")
        print("    Investigate these accounts immediately.")


if __name__ == "__main__":
    main()