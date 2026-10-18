import argparse
import json
import re
import sys
from datetime import datetime, timedelta

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path, year):
    """Return {ip: [(timestamp, username), ...]} for every failed login."""
    attempts = {}
    with open(path) as file:
        for line in file:
            match = PATTERN.search(line)
            if not match:
                continue
            username, ip = match.groups()
            try:
                timestamp = datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")
            except ValueError:
                continue
            attempts.setdefault(ip, []).append((timestamp, username))
    return attempts


def max_in_window(times, window):
    """Largest number of failures that fit inside any one time window."""
    times = sorted(times)
    best = 0
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(attempts, threshold, window_minutes, spray_users):
    window = timedelta(minutes=window_minutes)
    results = []
    for ip, entries in attempts.items():
        times = [t for t, _ in entries]
        users = sorted({u for _, u in entries})
        peak = max_in_window(times, window)
        if peak < threshold:
            continue
        spraying = len(users) >= spray_users
        results.append({
            "ip": ip,
            "attempts": len(entries),
            "peak_in_window": peak,
            "usernames": users,
            "first_seen": str(min(times)),
            "last_seen": str(max(times)),
            "attack_type": "Password Spraying" if spraying else "Brute Force",
            "mitre_technique": "T1110.003" if spraying else "T1110.001",
        })
    results.sort(key=lambda r: r["attempts"], reverse=True)
    return results


def print_report(results):
    if not results:
        print("No IPs over the threshold.")
        return
    print(f"{'IP':<18}{'Attempts':<10}{'In window':<11}{'Users':<7}{'Type':<19}Last seen")
    for r in results:
        print(
            f"{r['ip']:<18}{r['attempts']:<10}{r['peak_in_window']:<11}"
            f"{len(r['usernames']):<7}{r['attack_type']:<19}{r['last_seen']}"
        )


def save_report(results, path):
    with open(path, "w") as out:
        json.dump(results, out, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force and password-spraying attempts in auth.log"
    )
    parser.add_argument("logfile", nargs="?", default="samples/auth.log", help="path to auth.log")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="failures inside the window to flag an IP")
    parser.add_argument("-w", "--window", type=int, default=10, help="time window in minutes")
    parser.add_argument("-s", "--spray", type=int, default=3, help="unique usernames to call it spraying")
    parser.add_argument("-o", "--output", default="report.json", help="JSON report path")
    parser.add_argument("-y", "--year", type=int, default=datetime.now().year, help="log year (auth.log has none)")
    args = parser.parse_args()

    try:
        attempts = parse_log(args.logfile, args.year)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")

    if not attempts:
        sys.exit("No failed SSH logins found in the log.")

    results = analyze(attempts, args.threshold, args.window, args.spray)
    print_report(results)
    save_report(results, args.output)
    print(f"\n{len(results)} suspicious IP(s). Report saved to {args.output}")


if __name__ == "__main__":
    main()