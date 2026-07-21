#!/usr/bin/env python3
"""
CSC3106 Mini-Project - Part 1: Data-Driven Authentication Log Analysis
Group BB

Parses our assigned OpenSSH-style auth.log extract (1_auth.log) and produces
the summary tables + visualisations we're using as evidence in the Part 1
report section. Everything in the report should be reproducible by just
rerunning this against the extract.

Usage:
    python analysis.py [path-to-log-file] [--outdir OUTDIR]

See README.md for the full writeup of why we made the parsing calls we did.
"""

import argparse
import csv
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # write PNGs without a display
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# ---------------------------------------------------------------------------
# Configuration and assumptions
# ---------------------------------------------------------------------------

# Syslog-style timestamps in this extract ("Jul 06 00:04:33") carry no year.
# The extract covers a single, contiguous week, so the choice of year only
# affects the printed date labels, not event ordering or day-level counts.
ASSUMED_YEAR = 2026

# Accounts treated as privileged/high-value for reporting: root is the OS
# superuser, and the others are named accounts observed issuing privileged
# sudo commands (e.g. systemctl, apt) in this extract's sudo log lines.
PRIVILEGED_USERS = {"root", "deploy", "webadmin", "ops", "sysadmin"}

# A successful ("Accepted password") login preceded by at least this many
# failed attempts from the same source IP within a single burst (see
# BURST_GAP_MINUTES below), with no intervening success, is flagged as a
# suspected brute-force compromise. We set this well above the ~5-6
# occasional-mistype baseline we saw across ordinary source IPs in this
# extract - see README for how we picked it.
BRUTE_FORCE_STREAK_THRESHOLD = 10

# Failed attempts from the same IP are grouped into one "burst" as long as
# consecutive attempts are no more than this many minutes apart, otherwise
# a new burst starts. We needed this because our first version of the
# detection below only reset the streak on a success, which meant it just
# summed failed attempts across the whole file for an IP that only ever
# succeeded once - the gap-based grouping is what actually finds a real
# attack window instead of a meaningless multi-day total.
BURST_GAP_MINUTES = 30

TOP_N = 10

IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

# Matches the common syslog line prefix: "Mon DD HH:MM:SS host process[pid]: message"
LINE_RE = re.compile(
    r"^(?P<month>\w{3}) (?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

# sshd message patterns, checked in this order for each sshd line.
SSHD_PATTERNS = [
    ("failed_password", re.compile(
        r"^Failed password for (?:invalid user )?(?P<user>\S+) "
        rf"from {IP_RE} port (?P<port>\d+)"
    )),
    ("accepted_password", re.compile(
        r"^Accepted password for (?P<user>\S+) "
        rf"from {IP_RE} port (?P<port>\d+)"
    )),
    ("invalid_user", re.compile(
        rf"^Invalid user (?P<user>\S+) from {IP_RE} port (?P<port>\d+)$"
    )),
    ("max_auth_exceeded", re.compile(
        r"^error: maximum authentication attempts exceeded for "
        rf"(?:invalid user )?(?P<user>\S+) from {IP_RE} port (?P<port>\d+)"
    )),
    ("conn_closed_preauth", re.compile(
        rf"^Connection closed by authenticating user (?P<user>\S+) {IP_RE} "
        r"port (?P<port>\d+) \[preauth\]"
    )),
    ("session_opened", re.compile(
        r"^pam_unix\(sshd:session\): session opened for user (?P<user>\S+)"
    )),
    ("session_closed", re.compile(
        r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)"
    )),
    # This one we almost missed - it showed up as ~35 "unmatched" lines on
    # our first run, and it turned out to be sshd's own reverse-DNS
    # break-in heuristic, not something we're inferring ourselves. Worth
    # keeping as its own event type since it's corroborating evidence sshd
    # generated independently of anything we did.
    ("possible_breakin_warning", re.compile(
        r"^reverse mapping checking getaddrinfo for \S+ "
        rf"\[{IP_RE}\] failed - POSSIBLE BREAK-IN ATTEMPT!"
    )),
]

SUDO_PATTERN = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)


def classify_line(process, message):
    """Return (event_type, fields) for a syslog message, or (None, {}) if
    the line does not match a known authentication-relevant pattern.

    process == 'CRON' lines are cron session bookkeeping, not interactive
    authentication, so they are tagged separately and excluded from the
    authentication-focused counts and visualisations.
    """
    if process == "sshd":
        for event_type, pattern in SSHD_PATTERNS:
            m = pattern.match(message)
            if m:
                return event_type, m.groupdict()
        return None, {}
    if process == "sudo":
        m = SUDO_PATTERN.match(message)
        if m:
            return "sudo_command", m.groupdict()
        return None, {}
    if process == "CRON":
        return "cron_activity", {}
    return None, {}


def parse_log(path, assumed_year=ASSUMED_YEAR):
    """Read the raw log file and return a list of event records plus a list
    of raw lines that could not be classified (kept for the limitations
    discussion and for reviewers to audit parsing coverage)."""
    events = []
    unmatched = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            m = LINE_RE.match(line)
            if not m:
                unmatched.append((lineno, line))
                continue

            try:
                ts = datetime.strptime(
                    f"{m.group('month')} {m.group('day')} {m.group('time')} {assumed_year}",
                    "%b %d %H:%M:%S %Y",
                )
            except ValueError:
                unmatched.append((lineno, line))
                continue

            process = m.group("process").strip()
            event_type, fields = classify_line(process, m.group("message"))

            if event_type is None:
                unmatched.append((lineno, line))
                continue

            events.append({
                "lineno": lineno,
                "timestamp": ts,
                "process": process,
                "event_type": event_type,
                "user": fields.get("user"),
                "ip": fields.get("ip"),
                "port": fields.get("port"),
                "sudo_command": fields.get("command"),
                "sudo_target": fields.get("target"),
                "raw": line,
            })

    # Events must be in chronological order for the streak/time-series
    # analysis below; the source file is expected to be time-ordered per
    # host, but we sort defensively rather than assume it.
    events.sort(key=lambda e: (e["timestamp"], e["lineno"]))
    return events, unmatched


# ---------------------------------------------------------------------------
# Summary builders
# ---------------------------------------------------------------------------

def build_summary_counts(events, unmatched, total_lines):
    counts = Counter(e["event_type"] for e in events)
    rows = [{"event_type": k, "count": v} for k, v in counts.most_common()]
    rows.append({"event_type": "unmatched_lines", "count": len(unmatched)})
    rows.append({"event_type": "total_lines_in_file", "count": total_lines})
    return rows


def build_top_source_ips(events, top_n=TOP_N):
    failed = [e for e in events if e["event_type"] == "failed_password"]
    invalid = [e for e in events if e["event_type"] == "invalid_user"]
    accepted = [e for e in events if e["event_type"] == "accepted_password"]
    breakin = [e for e in events if e["event_type"] == "possible_breakin_warning"]

    failed_by_ip = Counter(e["ip"] for e in failed)
    invalid_by_ip = Counter(e["ip"] for e in invalid)
    accepted_by_ip = Counter(e["ip"] for e in accepted)
    breakin_by_ip = Counter(e["ip"] for e in breakin)

    ips = set(failed_by_ip) | set(invalid_by_ip) | set(accepted_by_ip) | set(breakin_by_ip)
    rows = []
    for ip in ips:
        rows.append({
            "source_ip": ip,
            "failed_password_count": failed_by_ip.get(ip, 0),
            "invalid_user_count": invalid_by_ip.get(ip, 0),
            "accepted_password_count": accepted_by_ip.get(ip, 0),
            "sshd_breakin_warning_count": breakin_by_ip.get(ip, 0),
        })
    rows.sort(key=lambda r: r["failed_password_count"], reverse=True)
    return rows[:top_n]


def build_targeted_usernames(events, top_n=TOP_N, privileged_users=PRIVILEGED_USERS):
    failed = [e for e in events if e["event_type"] == "failed_password"]
    by_user = Counter(e["user"] for e in failed)
    rows = [
        {
            "username": user,
            "failed_password_count": count,
            "privileged_account": user in privileged_users,
        }
        for user, count in by_user.most_common(top_n)
    ]
    return rows


def build_failed_attempts_over_time(events):
    failed = [e for e in events if e["event_type"] == "failed_password"]
    by_day = Counter(e["timestamp"].date() for e in failed)
    rows = [
        {"date": d.isoformat(), "failed_password_count": c}
        for d, c in sorted(by_day.items())
    ]
    return rows


def build_privileged_targeting(events, privileged_users=PRIVILEGED_USERS):
    relevant = [
        e for e in events
        if e["event_type"] in ("failed_password", "invalid_user", "accepted_password")
        and e["user"] in privileged_users
    ]
    grouped = Counter((e["user"], e["event_type"]) for e in relevant)
    rows = [
        {"username": user, "event_type": event_type, "count": count}
        for (user, event_type), count in sorted(grouped.items())
    ]
    return rows


def detect_burst_then_success(events, streak_threshold=BRUTE_FORCE_STREAK_THRESHOLD,
                               burst_gap_minutes=BURST_GAP_MINUTES):
    """Shared core of the burst-then-success check: per source IP, find
    successful logins preceded by a burst of failed password attempts with
    no intervening success. Failed attempts are grouped into a burst while
    the gap between consecutive attempts stays within burst_gap_minutes; a
    larger gap starts a new burst. This is the strongest evidence of an
    actual credential compromise (as opposed to scanning/guessing that never
    succeeds).

    Returns raw datetime objects rather than a report-ready row shape,
    because part2/detector.py's R1 rule imports this directly and needs
    datetimes for further alert-timing arithmetic; build_brute_force_success
    below does the CSV-friendly formatting for Part 1's own output. Sharing
    this function (rather than each part keeping its own copy of the
    streak/gap logic) is what guarantees R1 can't quietly drift from the
    Part 1 finding it's meant to reproduce."""
    gap = timedelta(minutes=burst_gap_minutes)
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("failed_password", "accepted_password"):
            by_ip[e["ip"]].append(e)

    findings = []
    for ip, evs in by_ip.items():
        streak = 0
        streak_start = None
        last_failed_ts = None
        usernames_in_burst = set()
        for e in evs:
            if e["event_type"] == "failed_password":
                if streak == 0 or (last_failed_ts is not None and e["timestamp"] - last_failed_ts > gap):
                    streak = 0
                    streak_start = e["timestamp"]
                    usernames_in_burst = set()
                streak += 1
                usernames_in_burst.add(e["user"])
                last_failed_ts = e["timestamp"]
            else:  # accepted_password
                if streak >= streak_threshold:
                    findings.append({
                        "source_ip": ip,
                        "username": e["user"],
                        "failed_count": streak,
                        "distinct_usernames_in_burst": len(usernames_in_burst),
                        "burst_start": streak_start,
                        "last_failed_at": last_failed_ts,
                        "success_time": e["timestamp"],
                    })
                streak = 0
                last_failed_ts = None
                usernames_in_burst = set()
    findings.sort(key=lambda r: r["failed_count"], reverse=True)
    return findings


def build_brute_force_success(events, streak_threshold=BRUTE_FORCE_STREAK_THRESHOLD,
                               burst_gap_minutes=BURST_GAP_MINUTES):
    """Report-ready wrapper around detect_burst_then_success, formatted for
    this script's CSV output."""
    findings = detect_burst_then_success(events, streak_threshold, burst_gap_minutes)
    return [
        {
            "source_ip": f["source_ip"],
            "username": f["username"],
            "failed_attempts_in_burst": f["failed_count"],
            "distinct_usernames_in_burst": f["distinct_usernames_in_burst"],
            "burst_start": f["burst_start"].isoformat(),
            "success_time": f["success_time"].isoformat(),
            "burst_span_seconds": int((f["last_failed_at"] - f["burst_start"]).total_seconds()),
        }
        for f in findings
    ]


def build_sudo_commands(events):
    rows = []
    for e in events:
        if e["event_type"] == "sudo_command":
            rows.append({
                "timestamp": e["timestamp"].isoformat(),
                "user": e["user"],
                "target_user": e["sudo_target"],
                "command": e["sudo_command"],
            })
    return rows


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_csv(rows, path):
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# Chart palette (dataviz skill: validated categorical + status hexes, six checks
# passed via scripts/validate_palette.js). Kept as module constants so the three
# report figures in this file read as one system rather than three ad-hoc charts.
COLOR_CATEGORICAL_BLUE = "#2a78d6"
COLOR_STATUS_CRITICAL = "#d03b3b"
COLOR_TEXT_PRIMARY = "#0b0b0b"
COLOR_TEXT_MUTED = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"


def _style_axes(ax, grid_axis):
    """Shared chart chrome: hairline recessive gridlines, no top/right spines,
    muted axis ink. Applied to every figure so they read as one system."""
    ax.set_axisbelow(True)
    ax.grid(axis=grid_axis, color=COLOR_GRID, linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(COLOR_BASELINE)
    ax.spines["bottom"].set_color(COLOR_BASELINE)
    ax.tick_params(colors=COLOR_TEXT_MUTED, labelcolor=COLOR_TEXT_MUTED)
    ax.xaxis.label.set_color(COLOR_TEXT_PRIMARY)
    ax.yaxis.label.set_color(COLOR_TEXT_PRIMARY)
    ax.title.set_color(COLOR_TEXT_PRIMARY)


def plot_top_source_ips(rows, path):
    rows = list(reversed(rows))  # largest at top of barh
    ips = [r["source_ip"] for r in rows]
    counts = [r["failed_password_count"] for r in rows]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(ips, counts, color=COLOR_CATEGORICAL_BLUE, height=0.6)
    _style_axes(ax, grid_axis="x")
    ax.set_xlabel("Failed password attempts")
    ax.set_ylabel("Source IP address")
    ax.set_title("Top source IP addresses by failed authentication attempts")
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                 str(count), va="center", fontsize=8, color=COLOR_TEXT_PRIMARY)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_failed_attempts_over_time(rows, path):
    dates = [r["date"] for r in rows]
    counts = [r["failed_password_count"] for r in rows]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(dates, counts, color=COLOR_CATEGORICAL_BLUE, width=0.6)
    _style_axes(ax, grid_axis="y")
    ax.set_xlabel("Date")
    ax.set_ylabel("Failed password attempts")
    ax.set_title("Failed authentication attempts per day")
    ax.tick_params(axis="x", rotation=30)
    for i, count in enumerate(counts):
        ax.text(i, count + max(counts) * 0.01, str(count), ha="center", fontsize=8, color=COLOR_TEXT_PRIMARY)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_targeted_usernames(rows, path):
    rows = list(reversed(rows))
    users = [r["username"] for r in rows]
    counts = [r["failed_password_count"] for r in rows]
    colors = [COLOR_STATUS_CRITICAL if r["privileged_account"] else COLOR_CATEGORICAL_BLUE for r in rows]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(users, counts, color=colors, height=0.6)
    _style_axes(ax, grid_axis="x")
    ax.set_xlabel("Failed password attempts")
    ax.set_ylabel("Targeted username")
    ax.set_title("Top targeted usernames by failed authentication attempts")
    legend_handles = [
        Patch(facecolor=COLOR_STATUS_CRITICAL, label="Privileged / high-value account"),
        Patch(facecolor=COLOR_CATEGORICAL_BLUE, label="Standard account"),
    ]
    ax.legend(handles=legend_handles, loc="lower right", fontsize=8, frameon=False)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                 str(count), va="center", fontsize=8, color=COLOR_TEXT_PRIMARY)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def write_unmatched_sample(unmatched, path, sample_size=50):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Total unmatched lines: {len(unmatched)}\n")
        f.write(f"Showing first {min(sample_size, len(unmatched))}:\n\n")
        for lineno, line in unmatched[:sample_size]:
            f.write(f"{lineno}: {line}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "logfile", nargs="?", default="1_auth.log.txt",
        help="Path to the assigned auth.log extract (default: 1_auth.log.txt)",
    )
    parser.add_argument(
        "--outdir", default="output",
        help="Directory to write generated tables and figures (default: output)",
    )
    parser.add_argument(
        "--streak-threshold", type=int, default=BRUTE_FORCE_STREAK_THRESHOLD,
        help="Failed attempts from one IP in a single burst before a "
             "following success is flagged as a suspected brute-force "
             f"compromise (default {BRUTE_FORCE_STREAK_THRESHOLD})",
    )
    parser.add_argument(
        "--burst-gap-minutes", type=int, default=BURST_GAP_MINUTES,
        help="Minutes between consecutive failed attempts from the same IP "
             "before a new burst is started; same meaning as "
             f"part2/detector.py's flag of the same name (default {BURST_GAP_MINUTES})",
    )
    parser.add_argument(
        "--assumed-year", type=int, default=ASSUMED_YEAR,
        help="Year to assume for timestamps that omit one, e.g. syslog's "
             f"'Jul 06 00:04:33' (default {ASSUMED_YEAR})",
    )
    parser.add_argument(
        "--privileged-users", default=",".join(sorted(PRIVILEGED_USERS)),
        help="Comma-separated usernames to treat as privileged/high-value "
             f"(default: {','.join(sorted(PRIVILEGED_USERS))})",
    )
    args = parser.parse_args()

    log_path = Path(args.logfile)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    privileged_users = {u.strip() for u in args.privileged_users.split(",") if u.strip()}

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        total_lines = sum(1 for _ in f)

    events, unmatched = parse_log(log_path, assumed_year=args.assumed_year)

    summary_counts = build_summary_counts(events, unmatched, total_lines)
    top_ips = build_top_source_ips(events)
    targeted_users = build_targeted_usernames(events, privileged_users=privileged_users)
    over_time = build_failed_attempts_over_time(events)
    privileged = build_privileged_targeting(events, privileged_users=privileged_users)
    brute_force = build_brute_force_success(events, streak_threshold=args.streak_threshold,
                                             burst_gap_minutes=args.burst_gap_minutes)
    sudo_cmds = build_sudo_commands(events)

    write_csv(summary_counts, outdir / "summary_counts.csv")
    write_csv(top_ips, outdir / "top_source_ips.csv")
    write_csv(targeted_users, outdir / "targeted_usernames.csv")
    write_csv(over_time, outdir / "failed_attempts_over_time.csv")
    write_csv(privileged, outdir / "privileged_account_targeting.csv")
    write_csv(brute_force, outdir / "brute_force_success.csv")
    write_csv(sudo_cmds, outdir / "sudo_commands.csv")
    write_unmatched_sample(unmatched, outdir / "unmatched_lines.txt")

    plot_top_source_ips(top_ips, outdir / "top_source_ips.png")
    plot_failed_attempts_over_time(over_time, outdir / "failed_attempts_over_time.png")
    plot_targeted_usernames(targeted_users, outdir / "targeted_usernames.png")

    print(f"Parsed {len(events)} authentication-relevant events "
          f"from {total_lines} lines ({len(unmatched)} unmatched).")
    print(f"Outputs written to: {outdir.resolve()}")
    if brute_force:
        top = brute_force[0]
        print(f"Highest-risk finding: {top['failed_attempts_in_burst']} failed attempts "
              f"from {top['source_ip']} in a single burst, before a successful login "
              f"to '{top['username']}' at {top['success_time']}.")


if __name__ == "__main__":
    main()
