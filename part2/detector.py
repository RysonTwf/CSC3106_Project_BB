#!/usr/bin/env python3
"""
CSC3106 Mini-Project - Part 2: Technical Defensive Response.
Group BB

Detection logic for the credential-guessing behaviour we found in Part 1.
This is the "detect" layer of our response to Risk 3 from the Part 1 risk
matrix (no working rate limit or lockout on web01's SSH password logins),
which is the gap that let the 117-attempt burst against `deploy` succeed.

Three rules, each tied to a Part 1 finding:

  R1  burst_then_success   CRITICAL  A successful login from an IP straight
                                     after a burst of >= 10 failed attempts.
                                     This is exactly the deploy compromise
                                     pattern (brute_force_success.csv).
  R2  high_volume_source   HIGH      An IP reaches 25 failed attempts within
                                     one burst. The four campaign IPs from
                                     Part 1 all blow far past this (348+ per
                                     burst); no legitimate IP in our extract
                                     ever exceeds 9.
  R3  privileged_targeting MEDIUM    A privileged account (root, deploy,
                                     webadmin, ops, sysadmin) accumulates
                                     >= 15 failed attempts within 60 minutes,
                                     regardless of source IP - catches
                                     distributed guessing R2 would miss.

Alerts are written to output/alerts.csv. Run with --plot to also produce
output/detection_timeline.png, which shows when each layer of the response
would have fired during the window in which `deploy` was compromised.

Usage:
    python detector.py [path-to-log-file] [--outdir OUTDIR] [--plot]

Thresholds are argparse flags so a review team can re-tune them against a
different extract without editing code. See README.md for how we picked the
defaults from our Part 1 numbers.
"""

import argparse
import csv
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from authlog_parsing import parse_auth_events, PRIVILEGED_USERS, detect_burst_then_success


def rule_burst_then_success(events, streak_threshold, burst_gap_minutes):
    """R1: thin wrapper around Part 1's detect_burst_then_success, framed as
    an alert with a fire time (the moment of the successful login) so we can
    talk about when a live system would have known. This reuses Part 1's
    burst/streak computation directly rather than reimplementing it, so R1
    cannot silently drift from the Part 1 finding it's meant to reproduce."""
    findings = detect_burst_then_success(events, streak_threshold, burst_gap_minutes)
    return [
        {
            "alert_time": f["success_time"],
            "rule": "R1_burst_then_success",
            "severity": "CRITICAL",
            "source_ip": f["source_ip"],
            "username": f["username"],
            "failed_count": f["failed_count"],
            "window_start": f["burst_start"],
            "detail": (f"successful login to '{f['username']}' after "
                       f"{f['failed_count']} failed attempts from {f['source_ip']} since "
                       f"{f['burst_start']:%b %d %H:%M:%S}"),
        }
        for f in findings
    ]


def rule_high_volume_source(events, burst_threshold, burst_gap_minutes):
    """R2: fire once per burst, at the moment an IP's failed-attempt burst
    reaches the threshold. Firing at the threshold crossing (not at the end
    of the burst) is the point - it is what turns this from an after-the-fact
    report into something with lead time."""
    gap = timedelta(minutes=burst_gap_minutes)
    last_ts = {}
    burst_count = defaultdict(int)
    burst_start = {}
    fired = set()  # IPs whose current burst has already alerted

    alerts = []
    for e in events:
        if e["event_type"] != "failed_password":
            continue
        ip = e["ip"]
        if ip in last_ts and e["timestamp"] - last_ts[ip] > gap:
            burst_count[ip] = 0
            fired.discard(ip)
        if burst_count[ip] == 0:
            burst_start[ip] = e["timestamp"]
        burst_count[ip] += 1
        last_ts[ip] = e["timestamp"]

        if burst_count[ip] >= burst_threshold and ip not in fired:
            fired.add(ip)
            alerts.append({
                "alert_time": e["timestamp"],
                "rule": "R2_high_volume_source",
                "severity": "HIGH",
                "source_ip": ip,
                "username": "",
                "failed_count": burst_count[ip],
                "window_start": burst_start[ip],
                "detail": (f"{burst_count[ip]} failed attempts from {ip} in one "
                           f"burst (started {burst_start[ip]:%b %d %H:%M:%S}), "
                           f"still ongoing at alert time"),
            })
    return alerts


def rule_privileged_targeting(events, window_threshold, window_minutes):
    """R3: sliding 60-minute window per privileged username, across all
    source IPs. This is the rule that would still fire if the campaign
    switched to rotating source addresses, which is exactly the uncertainty
    we flagged against Risk 2 in Part 1. Fires once per episode: re-arms only
    after the account's window empties out."""
    window = timedelta(minutes=window_minutes)
    recent = defaultdict(deque)
    armed = defaultdict(lambda: True)

    alerts = []
    for e in events:
        if e["event_type"] != "failed_password" or e["user"] not in PRIVILEGED_USERS:
            continue
        user = e["user"]
        dq = recent[user]
        dq.append((e["timestamp"], e["ip"]))
        while dq and e["timestamp"] - dq[0][0] > window:
            dq.popleft()
        if not dq:
            armed[user] = True
        if len(dq) >= window_threshold and armed[user]:
            armed[user] = False
            ips = {ip for _, ip in dq}
            alerts.append({
                "alert_time": e["timestamp"],
                "rule": "R3_privileged_targeting",
                "severity": "MEDIUM",
                "source_ip": ";".join(sorted(ips)),
                "username": user,
                "failed_count": len(dq),
                "window_start": dq[0][0],
                "detail": (f"privileged account '{user}' hit {len(dq)} failed "
                           f"attempts in {window_minutes} min from "
                           f"{len(ips)} source IP(s)"),
            })
    return alerts


def write_alerts_csv(alerts, path):
    fields = ["alert_time", "rule", "severity", "source_ip", "username",
              "failed_count", "window_start", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            row = dict(a)
            row["alert_time"] = a["alert_time"].isoformat()
            row["window_start"] = a["window_start"].isoformat()
            writer.writerow(row)


# Chart palette (dataviz skill: validated hexes). The three vertical markers
# below are states in a timeline (prevented / warned / breached), so they take
# the fixed status trio rather than arbitrary categorical colors; the main
# series takes the same categorical blue used in the Part 1 figures.
COLOR_CATEGORICAL_BLUE = "#2a78d6"
COLOR_STATUS_GOOD = "#0ca30c"
COLOR_STATUS_WARNING = "#c98500"  # dark-band warning step - readable at 2px line weight on white
COLOR_STATUS_CRITICAL = "#d03b3b"
COLOR_TEXT_PRIMARY = "#0b0b0b"
COLOR_TEXT_MUTED = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"


def plot_detection_timeline(events, alerts, path, ban_time=None):
    """Figure for the report: the window in which `deploy` was compromised,
    with markers for when each layer of the proposed response fires. Scoped
    to the IP behind the highest-severity alert so it stays meaningful on a
    different extract."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    crit = [a for a in alerts if a["rule"] == "R1_burst_then_success"]
    if not crit:
        print("No R1 alerts - skipping timeline plot (nothing to anchor it to).")
        return
    incident = max(crit, key=lambda a: a["failed_count"])
    ip = incident["source_ip"]
    t0 = incident["window_start"] - timedelta(minutes=5)
    t1 = incident["alert_time"] + timedelta(minutes=10)

    fails = [e["timestamp"] for e in events
             if e["event_type"] == "failed_password" and e["ip"] == ip
             and t0 <= e["timestamp"] <= t1]
    cumulative = list(range(1, len(fails) + 1))

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.step(fails, cumulative, where="post", color=COLOR_CATEGORICAL_BLUE, linewidth=2,
            label=f"cumulative failed attempts from {ip}")

    r2 = [a for a in alerts if a["rule"] == "R2_high_volume_source"
          and a["source_ip"] == ip and t0 <= a["alert_time"] <= t1]
    if r2:
        ax.axvline(r2[0]["alert_time"], color=COLOR_STATUS_WARNING, linestyle="--", linewidth=2,
                   label=f"R2 alert ({r2[0]['alert_time']:%H:%M:%S})")
    if ban_time and t0 <= ban_time <= t1:
        ax.axvline(ban_time, color=COLOR_STATUS_GOOD, linestyle="-.", linewidth=2,
                   label=f"simulated fail2ban ban ({ban_time:%H:%M:%S})")
    ax.axvline(incident["alert_time"], color=COLOR_STATUS_CRITICAL, linestyle="-", linewidth=2,
               label=f"actual successful login ({incident['alert_time']:%H:%M:%S})")

    ax.set_axisbelow(True)
    ax.grid(axis="y", color=COLOR_GRID, linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(COLOR_BASELINE)
    ax.spines["bottom"].set_color(COLOR_BASELINE)
    ax.tick_params(colors=COLOR_TEXT_MUTED, labelcolor=COLOR_TEXT_MUTED)
    ax.set_xlabel(f"Time ({incident['alert_time']:%d %b})", color=COLOR_TEXT_PRIMARY)
    ax.set_ylabel("Cumulative failed attempts", color=COLOR_TEXT_PRIMARY)
    ax.set_title(f"Compromise window for '{incident['username']}': when each "
                 f"proposed layer fires", color=COLOR_TEXT_PRIMARY)
    legend = ax.legend(fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.38),
                       ncol=2, frameon=True, facecolor="#fcfcfb", edgecolor="none")
    legend.get_frame().set_alpha(0.95)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Timeline figure written to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", nargs="?", default="../1_auth.log.txt",
                        help="Path to the auth.log extract (default: ../1_auth.log.txt)")
    parser.add_argument("--outdir", default="output",
                        help="Directory for generated outputs (default: output)")
    parser.add_argument("--plot", action="store_true",
                        help="Also write detection_timeline.png (needs matplotlib)")
    parser.add_argument("--r1-streak", type=int, default=10,
                        help="R1: failed attempts before a success (default 10)")
    parser.add_argument("--r2-burst", type=int, default=25,
                        help="R2: failed attempts within one burst (default 25)")
    parser.add_argument("--r3-window-count", type=int, default=15,
                        help="R3: failures per privileged account per window (default 15)")
    parser.add_argument("--r3-window-minutes", type=int, default=60,
                        help="R3: sliding window length in minutes (default 60)")
    parser.add_argument("--burst-gap-minutes", type=int, default=30,
                        help="Gap that separates bursts, same as Part 1 (default 30)")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    events = parse_auth_events(args.logfile)

    alerts = []
    alerts += rule_burst_then_success(events, args.r1_streak, args.burst_gap_minutes)
    alerts += rule_high_volume_source(events, args.r2_burst, args.burst_gap_minutes)
    alerts += rule_privileged_targeting(events, args.r3_window_count, args.r3_window_minutes)
    alerts.sort(key=lambda a: a["alert_time"])

    write_alerts_csv(alerts, outdir / "alerts.csv")

    by_rule = defaultdict(int)
    for a in alerts:
        by_rule[a["rule"]] += 1
    print(f"Parsed {len(events)} auth events; {len(alerts)} alerts:")
    for rule in sorted(by_rule):
        print(f"  {rule}: {by_rule[rule]}")

    crit = [a for a in alerts if a["severity"] == "CRITICAL"]
    for a in crit:
        print(f"CRITICAL: {a['detail']}")
        # Lead time a live responder would have had, per rule, before this
        # particular success happened.
        earlier = [x for x in alerts if x["source_ip"] == a["source_ip"]
                   and x["alert_time"] < a["alert_time"]]
        if earlier:
            first = min(earlier, key=lambda x: x["alert_time"])
            lead = a["alert_time"] - first["alert_time"]
            print(f"  earliest prior alert for {a['source_ip']}: {first['rule']} at "
                  f"{first['alert_time']:%b %d %H:%M:%S} "
                  f"({lead} before the successful login)")

    ban_time = None
    if args.plot:
        # Overlay when the "prevent" layer would have acted, using the same
        # policy the lockout simulation defaults to.
        from simulate_lockout import simulate
        result = simulate(events, maxretry=5, findtime_seconds=600,
                          bantime_seconds=3600, increment=True)
        if crit:
            ip = max(crit, key=lambda a: a["failed_count"])["source_ip"]
            bans = [b for b in result["bans"] if b["source_ip"] == ip]
            window_start = max(crit, key=lambda a: a["failed_count"])["window_start"]
            in_window = [b for b in bans if b["ban_time"] >= window_start]
            if in_window:
                ban_time = in_window[0]["ban_time"]
        plot_detection_timeline(events, alerts, outdir / "detection_timeline.png",
                                ban_time=ban_time)


if __name__ == "__main__":
    main()
