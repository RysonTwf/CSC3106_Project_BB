#!/usr/bin/env python3
"""
CSC3106 Mini-Project - Part 2: Technical Defensive Response.
Group BB

Replays our assigned extract through a fail2ban-style rate-limit/lockout
policy to test, against real evidence rather than intuition, whether the
"prevent" layer of our proposed response (config/fail2ban/jail.local) would
actually have stopped what we saw in Part 1 - and what it would have cost
legitimate users.

Policy modelled (same shape as fail2ban's sshd jail):
  - an IP that accumulates `maxretry` failed attempts within `findtime`
    seconds is banned for `bantime` seconds
  - with --increment (our recommendation, and the default), each repeat ban
    of the same IP doubles in length, mirroring fail2ban's
    bantime.increment behaviour
  - any event from a banned IP (failed OR successful) is counted as blocked:
    a banned IP cannot reach sshd at all

Honesty caveat, also spelled out in the report: this replays the traffic
exactly as it happened. A real attacker who keeps getting banned would
change behaviour (rotate IPs, slow down), so the right reading of these
numbers is "this specific observed attack would have been interrupted", not
"attacks like this become impossible". That residual risk is why the
response also has a detection layer (detector.py) and a structural fix
(key-only auth for privileged accounts, config/sshd_config.d/).

Usage:
    python simulate_lockout.py [path-to-log-file] [--outdir OUTDIR]
                               [--maxretry N] [--findtime SECONDS]
                               [--bantime SECONDS] [--no-increment]

Outputs output/lockout_simulation.csv (per-IP results) and a console summary
answering the question we actually care about: would the deploy compromise
have been prevented, and would anyone legitimate have been locked out?
"""

import argparse
import csv
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from authlog_parsing import parse_auth_events


def simulate(events, maxretry=5, findtime_seconds=600, bantime_seconds=3600,
             increment=True):
    """Replay events chronologically through the ban policy. Returns per-IP
    stats, the list of individual bans, and the successful logins that fell
    inside a ban window (i.e. logins the policy would have prevented)."""
    findtime = timedelta(seconds=findtime_seconds)

    banned_until = {}
    ban_counts = defaultdict(int)
    recent_fails = defaultdict(deque)
    stats = defaultdict(lambda: {
        "failed_seen": 0, "failed_blocked": 0,
        "accepted_seen": 0, "accepted_blocked": 0, "bans": 0,
    })
    bans = []
    blocked_logins = []

    for e in events:
        if e["event_type"] not in ("failed_password", "accepted_password"):
            continue
        ip = e["ip"]
        s = stats[ip]
        is_banned = ip in banned_until and e["timestamp"] < banned_until[ip]

        if e["event_type"] == "failed_password":
            s["failed_seen"] += 1
            if is_banned:
                s["failed_blocked"] += 1
                continue
            dq = recent_fails[ip]
            dq.append(e["timestamp"])
            while dq and e["timestamp"] - dq[0] > findtime:
                dq.popleft()
            if len(dq) >= maxretry:
                ban_counts[ip] += 1
                # bantime doubles per repeat ban when increment is on
                factor = 2 ** (ban_counts[ip] - 1) if increment else 1
                duration = timedelta(seconds=bantime_seconds * factor)
                banned_until[ip] = e["timestamp"] + duration
                s["bans"] += 1
                bans.append({
                    "source_ip": ip,
                    "ban_time": e["timestamp"],
                    "ban_seconds": int(duration.total_seconds()),
                    "ban_number_for_ip": ban_counts[ip],
                })
                dq.clear()
        else:  # accepted_password
            s["accepted_seen"] += 1
            if is_banned:
                s["accepted_blocked"] += 1
                blocked_logins.append({
                    "timestamp": e["timestamp"],
                    "source_ip": ip,
                    "username": e["user"],
                })

    return {"stats": dict(stats), "bans": bans, "blocked_logins": blocked_logins}


def plot_blocked_bars(stats, path):
    """Figure for the report: per-IP failed attempts under the proposed
    lockout policy, split into blocked (never reached sshd) vs. got through.
    Campaign IPs are shown individually; every other IP in the extract is
    rolled into a single "all other IPs" bar so the chart stays readable."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Chart palette (dataviz skill): blocked/got-through is a good/bad state,
    # not an arbitrary series, so it takes the fixed status pair rather than
    # categorical hues.
    color_good = "#0ca30c"
    color_critical = "#d03b3b"
    color_surface = "#fcfcfb"
    color_muted = "#898781"
    color_grid = "#e1e0d9"
    color_baseline = "#c3c2b7"
    color_text = "#0b0b0b"

    campaign_ips = {"203.0.113.77", "198.51.100.8", "203.0.113.101", "198.51.100.140"}
    rows = [(ip, s) for ip, s in stats.items() if ip in campaign_ips]
    rows.sort(key=lambda kv: kv[1]["failed_seen"], reverse=True)

    other_seen = sum(s["failed_seen"] for ip, s in stats.items() if ip not in campaign_ips)
    other_blocked = sum(s["failed_blocked"] for ip, s in stats.items() if ip not in campaign_ips)
    labels = [ip for ip, _ in rows] + ["all other IPs\n(12 IPs)"]
    seen = [s["failed_seen"] for _, s in rows] + [other_seen]
    blocked = [s["failed_blocked"] for _, s in rows] + [other_blocked]
    # Share of each IP's failed attempts blocked, not the raw count: the
    # campaign IPs' attempt volumes are two orders of magnitude apart, so a
    # 100%-stacked view is what actually makes "did the policy work for this
    # IP" comparable across rows.
    blocked_pct = [100 * b / t if t else 0 for b, t in zip(blocked, seen)]
    got_through_pct = [100 - p for p in blocked_pct]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    y = range(len(labels))
    bar_height = 0.6
    # A thin surface-color edge between segments stands in for the "2px surface
    # gap" mark spec - it separates the two stacked states without extra ink.
    ax.barh(y, blocked_pct, height=bar_height, color=color_good, edgecolor=color_surface, linewidth=1.5,
            label="blocked by policy (never reached sshd)")
    ax.barh(y, got_through_pct, left=blocked_pct, height=bar_height, color=color_critical,
            edgecolor=color_surface, linewidth=1.5, label="got through to sshd")
    for i, (bp, t) in enumerate(zip(blocked_pct, seen)):
        ax.annotate(f"{bp:.0f}% of {t}", (100, i), textcoords="offset points", xytext=(6, 0),
                    va="center", fontsize=8, color=color_text)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 130)
    ax.set_axisbelow(True)
    ax.grid(axis="x", color=color_grid, linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(color_baseline)
    ax.spines["bottom"].set_color(color_baseline)
    ax.tick_params(colors=color_muted, labelcolor=color_muted)
    ax.set_xlabel("Share of failed password attempts (%)", color=color_text)
    ax.set_title("Share of failed attempts blocked under the proposed fail2ban policy", color=color_text)
    ax.legend(fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.12),
              ncol=2, frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Blocked-attempts figure written to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", nargs="?", default="../1_auth.log.txt",
                        help="Path to the auth.log extract (default: ../1_auth.log.txt)")
    parser.add_argument("--outdir", default="output",
                        help="Directory for generated outputs (default: output)")
    parser.add_argument("--maxretry", type=int, default=5,
                        help="Failed attempts within findtime before a ban (default 5)")
    parser.add_argument("--findtime", type=int, default=600,
                        help="Window in seconds for counting retries (default 600)")
    parser.add_argument("--bantime", type=int, default=3600,
                        help="Initial ban length in seconds (default 3600)")
    parser.add_argument("--no-increment", action="store_true",
                        help="Disable doubling of repeat-ban durations")
    parser.add_argument("--plot", action="store_true",
                        help="Also write output/lockout_blocked.png (needs matplotlib)")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    events = parse_auth_events(args.logfile)
    result = simulate(events, maxretry=args.maxretry,
                      findtime_seconds=args.findtime,
                      bantime_seconds=args.bantime,
                      increment=not args.no_increment)

    rows = []
    for ip, s in sorted(result["stats"].items(),
                        key=lambda kv: kv[1]["failed_blocked"], reverse=True):
        rows.append({"source_ip": ip, **s})
    with open(outdir / "lockout_simulation.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    total_blocked = sum(s["failed_blocked"] for s in result["stats"].values())
    total_failed = sum(s["failed_seen"] for s in result["stats"].values())
    print(f"Policy: maxretry={args.maxretry}, findtime={args.findtime}s, "
          f"bantime={args.bantime}s, increment={not args.no_increment}")
    print(f"{len(result['bans'])} bans across {sum(1 for s in result['stats'].values() if s['bans'])} IPs; "
          f"{total_blocked} of {total_failed} failed attempts would have been blocked.")

    if result["blocked_logins"]:
        print("Successful logins that would have been PREVENTED (fell inside a ban):")
        for b in result["blocked_logins"]:
            print(f"  {b['timestamp']:%b %d %H:%M:%S}  {b['username']} from {b['source_ip']}")
    else:
        print("No successful logins fell inside a ban window under this policy.")

    # The cost side: a legitimate user locked out by their own typos would
    # show up here as a blocked login from an IP with routine successes.
    collateral = [b for b in result["blocked_logins"]
                  if result["stats"][b["source_ip"]]["accepted_seen"]
                  - result["stats"][b["source_ip"]]["accepted_blocked"] > 5]
    if collateral:
        print(f"Note: {len(collateral)} of those look like routine users "
              f"(IPs with >5 other successful logins) - check before tightening.")

    print(f"Per-IP details written to {outdir / 'lockout_simulation.csv'}")

    if args.plot:
        plot_blocked_bars(result["stats"], outdir / "lockout_blocked.png")


if __name__ == "__main__":
    main()
