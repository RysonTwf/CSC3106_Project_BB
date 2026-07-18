# Appendix: Asset-Focused Risk Matrix (Part 1)

**Asset:** `web01`, the host our extract came from, reachable over SSH,
including the privileged/service accounts on it (`root`, `deploy`,
`webadmin`, `ops`, `sysadmin`) that can `sudo` to root and restart
services or change system state (we saw `systemctl restart apache2` and
`apt update` among the commands actually run).

**Why it matters:** `web01` is what's serving the organisation's web
application, and it's administered remotely by a small set of named
accounts over SSH. If someone other than those accounts' legitimate
owners can get in, that's not just a `web01` problem. It's a problem for
whatever `web01` is running.

We tried to keep likelihood/impact grounded in `web01` specifically
rather than rating things in the abstract. Everything below points back
to a specific file in `output/` so it can be checked.

| # | Risk / finding | Likelihood | Impact | Why we rated it this way | What we're still not sure about |
|---|---|---|---|---|---|
| 1 | `web01` was accessed by someone who isn't the legitimate owner of the `deploy` account | **Confirmed / High** | **Critical** | `output/brute_force_success.csv` shows 117 failed passwords from `203.0.113.77` in a 34-minute window (23:13-23:47, 11 July), then a successful login, then a `sudo` command run as root within seconds (`output/sudo_commands.csv`). `deploy` genuinely has sudo-to-root rights, so this isn't a low-privilege account. | We only see the one command from that session. We can't tell if anything else happened (files changed, other accounts touched) because that's simply not information an auth.log captures. |
| 2 | Ongoing, concentrated credential-guessing against `web01` from a handful of external IPs | **High, and still happening as far as we can tell** | **High** | Four IPs (`203.0.113.77`, `198.51.100.8`, `203.0.113.101`, `198.51.100.140`) account for 2,555 of 3,724 failed attempts, 69% of all of them (`output/top_source_ips.csv`). Two of the four also tripped sshd's own break-in warning 35 times combined, which we didn't have to infer since sshd flagged it. | We have no way of knowing if this is one actor rotating source addresses or several unrelated scanners hitting the same box. |
| 3 | SSH password authentication on `web01` doesn't seem to have any working rate limit or lockout | **High** | **High** | 117 failed attempts from one IP in 34 minutes, uninterrupted. `output/summary_counts.csv` shows 443 "maximum authentication attempts exceeded" errors, which just means sshd hit its per-connection retry cap. The attacker simply reconnected and kept going, so whatever that cap is doing, it isn't stopping anyone. | We can't see firewall or fail2ban logs in this extract, so we genuinely don't know if a control exists somewhere and just isn't working, versus there being nothing there at all. |
| 4 | Privileged/service accounts on `web01` (not just `deploy`) are being directly guessed | **Medium** | **Critical if it works** | `root` alone was targeted 149 times (109 failed + 40 invalid-user, `output/privileged_account_targeting.csv`), and `deploy`/`webadmin`/`ops` are the three most-targeted usernames overall. No `Accepted password for root` line exists anywhere in the extract, so as far as we can tell root itself has held so far. | We only know `deploy` was actually compromised. Whether any of the others have been guessed successfully outside this specific week is something this log simply can't answer. |
| 5 | Once someone's logged into `web01`, there's not much to distinguish attacker activity from ordinary admin activity | **High, we already ran into this** | **Medium-High** | The one command run in the compromised session, `systemctl restart apache2`, is identical to a command run 60 other times in the extract by accounts we have no reason to suspect (`output/sudo_commands.csv`). Nothing about the command itself is unusual. | This is more a gap in what we can detect than a specific attacker action we observed. We genuinely don't know if the compromised session did anything beyond that one command. |
