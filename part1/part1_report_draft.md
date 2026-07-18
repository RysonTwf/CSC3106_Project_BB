# Part 1: Data-Driven Authentication Log Analysis (Group BB)

*Draft for the group report, still needs a once-over before it goes into
report.pdf, but the numbers below are all pulled straight from
`part1/output/`, so they shouldn't need re-checking, just rewording if we
want.*

## 1. Security question and framing

We were given `1_auth.log` (Group BB's extract: 12,000 lines from a host
called `web01`, covering 6-12 July) and asked to figure out what an
organisation should actually be worried about in it. Rather than just
listing every failed login we could find, we tried to keep coming back to
one question:

> **Which authentication events or patterns on `web01` should be
> prioritised for investigation or response, and why?**

Everything below came out of `part1/analysis.py`, which we wrote to parse
the raw log and produce the tables/figures we're using as evidence (see
`part1/README.md` for how it works and why we made the parsing choices we
did). We leaned on AI tooling to help write the parser and draft this
section, which is declared in `part1/ai_use_declaration.md`, but every
number quoted here comes from actually running the script against our
extract, not from asking a model to summarise the log for us.

## 2. What we found

Running the script over all 12,000 lines (nothing was left unparsed once
we accounted for every message type sshd actually logs, see
`output/summary_counts.csv`) gave us 3,724 failed password attempts,
1,991 successful logins, and 1,468 "invalid user" notices, plus 443
`maximum authentication attempts exceeded` errors. On their own those
numbers don't say much, so we dug into where they were coming from and
when.

**The big one: a brute-force attempt that actually worked.** One IP,
`203.0.113.77`, threw 117 failed passwords at the `deploy` account inside
a 34-minute window (23:13-23:47 on 11 July) and then got in. The very
next line is `Accepted password for deploy` at 23:47:04
(`output/brute_force_success.csv`). Within seconds that session ran `sudo
systemctl restart apache2` as root (`output/sudo_commands.csv`). We
checked whether this was just a case of someone mistyping their password
a few times (ordinary IPs elsewhere in the log occasionally show 5 or 6
failed attempts right before a legitimate success), but nothing else
comes close to 117 in a tight burst, so we're treating this as a genuine
compromise rather than noise.

**It's not just that one IP.** Four source IPs, `203.0.113.77`,
`198.51.100.8`, `203.0.113.101`, and `198.51.100.140`, are responsible
for 2,555 of the 3,724 failed attempts in the whole extract, which is
69%. Everything else sits in the 84-113 range (Figure 1,
`output/top_source_ips.png`). Two of those four IPs also tripped sshd's
own `POSSIBLE BREAK-IN ATTEMPT!` reverse-DNS warning a combined 35 times.
That's not something we inferred, sshd flagged it itself.

**They're not going after random accounts either.** `deploy` (428 failed
attempts), `webadmin` (340), and `ops` (212) are the three most-targeted
usernames in the whole log, ahead of ordinary accounts like `alice` (204)
or `ben` (170), see Figure 2, `output/targeted_usernames.png`. All three
of those top accounts turn out to have `sudo` rights (we can see this in
`output/sudo_commands.csv`). `root` was hit 149 times too (109 failed +
40 invalid-user), though no `Accepted password for root` line shows up
anywhere in the extract, so at least on paper root itself held.

**And it comes in bursts, not a steady drip.** 7 July alone accounts for
1,161 failed attempts, more than the next two busiest days combined
(779 on the 8th), while quieter days like the 9th sit around 165
(`output/failed_attempts_over_time.csv`). Whatever's hitting `web01`
isn't a constant background hum. It ramps up and dies down.

## 3. What we think this means

Reading these together, the picture is fairly consistent: something
automated is repeatedly probing `web01`'s SSH login for weak credentials,
and it clearly prefers accounts that carry administrative privilege over
ordinary user accounts. That alone would be worth flagging. What makes it
more than a theoretical concern is that this pattern **already
succeeded once** inside the window we were given. The `deploy` account
was compromised, and the compromised session was used to run a privileged
command.

We want to be careful not to overclaim here, though. The log can't tell
us who was behind `203.0.113.77`, and it can't confirm anything the
attacker did beyond the one `sudo` command we can see. Actually, that
command, `systemctl restart apache2`, turns out to be one of the more
awkward findings in our analysis: it's run 60 other times across the
extract by accounts we have no reason to suspect, so on its own it looks
completely ordinary. If we hadn't traced the authentication pattern
leading up to it, we'd have no way of telling this particular instance
apart from routine admin work. That's arguably a finding in itself.
`web01` currently has no way to distinguish "attacker just logged in and
ran a command" from "admin logged in and ran a command."

## 4. Risk summary

We've written this up properly as an asset-focused risk matrix in the
appendix (`part1/risk_matrix.md`), including how confident we are in each
one and what we're still unsure about. In short, in priority order:

1. The `deploy` account compromise. This already happened, and `deploy`
   has sudo/root-equivalent access, so this is our top priority.
2. The broader credential-guessing campaign from the four high-volume
   IPs, which appears to be ongoing.
3. The apparent absence of any rate-limiting or lockout on SSH. Without
   this gap, the 117-attempt burst probably wouldn't have gotten anywhere.
4. Direct guessing against other privileged accounts (`root` especially),
   which hasn't succeeded yet but carries the worst impact if it does.
5. The difficulty of telling attacker activity apart from legitimate
   admin activity once someone's logged in.

## 5. What we'd recommend doing first

- Treat the `deploy` account as compromised right now, not as a
  hypothetical. Rotate its password immediately and go back through
  anything changed by or after that 23:47:04 session.
- Block or throttle the four IPs we flagged, at least until someone's
  had a chance to look into them properly. Two of them already tripped
  sshd's own break-in heuristic, which we think is enough to justify
  acting before a full investigation wraps up.
- Put some form of rate-limiting or account lockout on SSH password
  logins. fail2ban or similar would work, or moving to key-based auth
  entirely would remove password guessing as an option altogether.
- Add MFA (or just switch to keys) for the privileged accounts
  specifically: `root`, `deploy`, `webadmin`, `ops`, `sysadmin`. They're
  both the most targeted and the most damaging if guessed.
- Get some alerting in place for "burst of failures immediately followed
  by a success," because right now the only reason we caught this was by
  going back through the log after the fact.

## 6. Where we're not sure / what's missing

We should be upfront about the limits of what this log can tell us:

- This is one host over one week. We wouldn't want to assume the same
  pattern holds on other systems, or even on `web01` outside this window,
  and other groups working from the same base dataset may see
  completely different evidence in their extract.
- The IPs involved all sit in RFC 5737 documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which lines up with
  this being a sanitised teaching dataset. There's no point trying to
  geolocate or reputation-check them.
- We can't actually prove the `deploy` login was illegitimate from the
  log alone. The burst-then-success pattern is strong circumstantial
  evidence, but it isn't a confession. We're comfortable calling it a
  compromise, but a stricter reviewer might want to call it "probable"
  rather than "confirmed."
- There's no firewall, IDS, or file-integrity log in this extract, so we
  genuinely don't know whether some control already exists and got
  bypassed, versus nothing being there at all.
- Full details on how we handled edge cases while parsing (e.g. the
  `Failed password for invalid user X` vs `Failed password for X`
  distinction) are in `part1/README.md`. We didn't want to duplicate all
  of that here, but it's worth reading if you're trying to reproduce our
  numbers.

## Figures referenced

- **Figure 1**, `output/top_source_ips.png`: top 10 source IPs by failed
  password attempts (the required visualisation).
- **Figure 2**, `output/targeted_usernames.png`: top 10 targeted
  usernames by failed password attempts, privileged accounts highlighted
  in red (our chosen second visualisation).
- We also generated `output/failed_attempts_over_time.png` (daily failed
  attempts) as supporting evidence for the burst pattern discussed above.
  Worth including if we have room, otherwise it's still in the output
  folder for reference.
