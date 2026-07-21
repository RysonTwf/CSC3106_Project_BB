# Part 1 - Data-Driven Authentication Log Analysis (Group BB)

This is the reproducible-evidence part of our Part 1 submission for the
CSC3106 mini-project. We're Group BB, which per the spec (Table 1) means
we got `1_auth.log`.

## What you need

- Python 3.10+ (we built and tested this on 3.11)
- `matplotlib` (we used 3.10.x) for the PNG figures. Everything else is
  standard library, no pandas or anything heavier needed

```
pip install matplotlib
```

## Input file

By default the script looks for `1_auth.log.txt` in whatever directory
you run it from, but you can just pass a path instead. Our copy lives one
level up from this folder, at `../1_auth.log.txt`: 12,000 lines, host
`web01`, dated 6-12 July.

## Running it

From inside `part1/`:

```
python analysis.py ../1_auth.log.txt --outdir output
```

or, if you've copied the log into `part1/` itself as `1_auth.log.txt`,
just:

```
python analysis.py
```

`--outdir` defaults to `output/`, which is already populated from our
last run. Rerunning just overwrites it, so don't worry about stale
files hanging around.

The brute-force streak threshold (`--streak-threshold`, default 10), the
burst-grouping gap (`--burst-gap-minutes`, default 30), the assumed year for
timestamps (`--assumed-year`, default 2026), and the privileged-account list
(`--privileged-users`, comma-separated, default
`deploy,ops,root,sysadmin,webadmin`) are all argparse flags rather than
values you'd need to edit the script for, so a review team can re-tune them
against a different extract without touching the code - same reasoning as
the thresholds in `part2/detector.py`.

## What the script actually does

Broadly: it reads the raw file, splits every line into the syslog prefix
(timestamp/host/process/pid) and the message, figures out what kind of
event the message is, and then builds a handful of summary tables and
three charts out of that.

The event types we ended up needing, once we'd actually looked at enough
of the log to see what sshd logs in practice, are: `Accepted password`,
`Failed password` (including the annoying `... for invalid user ...`
variant, more on that below), `Invalid user`, `error: maximum
authentication attempts exceeded`, `Connection closed by authenticating
user ... [preauth]`, session open/close lines, and (this one we didn't
expect until we actually ran the script and saw a chunk of unmatched
lines) sshd's own `reverse mapping ... POSSIBLE BREAK-IN ATTEMPT!`
warning. `sudo` and `CRON` lines get handled separately since they're a
different process entirely.

### A few decisions we had to make, and why

- **What counts as a failed authentication attempt.** We're counting
  every `Failed password for ...` line, whether or not the username
  turned out to exist (so both `Failed password for invalid user X` and
  `Failed password for X` count). We kept `Invalid user X from IP`
  separate rather than folding it into the failed-password count. sshd
  logs that once per connection regardless of how many password guesses
  follow it, so counting both would have double-counted the same
  connection.
- **Usernames and IPs** come straight from the regex match, nothing
  normalised or guessed. So if a username in the log is a typo or
  something an attacker made up, it shows up verbatim rather than us
  trying to "clean" it.
- **Lines we couldn't classify** get written out to
  `output/unmatched_lines.txt` with their line numbers, so anyone
  checking our work can see exactly what got excluded. Right now that
  file is basically empty. We're at 0 unmatched out of 12,000 lines,
  though it took us a second pass to get there (we initially missed the
  break-in-warning lines entirely and had to add a pattern for them).
- **The brute-force detection was the trickiest part.** Our first attempt
  just counted "consecutive failed attempts before a success" per IP, but
  that gave a nonsense number, 1,120, because it never resets except on
  a success, so it was just summing failed attempts across the entire
  five-day gap between two unrelated events. We fixed this by grouping
  failed attempts into "bursts": if the gap between one failed attempt
  and the next (same IP) is under 30 minutes they're the same burst,
  otherwise a new one starts. That's what `BURST_GAP_MINUTES` at the top
  of the script controls. With that fix, the real number is 117 failed
  attempts in a 34-minute window immediately before the `deploy` account
  got compromised, a much more honest description of what actually
  happened. `BRUTE_FORCE_STREAK_THRESHOLD` (currently 10) is how big a
  burst has to be before we flag it; we picked that because ordinary IPs
  in this extract occasionally hit 5-6 failed attempts before a
  legitimate success (people mistyping passwords, presumably), so
  anything comfortably above that isn't explained by normal typos.
- **No year in the timestamps.** Syslog just gives you `Jul 06
  00:04:33`, no year, so we hard-coded one (`ASSUMED_YEAR` at the top of
  the file) since the whole extract is one contiguous week anyway. This
  only changes what date string gets printed. It doesn't affect
  ordering or which day something gets bucketed into.
- **Which accounts we call "privileged."** `root`, `deploy`, `webadmin`,
  `ops`, `sysadmin`. We picked this list because these are the accounts
  we actually saw running `sudo` commands in the log
  (`output/sudo_commands.csv`), not because we're claiming to know the
  organisation's real access model. It's a reporting convenience more
  than anything.

## What ends up in `output/`

| File | What it is |
|---|---|
| `summary_counts.csv` | Every event type we classified, plus how many lines we couldn't and the total line count. |
| `top_source_ips.csv` / `top_source_ips.png` | Top 10 IPs by failed-password count, with invalid-user/accepted/break-in-warning counts alongside for context. This is the required visualisation. |
| `targeted_usernames.csv` / `targeted_usernames.png` | Top 10 targeted usernames by failed-password count, privileged ones highlighted. Our chosen second visualisation. |
| `failed_attempts_over_time.csv` / `failed_attempts_over_time.png` | Failed attempts per day. We used this to back up the "it comes in bursts" point in the report. |
| `privileged_account_targeting.csv` | Just the privileged-account numbers pulled out separately. |
| `brute_force_success.csv` | The burst-then-success detection output. This is where the 117-attempt finding lives. |
| `sudo_commands.csv` | Every sudo command line we parsed, for checking what happened post-login. |
| `unmatched_lines.txt` | Whatever the parser couldn't classify (currently nothing). |

## Assumptions and limitations, so nobody assumes more than we found

- Everything here is about `web01` specifically, over this one week. We
  wouldn't generalise it to other hosts, and other groups working off the
  same base dataset will have different extracts and different findings.
- The source IPs are all in RFC 5737 documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24). Makes sense for a sanitised teaching
  dataset, but it also means geolocation/reputation lookups would be
  meaningless even if we wanted to do them.
- We can't actually prove from the log alone that the `deploy` login was
  illegitimate. The burst-then-success pattern is strong circumstantial
  evidence, but it's not a smoking gun in the strictest sense.
- The one sudo command we can see from the compromised session
  (`systemctl restart apache2`) is identical to commands run by
  legitimate accounts elsewhere in the log, so command content alone
  wouldn't have told us anything was wrong. The authentication pattern
  is the only signal we actually have.
- An auth.log extract doesn't give us any network- or firewall-level
  evidence, so our findings are limited to whatever SSH/PAM/sudo logging
  happens to record.
