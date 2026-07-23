# CSC3106 Mini-Project (Group BB)

This is Group BB's submission for the CSC3106 mini-project. We were assigned
`1_auth.log`, a 12,000-line OpenSSH auth log extract from host `web01`
covering 6-12 July. Part 1 is a reproducible, script-driven analysis of that
extract; its headline finding is that `203.0.113.77` fired 117 uninterrupted
password guesses at the `deploy` account in a 34-minute window on 11 July and
got in. Part 2 is a technical defensive response built directly off that
finding: a rate-limit/lockout policy, a detection layer, and SSH hardening,
each tested against the same extract rather than just proposed on paper.

The written report (submitted separately, per the assignment's format) cites
every figure and table below by filename so a marker can check any claim
against the code and data that produced it.

## Layout

```
1_auth.log.txt              our assigned log extract (12,000 lines, host web01, 6-12 Jul)
part1/                      data-driven analysis: parsing, summary tables, 3 figures
  analysis.py                the parser + analysis script
  risk_matrix.md              asset-focused risk matrix, cross-referenced to part1/output/
  output/                     generated CSVs and PNGs (rerun analysis.py to regenerate)
  README.md                   parsing decisions, output-file reference, assumptions
part2/                      technical defensive response to the Part 1 findings
  detector.py                  "detect" layer: three alerting rules
  simulate_lockout.py          tests the "prevent" layer against the real extract
  authlog_parsing.py           parsing shared with Part 1, kept identical on purpose
  config/                      "prevent"/"preserve" layer configs (fail2ban, sshd, rsyslog)
  output/                     generated CSVs and PNGs (rerun detector.py / simulate_lockout.py)
  README.md                   detection-rule thresholds, output-file reference, assumptions
images/                     copies of the PNG figures embedded in the written report
SIT_CSC3106_Mini_Project_and_Labs-2.pdf   the assignment brief (not our submission)
```

## How the two parts connect

Part 1's risk matrix rates Risk 3 as the structural gap behind everything
else: `web01`'s SSH password login has no working rate limit or lockout, so
117 guesses in a row simply never got interrupted. Part 2 is built to close
that specific gap, and the response is tested (not just asserted) by
replaying the same extract through the proposed fail2ban policy in
`simulate_lockout.py`. That closes the loop back to Risk 1 (the `deploy`
compromise) and Risk 2 (the wider guessing campaign) in the same risk matrix.

## Quick start

From the repository root, with Python 3.10+ (see `part1/README.md` for the
exact `pip install` line):

```
cd part1
python analysis.py ../1_auth.log.txt --outdir output

cd ../part2
python detector.py ../1_auth.log.txt --plot
python simulate_lockout.py ../1_auth.log.txt --plot
```

That regenerates every CSV and PNG cited by the report, in both `part1/output/`
and `part2/output/`.

## Where to go for what

- Parsing decisions, argparse flags, and the full output-file reference for
  Part 1: see `part1/README.md`.
- Detection-rule thresholds, the fail2ban policy tested, and the full
  output-file reference for Part 2: see `part2/README.md`.
- Python version and package requirements are documented in `part1/README.md`
  (same requirements apply to both parts).
