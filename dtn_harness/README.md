# DTN Anti-Spam Run Harness

One command runs the full three-run experiment (Run 1 / Run 2 / Run 3) for one
anti-spam tool over the Earth–Moon DTN testbed, prints live progress, and saves
every artifact to disk. It exists so a future student can reproduce the
SpamAssassin / rspamd / Razor evaluations without driving each run by hand.

It automates everything that *can* be automated from the Mac. A few things are
testbed- or tool-specific and are called out below as **manual steps** or
**`TODO(verify)`** — do those once, then the harness handles the rest.

```
dtn_harness/
├── run.py        ← the single entry script
├── config.yaml   ← the single config file (VMs, credentials, every command)
└── README.md     ← this file
```

---

## What it does

For the selected tool it runs three runs and, for each one:

1. **Reset** — cold-restart `unbound` (clears the DNS cache *and* the infra-cache
   `rto` state), empty the maildir, reset the tool, clear any netem.
2. **Configure** — apply the run's tool profile (default vs reduced-timeout) and,
   for delayed runs, apply the netem delay on the relay.
3. **RTT gate** — ping Earth from the Moon node and **abort the run** if the RTT
   is outside the expected window. This is what stops a silently-failed netem
   from producing data that looks valid. *(This is the direct fix for the Run 3
   contamination described in `results/*.tex`.)*
4. **Capture** — start `tcpdump` on the relay and the Moon node (excluding
   management SSH so the DNS-vs-bundle bandwidth tables stay clean).
5. **Send + scan** — push detached agents: a sender that streams the corpus over
   BPMail at a fixed pace, and a receiver that watches the maildir and scans each
   message **serially** (so scan time is measurable and queue-wait is recorded
   separately).
6. **Drain + reconcile** — wait for the last bundles, then compute which
   Message-IDs went missing.
7. **Health check** — read the resolver `rto`; if it hit the 120 000 ms ceiling
   the run is flagged **SUSPECT** in its manifest (you find out that evening, not
   in analysis three weeks later).
8. **Collect** — pull all CSVs, raw scan outputs, pcaps and stats to the Mac and
   write `manifest.json`. A unified `per_email.csv` (same schema for all tools)
   is produced so the analysis pipeline is shared.

At the end it writes `summary.json` and prints a per-run table, then powers the
VMs down.

Results land in `~/Desktop/DTN_runs/<tool>_<date>/` (configurable):

```
<tool>_<date>/
├── session.log
├── summary.json
├── run1/ run2/ run3/
│   ├── manifest.json      per_email.csv      missing_ids.txt
│   ├── tc_qdisc.txt       infra_before.txt   infra_after.txt   unbound_stats.txt
│   ├── mail1/ (sent.csv, agent.log)
│   ├── mail2/ (results.csv, out/*.out, *.pcap, agent.log)
│   └── space/ (*.pcap)
```

---

## One-time setup on the Mac

```bash
pip install paramiko pyyaml
```

Then edit **`config.yaml`**:

- Fill in each VM's `host`, `user`, `password`, and the exact `utm_name` shown by
  `utmctl list`.
- Set `active_tool` to `rspamd`, `spamassassin`, or `razor`.
- Work through every field marked **`TODO(verify)`** (see the checklist below).

## One-time setup on the VMs

- **Passwordless sudo.** The harness runs `tc`, `tcpdump`, `systemctl` and
  `unbound-control` with `sudo`. Give the VM users NOPASSWD sudo for those (or the
  simplest: `<user> ALL=(ALL) NOPASSWD:ALL` in a test VM via `visudo`).
- **SSH reachable.** `space` is reached directly; `mail1`/`mail2` are tunnelled
  through `space` automatically (their `proxy: space` in config).
- **Corpus present** on `mail1` at `corpus_dir` (the 681-message set, minus
  `email_00444.eml`).
- **Mail path working** — Postfix/Dovecot delivering received mail into
  `mail2`'s maildir, and `bpmailrecv` feeding the submission agent.

---

## Running it

```bash
python3 run.py                      # full three-run pass for active_tool
python3 run.py --tool razor         # override the tool
python3 run.py --corpus-limit 5     # SMOKE TEST first — 5 emails end to end
python3 run.py --runs run2,run3     # subset of runs
python3 run.py --boot-only          # boot VMs and stop
python3 run.py --verify-only        # run the gates and stop
python3 run.py --shutdown-only      # power VMs down
```

**Always run `--corpus-limit 5` once first.** It exercises the entire flow
(boot → gates → send → scan → collect → shutdown) in minutes and surfaces any
wrong path or command before you commit to an ~18-hour full pass.

**Time budget:** 681 emails × 30 s pacing ≈ 5–6 h per delayed run; three runs
≈ 18–20 h including boot, drain and collection. Plan a full pass as overnight
plus a day. The Mac is kept awake with `caffeinate` for the duration.

---

## `TODO(verify)` checklist (in `config.yaml`)

These are testbed facts the harness cannot know. Wrong values fail loudly (good)
or produce an invalid run — check them before the first real pass:

| Field | What to confirm |
|---|---|
| `nodes.*.password`, `utm_name` | real credentials and exact UTM VM names |
| `nodes.space.delay_if` / `ifb_if` | the interface netem attaches to on the relay |
| `nodes.mail1.corpus_dir` / `corpus_glob` | where the `.eml` corpus lives and its filename pattern |
| `nodes.mail2.maildir` | where delivered mail actually lands |
| `dtn.send_cmd` | BPMail profile id / dest EID (`bpmailsend -t 26 <profile> <dest>`) |
| `commands.delay_apply` / `delay_clear` | your exact `tc netem`/`ifb` sequence |
| `commands.ion_*` + `ion_restart_enabled` | ION 4.1.4 start/stop/probe (off by default) |
| `tools.spamassassin.profiles` | your `local.cf` path |
| `tools.rspamd.profiles` | your `local.d` override path |
| `tools.razor.core_pm` | path to `Razor2::Client::Core.pm` (see below) |

---

## Manual steps that cannot be fully automated

### Razor reduced-timeout (Run 3)
Razor exposes **no timeout knob** in `razor-agent.conf` — the connect timeout is
a hardcoded `Timeout => 20` in `Razor2::Client::Core.pm`. Run 3 needs it below
the 2.6 s RTT. The harness patches it with `sed` (20 → 2, keeping a `.orig`
backup) **if `tools.razor.core_pm` points at the right file**. Find it with:

```bash
perl -MRazor2::Client::Core -e 'print $INC{"Razor2/Client/Core.pm"}, "\n"'
```

Put that path in `config.yaml`. If the `sed` doesn't match your version's
formatting, edit the two `Timeout => 20` lines by hand and set both to `2`.

### rspamd on Apple-Silicon VMs (SVE2 crash)
On ARM64 UTM guests, rspamd can crash with `SIGILL` in Vectorscan's SVE2 path
(the guest mis-advertises SVE2). If you hit this, install the `getauxval`
`LD_PRELOAD` shim and load it into the rspamd service, as documented in
`results/rspamd_dtn_evaluation.tex` (§"Platform crash and fix"). The harness does
not install the shim — do it once during VM setup.

### SpamAssassin resolver tuning
Stock `unbound` on Ubuntu 22.04 drops delayed answers
(`discard-timeout` 1900 ms < 2.6 s RTT). Set `discard-timeout: 9000` and
`infra-cache-min-rtt: 4000` in `unbound.conf` before running — otherwise every
delayed DNSBL answer is discarded and detection collapses for reasons unrelated
to the tool. Details in `results/spamassassin_dtn_runs.tex`.

---

## Notes / limitations

- **Parsing is best-effort.** Raw scan output is always saved to
  `mail2/out/*.out`, so `per_email.csv` can be regenerated with a refined parser
  without re-running anything. The three parsers live in `run.py`
  (`parse_rspamd` / `parse_spamassassin` / `parse_razor`) — check them against
  your tool versions' output format.
- **Blocklist drift.** The harness runs Run 2 and Run 3 back to back so their
  per-message comparison is clean; Run 1 is unavoidably hours from Run 3, so
  baseline-vs-delayed flip analysis stays drift-limited (see the results docs).
- **DCC** is intentionally not implemented. Adding a fourth tool is one block in
  `config.yaml` under `tools:` plus a parser function — it is not otherwise
  wired in.
- This harness was written against the testbed described in the results
  write-ups but has **not** been executed against a live testbed from this
  directory. Treat the first `--corpus-limit 5` run as the real integration test.
