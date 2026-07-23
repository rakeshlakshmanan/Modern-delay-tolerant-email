#!/usr/bin/env python3
# =============================================================================
# DTN Anti-Spam Run Harness  --  single entry script
# =============================================================================
# One command runs the whole three-run experiment (Run 1 / Run 2 / Run 3) for
# one anti-spam tool over the Earth-Moon DTN testbed, prints live progress, and
# saves every artifact to the results directory.
#
#   python3 run.py                      # run the tool named in config.yaml
#   python3 run.py --tool razor         # override the tool
#   python3 run.py --runs run2,run3     # only some runs
#   python3 run.py --corpus-limit 5     # quick smoke test (first 5 emails)
#   python3 run.py --boot-only          # boot the VMs and stop
#   python3 run.py --verify-only        # run the pre-flight gates and stop
#   python3 run.py --shutdown-only      # power the VMs down and stop
#
# Requirements on the Mac:   pip install paramiko pyyaml
# See README.md for testbed prerequisites (passwordless sudo, corpus, etc).
# =============================================================================

import argparse
import datetime as dt
import io
import json
import os
import posixpath
import shutil
import subprocess
import sys
import time

# ---- third-party (imported lazily so we can print a friendly message) -------
try:
    import yaml
except ImportError:
    sys.exit("Missing dependency 'pyyaml'.  Run:  pip install pyyaml paramiko")
try:
    import paramiko
except ImportError:
    sys.exit("Missing dependency 'paramiko'.  Run:  pip install paramiko pyyaml")


HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = "~/dtn_harness_agent"          # working dir created on each VM
RUN_IDS = ["run1", "run2", "run3"]


# =============================================================================
# Logging  --  timestamped, to stdout (live) and to a session log file
# =============================================================================
class Log:
    def __init__(self):
        self.fh = None

    def open(self, path):
        self.fh = open(path, "a", buffering=1)

    def __call__(self, msg, level="INFO"):
        line = "%s  %-5s %s" % (dt.datetime.utcnow().strftime("%H:%M:%S"), level, msg)
        print(line, flush=True)
        if self.fh:
            self.fh.write(line + "\n")


log = Log()


class Abort(Exception):
    """Raised by a failed gate. Aborts the current run (or the whole session)."""


# =============================================================================
# Config loading  --  fail loudly, never silently default anything that
# affects the experiment.
# =============================================================================
def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        sys.exit("config.yaml did not parse to a mapping")
    return cfg


def req(d, *keys):
    """Fetch a required nested key or exit with a clear message."""
    cur = d
    trail = []
    for k in keys:
        trail.append(str(k))
        if not isinstance(cur, dict) or k not in cur:
            sys.exit("config.yaml: missing required key: %s" % ".".join(trail))
        cur = cur[k]
    return cur


def expand(p):
    return os.path.expanduser(os.path.expandvars(p))


# =============================================================================
# Remote transport  --  paramiko, with optional jump through a proxy node.
# Every remote interaction in the harness goes through this class.
# =============================================================================
class Node:
    def __init__(self, name, ncfg, ssh_cfg, proxy=None):
        self.name = name
        self.host = req(ncfg, "host")
        self.user = req(ncfg, "user")
        self.password = req(ncfg, "password")
        self.cfg = ncfg
        self.ssh_cfg = ssh_cfg
        self.proxy = proxy           # another connected Node, or None
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sock = None
        if self.proxy is not None:
            ptrans = self.proxy.client.get_transport()
            sock = ptrans.open_channel(
                "direct-tcpip", (self.host, 22), ("127.0.0.1", 0)
            )
        self.client.connect(
            self.host,
            username=self.user,
            password=self.password,
            sock=sock,
            timeout=self.ssh_cfg.get("connect_timeout_s", 30),
            banner_timeout=self.ssh_cfg.get("connect_timeout_s", 30),
            auth_timeout=self.ssh_cfg.get("connect_timeout_s", 30),
            allow_agent=False,
            look_for_keys=False,
        )
        self.client.get_transport().set_keepalive(self.ssh_cfg.get("keepalive_s", 30))
        return self

    def run(self, cmd, timeout=120, check=False):
        """Run a command, wait for it, return (rc, stdout, stderr)."""
        wrapped = "bash -lc %s" % _shquote(cmd)
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise Abort("[%s] command failed (rc=%d): %s\n%s" % (self.name, rc, cmd, err.strip()))
        return rc, out, err

    def run_detached(self, cmd):
        """Launch a long-running command and return immediately (nohup)."""
        full = "nohup bash -lc %s >/dev/null 2>&1 &" % _shquote(cmd)
        self.client.exec_command(full)

    def put_text(self, content, remote):
        sftp = self.client.open_sftp()
        try:
            self._sftp_mkdirs(sftp, posixpath.dirname(remote))
            with sftp.file(remote, "w") as fh:
                fh.write(content)
            sftp.chmod(remote, 0o755)
        finally:
            sftp.close()

    def get(self, remote, local):
        sftp = self.client.open_sftp()
        try:
            sftp.get(remote, local)
        finally:
            sftp.close()

    def pull_dir(self, remote_dir, local_dir):
        """Tar a remote dir, pull the tarball, extract locally."""
        os.makedirs(local_dir, exist_ok=True)
        tar = "/tmp/dtnh_%s_%d.tgz" % (self.name, int(time.time()))
        rc, _, err = self.run("tar czf %s -C %s . 2>/dev/null" % (tar, remote_dir))
        if rc != 0:
            log("[%s] nothing to pull from %s" % (self.name, remote_dir), "WARN")
            return
        local_tar = os.path.join(local_dir, "_pull.tgz")
        self.get(tar, local_tar)
        self.run("rm -f %s" % tar)
        subprocess.run(["tar", "xzf", local_tar, "-C", local_dir], check=False)
        os.remove(local_tar)

    def alive(self):
        try:
            rc, _, _ = self.run("true", timeout=15)
            return rc == 0
        except Exception:
            return False

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

    @staticmethod
    def _sftp_mkdirs(sftp, path):
        parts, cur = path.strip("/").split("/"), ""
        for p in parts:
            cur += "/" + p
            try:
                sftp.stat(cur)
            except IOError:
                sftp.mkdir(cur)


def _shquote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


# =============================================================================
# Local host operations  --  utmctl, caffeinate, disk checks
# =============================================================================
def local(cmd, timeout=120):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def utmctl(cfg, *args):
    exe = expand(req(cfg, "host", "utmctl"))
    return local('"%s" %s' % (exe, " ".join(args)))


# =============================================================================
# Embedded agent scripts  --  pushed to each VM, launched detached.
# They write sentinel files the host polls (STATUS / progress / *.csv).
# =============================================================================
SENDER_SH = r'''#!/usr/bin/env bash
set -u
RUN_ID="$1"
BASE="AGENT_DIR/$RUN_ID"
source "$BASE/env.sh"
STATUS="$BASE/STATUS"; PROG="$BASE/progress"; LOG="$BASE/agent.log"; SENT="$BASE/sent.csv"
echo RUNNING > "$STATUS"
finish(){ if [ "$1" -eq 0 ]; then echo DONE > "$STATUS"; else echo FAILED > "$STATUS"; fi; }
trap 'finish $?' EXIT
echo "seq,filename,message_id,sent_utc,exit_code" > "$SENT"
cd "$ION_DIR" 2>/dev/null || true   # bpmailsend runs in the ION node dir

# Build the file list: sorted glob, minus excludes, minus limit.
mapfile -t ALL < <(ls "$CORPUS_DIR"/$CORPUS_GLOB 2>/dev/null | sort)
FILES=()
for f in "${ALL[@]}"; do
  bn=$(basename "$f")
  skip=0
  for e in $EXCLUDES; do [ "$bn" = "$e" ] && skip=1; done
  [ "$skip" -eq 0 ] && FILES+=("$f")
done
if [ "$LIMIT" -gt 0 ]; then FILES=("${FILES[@]:0:$LIMIT}"); fi
TOTAL=${#FILES[@]}
echo "sending $TOTAL messages, pacing ${PACING}s" >>"$LOG"

seq=0
for f in "${FILES[@]}"; do
  seq=$((seq+1))
  bn=$(basename "$f")
  export FILE="$f"
  mid=$(grep -i -m1 '^Message-ID:' "$f" | tr -d '\r\n' | cut -d' ' -f2-)
  sent=$(date -u +%s.%N)
  eval "$SEND_CMD"
  rc=$?
  echo "$seq,$bn,$mid,$sent,$rc" >> "$SENT"
  echo "$seq/$TOTAL" > "$PROG"
  [ "$seq" -lt "$TOTAL" ] && sleep "$PACING"
done
echo "sender done" >>"$LOG"
'''

RECEIVER_SH = r'''#!/usr/bin/env bash
set -u
RUN_ID="$1"
BASE="AGENT_DIR/$RUN_ID"
source "$BASE/env.sh"
STATUS="$BASE/STATUS"; PROG="$BASE/progress"; LOG="$BASE/agent.log"
RESULTS="$BASE/results.csv"
mkdir -p "$BASE/out"
echo RUNNING > "$STATUS"
finish(){ if [ "$1" -eq 0 ]; then echo DONE > "$STATUS"; else echo FAILED > "$STATUS"; fi; }
trap 'finish $?' EXIT
echo "seq,message_id,arrived_utc,scan_start_utc,scan_end_utc,scan_s,exit_code" > "$RESULTS"
cd "$ION_DIR" 2>/dev/null || true   # bpmailrecv runs in the ION node dir

# Blocking bpmailrecv loop: receive one bundle, scan it, log timing, repeat.
# bpmailrecv is serialized by design, so scanning is inherently one-at-a-time.
# RECV_CMD is wrapped in `timeout` so an idle receiver can re-check the STOP
# sentinel the host drops when the run is draining.
seq=0
while true; do
  [ -e "$BASE/STOP" ] && break
  RAW=$(timeout "$RECV_TIMEOUT" bash -c "$RECV_CMD")
  if [ -z "$RAW" ]; then
    continue      # timed out with no bundle; re-check STOP and wait again
  fi
  arrived=$(date -u +%s.%N)
  seq=$((seq+1))
  num=$(printf '%05d' "$seq")
  eml="$BASE/out/${num}.eml"
  printf '%s' "$RAW" > "$eml"
  mid=$(grep -i -m1 '^Message-ID:' "$eml" | tr -d '\r\n' | cut -d' ' -f2-)
  export FILE="$eml"
  outf="$BASE/out/${num}.out"
  start=$(date -u +%s.%N)
  eval "$SCAN_CMD" > "$outf" 2>&1
  rc=$?
  end=$(date -u +%s.%N)
  dur=$(awk "BEGIN{printf \"%.3f\", $end-$start}")
  printf '%s,%s,%s,%s,%s,%s,%s\n' "$seq" "$mid" "$arrived" "$start" "$end" "$dur" "$rc" >> "$RESULTS"
  echo "$seq/$EXPECTED" > "$PROG"
  [ "$EXPECTED" -gt 0 ] && [ "$seq" -ge "$EXPECTED" ] && break
done
echo "receiver done: scanned $seq" >>"$LOG"
'''


# =============================================================================
# Per-tool output parsers (run on the host over the pulled scan outputs).
# Raw output is always saved, so parsing can be refined later without re-running.
# =============================================================================
import re

def parse_rspamd(text, rc):
    """Parse `rspamc --mime` output (adds X-Spam-* headers to the message)."""
    verdict, score, thr, rules = "", "", "", []
    m = re.search(r"X-Spam-Score:\s*([-\d.]+)\s*/\s*([-\d.]+)", text)
    if not m:                       # fall back to plain `rspamc` "Score: x / y"
        m = re.search(r"Score:\s*([-\d.]+)\s*/\s*([-\d.]+)", text)
    if m:
        score, thr = m.group(1), m.group(2)
    # Verdict from the action: "no action"/"greylist" are not spam-flagged;
    # "add header", "rewrite subject", "reject" are.
    ma = re.search(r"X-Spam-Action:\s*(.+)", text)
    if ma:
        action = ma.group(1).strip().lower()
        verdict = "NO" if action in ("no action", "no_action", "greylist") else "YES"
    elif score and thr:
        try:
            verdict = "YES" if float(score) >= float(thr) else "NO"
        except ValueError:
            pass
    # Symbols: the X-Spam-Symbols header is comma-separated and may fold across
    # continuation lines (leading whitespace).
    ms = re.search(r"X-Spam-Symbols:\s*((?:.*)(?:\n[ \t]+.*)*)", text)
    if ms:
        rules = [s.strip() for s in re.split(r"[,\s]+", ms.group(1)) if s.strip()]
    elif re.search(r"^Symbol:", text, re.M):
        rules = re.findall(r"Symbol:\s*([A-Z0-9_]+)", text)
    return verdict, score, thr, rules

def parse_spamassassin(text, rc):
    """Parse the X-Spam-Status header, which folds across continuation lines."""
    verdict, score, thr, rules = "", "", "", []
    m = re.search(r"^X-Spam-Status:\s*(.*(?:\n[ \t]+.*)*)", text, re.M)
    if not m:
        return verdict, score, thr, rules
    hdr = re.sub(r"\n[ \t]+", "", m.group(1))     # RFC-unfold: join continuation lines
    mv = re.match(r"\s*(Yes|No)", hdr, re.I)
    if mv:
        verdict = "YES" if mv.group(1).lower() == "yes" else "NO"
    ms = re.search(r"score=([-\d.]+)", hdr)
    if ms:
        score = ms.group(1)
    mr = re.search(r"required=([-\d.]+)", hdr)
    if mr:
        thr = mr.group(1)
    mt = re.search(r"tests=([A-Za-z0-9_,]+)", hdr)  # ends at the space before autolearn=
    if mt:
        rules = [t for t in mt.group(1).split(",") if t and t != "none"]
    return verdict, score, thr, rules

def parse_razor(text, rc):
    # exit 0 = catalogued (spam), 1 = not catalogued (ham), 2 = network error
    if rc == 0:
        return "YES", "", "", []
    if rc == 1:
        return "NO", "", "", []
    return "ERROR", "", "", []

PARSERS = {"rspamd": parse_rspamd, "spamassassin": parse_spamassassin, "razor": parse_razor}


# =============================================================================
# The harness
# =============================================================================
class Harness:
    def __init__(self, cfg, tool_name, results_root):
        self.cfg = cfg
        self.tool_name = tool_name
        self.tool = req(cfg, "tools", tool_name)
        self.results_root = results_root
        self.nodes = {}          # name -> Node (connected)
        self.summary = {}

    # ---- connection lifecycle ------------------------------------------------
    def connect_all(self):
        ssh_cfg = self.cfg.get("ssh", {})
        ncfgs = req(self.cfg, "nodes")
        order = sorted(ncfgs, key=lambda n: ncfgs[n].get("boot_order", 99))
        for name in order:
            ncfg = ncfgs[name]
            proxy_name = ncfg.get("proxy")
            proxy = self.nodes.get(proxy_name) if proxy_name else None
            if proxy_name and proxy is None:
                raise Abort("node %s lists proxy %s which is not connected yet" % (name, proxy_name))
            node = Node(name, ncfg, ssh_cfg, proxy=proxy)
            log("connecting to %s (%s)%s" % (name, ncfg["host"],
                                             " via %s" % proxy_name if proxy_name else ""))
            node.connect()
            self.nodes[name] = node

    def close_all(self):
        for n in reversed(list(self.nodes.values())):
            n.close()

    def n(self, name):
        return self.nodes[name]

    # ---- Phase 0: host preflight --------------------------------------------
    def preflight(self):
        log("=== Phase 0: host preflight ===")
        rc, out, _ = utmctl(self.cfg, "list")
        if rc != 0:
            raise Abort("utmctl not runnable; check host.utmctl path")
        for name, ncfg in req(self.cfg, "nodes").items():
            if ncfg["utm_name"] not in out:
                log("VM '%s' not listed by utmctl (names: check `utmctl list`)" % ncfg["utm_name"], "WARN")
        results_dir = expand(req(self.cfg, "host", "results_dir"))
        os.makedirs(results_dir, exist_ok=True)
        free_gb = shutil.disk_usage(results_dir).free / 1e9
        need = req(self.cfg, "host", "min_free_gb")
        if free_gb < need:
            raise Abort("results disk has %.1f GB free, need >= %d" % (free_gb, need))
        log("results dir: %s  (%.1f GB free)" % (results_dir, free_gb))

    # ---- Phase 1: boot -------------------------------------------------------
    def boot(self):
        log("=== Phase 1: boot VMs ===")
        ncfgs = req(self.cfg, "nodes")
        order = sorted(ncfgs, key=lambda n: ncfgs[n].get("boot_order", 99))
        for name in order:
            vm = ncfgs[name]["utm_name"]
            rc, out, _ = utmctl(self.cfg, "status", _shquote(vm))
            if "started" not in out.lower():
                log("starting VM %s ..." % vm)
                utmctl(self.cfg, "start", _shquote(vm))
        # connect (which also proves SSH is up); retry until boot timeout
        deadline = time.time() + req(self.cfg, "host", "boot_ssh_timeout_s")
        while True:
            try:
                self.connect_all()
                break
            except Exception as e:
                if time.time() > deadline:
                    raise Abort("VMs did not become SSH-reachable in time: %s" % e)
                log("waiting for SSH ... (%s)" % e, "WARN")
                self.close_all()
                self.nodes = {}
                time.sleep(10)
        log("all three VMs reachable over SSH")

    # ---- Phase 2: verification gates ----------------------------------------
    def verify(self):
        log("=== Phase 2: testbed verification ===")
        cmds = req(self.cfg, "commands")

        # clocks
        host_now = time.time()
        for name in self.nodes:
            rc, out, _ = self.n(name).run("date -u +%s.%N")
            if rc != 0:
                raise Abort("cannot read clock on %s" % name)
            offset = abs(float(out.strip()) - host_now)
            lvl = "INFO" if offset < 0.1 else "WARN"
            log("clock offset %s: %.3f s" % (name, offset), lvl)
            if offset > 1.0:
                raise Abort("clock on %s is >1s off host; sync NTP first" % name)

        # resolver on mail2
        if self.n("mail2").run(cmds["unbound_isactive"])[1].strip() != "active":
            raise Abort("unbound is not active on mail2")
        if self.n("mail2").run(cmds["dig_probe"])[0] != 0:
            raise Abort("resolver on mail2 failed a test lookup")
        log("resolver on mail2: active and resolving")

        # ION (optional)
        if cmds.get("ion_restart_enabled"):
            self._ion_restart()

        # tool present
        rc, out, _ = self.n("mail2").run(self.tool["version_cmd"])
        if rc != 0 or not out.strip():
            raise Abort("tool '%s' not found on mail2 (version_cmd failed)" % self.tool_name)
        self.tool_version = out.strip().splitlines()[0]
        log("tool: %s" % self.tool_version)

    def _ion_dir(self, name):
        return req(self.n(name).cfg, "ion_dir")

    def _ion_restart(self):
        cmds = req(self.cfg, "commands")
        ncfgs = req(self.cfg, "nodes")
        order = sorted(ncfgs, key=lambda n: ncfgs[n].get("boot_order", 99))
        log("restarting ION on all nodes (resets the 24h contact window)")
        for name in reversed(order):
            self.n(name).run(cmds["ion_stop"].replace("{ion_dir}", self._ion_dir(name)), timeout=60)
        for name in order:                       # relay first, then endpoints
            self.n(name).run(cmds["ion_start"].replace("{ion_dir}", self._ion_dir(name)), timeout=60)
            time.sleep(3)
        rc, out, _ = self.n("mail2").run(
            cmds["ion_probe"].replace("{ion_dir}", self._ion_dir("mail2")), timeout=30)
        log("ION restarted; mail2 probe: %s" % out.strip())

    # ---- Phase 3: one run ----------------------------------------------------
    def do_run(self, run_id, corpus_limit):
        rcfg = req(self.tool, "runs", run_id)
        delay = req(rcfg, "delay")
        profile = req(rcfg, "profile")
        pacing = req(rcfg, "pacing_s")
        cmds = req(self.cfg, "commands")
        net = req(self.cfg, "network")
        space, mail1, mail2 = self.n("space"), self.n("mail1"), self.n("mail2")
        rdir = os.path.join(self.results_root, run_id)
        os.makedirs(rdir, exist_ok=True)

        log("=== Run %s  (delay=%s, profile=%s, pacing=%ss) ===" % (run_id, delay, profile, pacing))
        started = dt.datetime.utcnow()

        # -- 3a reset ----------------------------------------------------------
        log("reset: cold resolver, clear prior agent state, tool reset, clear netem")
        mail2.run(cmds["unbound_restart"], timeout=60)   # cold DNS + infra cache
        mail2.run("rm -rf %s/%s" % (AGENT_DIR, run_id))
        mail1.run("rm -rf %s/%s" % (AGENT_DIR, run_id))
        mail2.run(self.tool.get("reset_cmd", "true"), timeout=120)   # e.g. start rspamd
        self._delay_clear(space)
        _, infra0, _ = mail2.run(cmds["unbound_dump_infra"])
        _write(os.path.join(rdir, "infra_before.txt"), infra0)

        # -- 3b apply configuration -------------------------------------------
        prof_cmd = req(self.tool, "profiles", profile)
        prof_cmd = self._fmt_tool(prof_cmd)
        log("apply tool profile '%s'" % profile)
        rc, out, err = mail2.run(prof_cmd, timeout=120)
        if rc != 0:
            log("profile command returned rc=%d: %s" % (rc, err.strip()), "WARN")
        if delay:
            self._delay_apply(space)
        _, qdisc, _ = space.run(self._fmt_iface(cmds["delay_show"]))
        _write(os.path.join(rdir, "tc_qdisc.txt"), qdisc)

        # -- 3c RTT gate  (the most important gate) ---------------------------
        rtt = self._measure_rtt()
        window = net["rtt_delayed_window_ms"] if delay else net["rtt_nodelay_window_ms"]
        log("measured RTT: %.0f ms  (gate %s)" % (rtt, window))
        if not (window[0] <= rtt <= window[1]):
            raise Abort("RTT %.0f ms outside gate %s for %s -- aborting run" % (rtt, window, run_id))

        # -- 3d captures -------------------------------------------------------
        cap_start = dt.datetime.utcnow().isoformat()
        for host, tag in ((space, "space"), (mail2, "mail2")):
            out_tmpl = "%s/%s/%s_%s_%%03d.pcap" % (AGENT_DIR, run_id, tag, run_id)
            host.run("mkdir -p %s/%s" % (AGENT_DIR, run_id))
            host.run_detached(cmds["tcpdump"].replace("{out}", out_tmpl))
        log("packet captures started")

        # -- 3e push + launch agents ------------------------------------------
        expected = self._expected_count(corpus_limit)
        self._deploy_agents(run_id, pacing, corpus_limit, expected)
        log("launching receiver, then sender (expected %d messages)" % expected)
        mail2.run_detached("%s/receiver.sh %s" % (AGENT_DIR, run_id))
        time.sleep(3)
        mail1.run_detached("%s/sender.sh %s" % (AGENT_DIR, run_id))

        # -- 3f poll -----------------------------------------------------------
        self._poll(run_id, expected, started)

        # -- 3g drain ----------------------------------------------------------
        self._drain(run_id, expected)

        # -- 3i stop captures + health ----------------------------------------
        for host in (space, mail2):
            host.run("sudo pkill -f 'tcpdump -i any' 2>/dev/null || true")
        health = self._health(run_id, rdir)

        # -- 3j collect + manifest --------------------------------------------
        self._collect(run_id, rdir)
        counts = self._reconcile(rdir, corpus_limit)
        per_email = self._build_unified_csv(run_id, rdir)
        manifest = {
            "experiment": os.path.basename(self.results_root),
            "run_id": run_id,
            "tool": {"name": self.tool_name, "version": getattr(self, "tool_version", ""),
                     "profile": profile},
            "network": {"delay": delay, "measured_rtt_ms": round(rtt),
                        "gate_window_ms": window},
            "timing": {"start_utc": started.isoformat(),
                       "end_utc": dt.datetime.utcnow().isoformat(),
                       "capture_start_utc": cap_start,
                       "pacing_s": pacing},
            "counts": counts,
            "health": health,
        }
        status = "SUSPECT" if health.get("max_rto_ms", 0) >= 120000 else "OK"
        manifest["status"] = status
        _write(os.path.join(rdir, "manifest.json"), json.dumps(manifest, indent=2))
        log("run %s complete -- status %s" % (run_id, status),
            "WARN" if status == "SUSPECT" else "INFO")

        self.summary[run_id] = {"status": status, "counts": counts,
                                "health": health, "scan_stats": per_email}
        # clean netem so the next run starts from a known state
        self._delay_clear(space)
        return status

    # ---- run helpers ---------------------------------------------------------
    def _fmt_iface(self, s):
        sc = self.n("space").cfg
        return (s.replace("{delay_if}", sc["delay_if"])
                 .replace("{ifb_if}", sc["ifb_if"])
                 .replace("{delay_ms}", str(req(self.cfg, "network", "one_way_delay_ms"))))

    def _fmt_tool(self, s):
        # substitute tool-specific placeholders (e.g. Razor's {core_pm})
        if "core_pm" in self.tool:
            s = s.replace("{core_pm}", self.tool["core_pm"])
        return s

    def _delay_apply(self, space):
        log("applying %d ms each-way netem delay on %s" %
            (req(self.cfg, "network", "one_way_delay_ms"), space.cfg["delay_if"]))
        space.run(self._fmt_iface(req(self.cfg, "commands", "delay_apply")), timeout=60)

    def _delay_clear(self, space):
        space.run(self._fmt_iface(req(self.cfg, "commands", "delay_clear")), timeout=60)

    def _measure_rtt(self):
        net = req(self.cfg, "network")
        probe_from = self.n(net["rtt_probe_from"])
        target = net["rtt_probe_to"]
        rc, out, _ = probe_from.run("ping -c 5 -w 30 %s" % target, timeout=60)
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)   # rtt min/avg/max
        if not m:
            raise Abort("could not parse ping RTT from %s to %s\n%s"
                        % (net["rtt_probe_from"], target, out))
        return float(m.group(1))

    def _expected_count(self, corpus_limit):
        size = req(self.cfg, "corpus", "size")
        excl = len(self.cfg["corpus"].get("exclude", []))
        n = size - excl
        if corpus_limit and corpus_limit > 0:
            n = min(n, corpus_limit)
        return n

    def _deploy_agents(self, run_id, pacing, corpus_limit, expected):
        mail1, mail2 = self.n("mail1"), self.n("mail2")
        excludes = " ".join(self.cfg["corpus"].get("exclude", []))
        send_cmd = req(self.cfg, "dtn", "send_cmd")
        recv_cmd = req(self.cfg, "dtn", "recv_cmd")
        scan_cmd = req(self.tool, "scan_cmd")
        recv_timeout = req(self.cfg, "host", "recv_timeout_s")

        env_sender = "\n".join([
            'CORPUS_DIR="%s"' % req(mail1.cfg, "corpus_dir"),
            'CORPUS_GLOB="%s"' % req(mail1.cfg, "corpus_glob"),
            'ION_DIR="%s"' % req(mail1.cfg, "ion_dir"),
            'EXCLUDES="%s"' % excludes,
            'LIMIT=%d' % (corpus_limit or 0),
            'PACING=%d' % pacing,
            "SEND_CMD=%s" % _shquote(send_cmd),
        ]) + "\n"
        env_recv = "\n".join([
            'ION_DIR="%s"' % req(mail2.cfg, "ion_dir"),
            'EXPECTED=%d' % expected,
            'RECV_TIMEOUT=%d' % recv_timeout,
            "RECV_CMD=%s" % _shquote(recv_cmd),
            "SCAN_CMD=%s" % _shquote(scan_cmd),
        ]) + "\n"

        base1 = "%s/%s" % (AGENT_DIR, run_id)
        base2 = "%s/%s" % (AGENT_DIR, run_id)
        mail1.run("mkdir -p %s" % base1)
        mail2.run("mkdir -p %s/out" % base2)
        mail1.put_text(env_sender, _abs(mail1, base1 + "/env.sh"))
        mail2.put_text(env_recv, _abs(mail2, base2 + "/env.sh"))
        mail1.put_text(SENDER_SH.replace("AGENT_DIR", _abs(mail1, AGENT_DIR)),
                       _abs(mail1, AGENT_DIR + "/sender.sh"))
        mail2.put_text(RECEIVER_SH.replace("AGENT_DIR", _abs(mail2, AGENT_DIR)),
                       _abs(mail2, AGENT_DIR + "/receiver.sh"))

    def _read_sentinel(self, node, run_id, name):
        rc, out, _ = node.run("cat %s/%s/%s 2>/dev/null" % (AGENT_DIR, run_id, name))
        return out.strip()

    def _poll(self, run_id, expected, started):
        interval = req(self.cfg, "host", "poll_interval_s")
        run_timeout = req(self.cfg, "host", "run_timeout_s")
        mail1, mail2 = self.n("mail1"), self.n("mail2")
        while True:
            s_status = self._read_sentinel(mail1, run_id, "STATUS")
            r_status = self._read_sentinel(mail2, run_id, "STATUS")
            s_prog = self._read_sentinel(mail1, run_id, "progress") or "0/?"
            r_prog = self._read_sentinel(mail2, run_id, "progress") or "0/?"
            elapsed = (dt.datetime.utcnow() - started).total_seconds()
            log("  [%s] sender %s %s | receiver %s %s | %.0fs elapsed"
                % (run_id, s_status or "?", s_prog, r_status or "?", r_prog, elapsed))
            if "FAILED" in (s_status, r_status):
                raise Abort("an agent reported FAILED during %s" % run_id)
            if s_status == "DONE":
                log("  sender finished; entering drain")
                return
            if elapsed > run_timeout:
                raise Abort("run %s exceeded run_timeout_s" % run_id)
            time.sleep(interval)

    def _drain(self, run_id, expected):
        mail2 = self.n("mail2")
        drain_timeout = req(self.cfg, "host", "drain_timeout_s")
        interval = req(self.cfg, "host", "poll_interval_s")
        deadline = time.time() + drain_timeout
        last_prog = None
        while time.time() < deadline:
            prog = self._read_sentinel(mail2, run_id, "progress") or "0/?"
            done = prog.split("/")[0]
            log("  [%s] draining: receiver %s" % (run_id, prog))
            try:
                if int(done) >= expected:
                    break
            except ValueError:
                pass
            if prog == last_prog:
                # no new arrivals this interval; keep waiting until timeout
                pass
            last_prog = prog
            time.sleep(interval)
        # tell the receiver to stop watching and exit cleanly
        mail2.run("touch %s/%s/STOP" % (AGENT_DIR, run_id))
        time.sleep(3)

    def _health(self, run_id, rdir):
        mail2 = self.n("mail2")
        cmds = req(self.cfg, "commands")
        _, infra, _ = mail2.run(cmds["unbound_dump_infra"])
        _write(os.path.join(rdir, "infra_after.txt"), infra)
        _, stats, _ = mail2.run(cmds["unbound_stats"])
        _write(os.path.join(rdir, "unbound_stats.txt"), stats)
        rtos = [int(x) for x in re.findall(r"rto\s+(\d+)", infra)]
        max_rto = max(rtos) if rtos else 0
        drops = 0
        rc, out, _ = mail2.run("journalctl -u unbound --since '-6 hours' 2>/dev/null "
                               "| grep -c 'older than discard-timeout' || true")
        try:
            drops = int(out.strip() or "0")
        except ValueError:
            drops = 0
        health = {"max_rto_ms": max_rto, "discard_drops": drops}
        lvl = "WARN" if max_rto >= 120000 else "INFO"
        log("health: max resolver rto=%d ms, discard-drops=%d" % (max_rto, drops), lvl)
        return health

    def _collect(self, run_id, rdir):
        log("collecting artifacts for %s" % run_id)
        for node_name in ("mail1", "mail2", "space"):
            node = self.n(node_name)
            self.n(node_name).pull_dir("%s/%s" % (AGENT_DIR, run_id),
                                       os.path.join(rdir, node_name))

    def _reconcile(self, rdir, corpus_limit):
        # Totals are row counts (some corpus emails have no Message-ID, so an
        # ID-only count under-reports). The Message-ID set diff still identifies
        # *which* messages are missing, where an ID is present.
        sent_rows = _csv_col(os.path.join(rdir, "mail1", "sent.csv"), "message_id")
        recv_rows = _csv_col(os.path.join(rdir, "mail2", "results.csv"), "message_id")
        sent_total, arrived_total = len(sent_rows), len(recv_rows)
        sent_ids = set(x for x in sent_rows if x)
        recv_ids = set(x for x in recv_rows if x)
        missing_ids = sorted(sent_ids - recv_ids)
        _write(os.path.join(rdir, "missing_ids.txt"), "\n".join(missing_ids))
        lost = max(0, sent_total - arrived_total)     # count-based, catches no-ID losses
        counts = {"sent": sent_total, "arrived": arrived_total,
                  "missing": lost, "missing_ids": len(missing_ids),
                  "loss_pct": round(100.0 * lost / max(1, sent_total), 2)}
        log("reconcile: sent=%d arrived=%d missing=%d (%.1f%%), %d identified by Message-ID"
            % (sent_total, arrived_total, lost, counts["loss_pct"], len(missing_ids)))
        return counts

    def _build_unified_csv(self, run_id, rdir):
        """Join receiver timing with parsed scan output into one CSV + stats."""
        results = os.path.join(rdir, "mail2", "results.csv")
        out_dir = os.path.join(rdir, "mail2", "out")
        parser = PARSERS[self.tool.get("parser", self.tool_name)]
        rows, scan_times = [], []
        header = ["run_id", "tool", "seq", "message_id",
                  "arrived_utc", "scan_start_utc", "scan_end_utc", "scan_s",
                  "exit_code", "verdict", "score", "threshold", "rules"]
        for r in _csv_rows(results):
            seq = r.get("seq", "")
            rawf = os.path.join(out_dir, "%05d.out" % int(seq)) if seq.isdigit() else None
            text = _read(rawf) if rawf and os.path.exists(rawf) else ""
            rc = int(r.get("exit_code") or -1)
            verdict, score, thr, rules = parser(text, rc)
            try:
                scan_times.append(float(r["scan_s"]))
            except Exception:
                pass
            rows.append([run_id, self.tool_name, seq, r.get("message_id", ""),
                         r.get("arrived_utc", ""), r.get("scan_start_utc", ""), r.get("scan_end_utc", ""),
                         r.get("scan_s", ""), rc, verdict, score, thr, ";".join(rules)])
        _write_csv(os.path.join(rdir, "per_email.csv"), header, rows)
        flagged = sum(1 for x in rows if x[9] == "YES")
        errors = sum(1 for x in rows if x[9] == "ERROR")
        st = _stats(scan_times)
        st.update({"flagged_yes": flagged, "errors": errors, "scanned": len(rows)})
        log("scan stats: scanned=%d flagged=%d errors=%d | scan_s mean=%.2f median=%.2f max=%.2f"
            % (len(rows), flagged, errors, st["mean"], st["median"], st["max"]))
        return st

    # ---- Phase 4: shutdown ---------------------------------------------------
    def shutdown(self):
        log("=== Phase 4: shutdown ===")
        ncfgs = req(self.cfg, "nodes")
        order = sorted(ncfgs, key=lambda n: ncfgs[n].get("boot_order", 99), reverse=True)
        for name in order:
            vm = ncfgs[name]["utm_name"]
            log("stopping VM %s" % vm)
            utmctl(self.cfg, "stop", _shquote(vm))

    # ---- Phase 5: summary ----------------------------------------------------
    def write_summary(self):
        path = os.path.join(self.results_root, "summary.json")
        _write(path, json.dumps({"tool": self.tool_name, "runs": self.summary}, indent=2))
        log("=== Summary ===")
        log("%-6s %-8s %8s %8s %8s %10s %9s" %
            ("run", "status", "scanned", "flagged", "errors", "scan_mean", "loss%"))
        for rid in RUN_IDS:
            s = self.summary.get(rid)
            if not s:
                continue
            log("%-6s %-8s %8d %8d %8d %10.2f %9.2f" %
                (rid, s["status"], s["scan_stats"]["scanned"], s["scan_stats"]["flagged_yes"],
                 s["scan_stats"]["errors"], s["scan_stats"]["mean"], s["counts"]["loss_pct"]))
        log("results saved under: %s" % self.results_root)


# =============================================================================
# small helpers
# =============================================================================
def _abs(node, path):
    # agent paths use ~; expand to the node's home for sftp
    if path.startswith("~"):
        return "/home/%s%s" % (node.user, path[1:])
    return path

def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text if text is not None else "")

def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def _write_csv(path, header, rows):
    import csv
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

def _csv_rows(path):
    import csv
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))

def _csv_col(path, col):
    return [r.get(col, "") for r in _csv_rows(path)]

def _stats(vals):
    if not vals:
        return {"min": 0.0, "mean": 0.0, "median": 0.0, "max": 0.0}
    s = sorted(vals)
    n = len(s)
    mean = sum(s) / n
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    return {"min": s[0], "mean": mean, "median": median, "max": s[-1]}


# =============================================================================
# main
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="DTN anti-spam three-run harness")
    ap.add_argument("--config", default=os.path.join(HERE, "config.yaml"))
    ap.add_argument("--tool", help="override active_tool in config")
    ap.add_argument("--runs", help="comma list, e.g. run2,run3 (default: all)")
    ap.add_argument("--corpus-limit", type=int, default=0, help="only send first N emails")
    ap.add_argument("--boot-only", action="store_true")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--shutdown-only", action="store_true")
    ap.add_argument("--no-shutdown", action="store_true",
                    help="leave the VMs running after the pass (useful for smoke tests)")
    ap.add_argument("--continue-on-error", action="store_true",
                    help="keep going to the next run if one fails a gate")
    args = ap.parse_args()

    cfg = load_config(args.config)
    tool_name = args.tool or req(cfg, "active_tool")
    if tool_name not in req(cfg, "tools"):
        sys.exit("unknown tool '%s' (configured tools: %s)"
                 % (tool_name, ", ".join(cfg["tools"])))
    runs = args.runs.split(",") if args.runs else list(RUN_IDS)
    for r in runs:
        if r not in cfg["tools"][tool_name]["runs"]:
            sys.exit("run '%s' not defined for tool '%s'" % (r, tool_name))

    # results dir + session log
    tag = cfg.get("experiment_tag") or dt.datetime.now().strftime("%Y%m%d_%H%M")
    results_root = os.path.join(expand(req(cfg, "host", "results_dir")),
                                "%s_%s" % (tool_name, tag))
    os.makedirs(results_root, exist_ok=True)
    log.open(os.path.join(results_root, "session.log"))
    log("DTN harness starting | tool=%s | runs=%s | limit=%s"
        % (tool_name, ",".join(runs), args.corpus_limit or "full"))

    # keep the Mac awake
    caff = None
    if cfg.get("host", {}).get("use_caffeinate", True):
        try:
            caff = subprocess.Popen(["caffeinate", "-i"])
            log("caffeinate acquired (Mac will not idle-sleep)")
        except FileNotFoundError:
            log("caffeinate not found; continuing", "WARN")

    h = Harness(cfg, tool_name, results_root)
    try:
        h.preflight()
        if args.shutdown_only:
            h.shutdown()
            return
        h.boot()
        if args.boot_only:
            log("boot-only: done"); return
        h.verify()
        if args.verify_only:
            log("verify-only: gates passed"); return

        for rid in runs:
            try:
                h.do_run(rid, args.corpus_limit)
            except Abort as e:
                log("run %s ABORTED: %s" % (rid, e), "ERROR")
                h.summary[rid] = {"status": "ABORTED", "counts": {"loss_pct": 0},
                                  "health": {}, "scan_stats": _stats([]) |
                                  {"flagged_yes": 0, "errors": 0, "scanned": 0}}
                if not args.continue_on_error:
                    break
        h.write_summary()
        if args.no_shutdown:
            log("--no-shutdown: leaving VMs running")
        else:
            h.shutdown()
    except Abort as e:
        log("ABORT: %s" % e, "ERROR")
        sys.exit(2)
    except KeyboardInterrupt:
        log("interrupted by user", "ERROR")
        sys.exit(130)
    finally:
        h.close_all()
        if caff:
            caff.terminate()


if __name__ == "__main__":
    main()
