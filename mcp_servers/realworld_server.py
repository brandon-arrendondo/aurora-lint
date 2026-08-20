#!/usr/bin/env python3
"""
MCP server for running sqc, cppcheck, and clang-tidy against real open-source
codebases (libcrc, sqlite, mosquitto, curl, hostap, lua, raylib, pureftpd) and
tracking results with version+commit SHA tagging. Results stored in SQLite
(data/benchmarks.db). See CODEBASES below for the authoritative, current list.

Supports local and remote execution via SSH. Remote hosts share identical paths
(same username, same directory layout). Results are fetched back via scp.

Tools:
  run_analysis(tool, codebase, host) - Start one tool×codebase run (local or remote)
  run_all(codebase, tool, host)      - Convenience: run multiple combos
  get_status()                       - Show all active/completed/failed runs
  get_results(run, project)          - Per-project + per-rule results (SQLite-first)
  compare_runs(base, target)         - Compare two runs with per-rule deltas
  get_dashboard(run, compare, top)   - FP tracking dashboard with rule deltas
  list_runs()                        - List all runs (SQLite + filesystem)
  get_rule_trend(rule_id, project)   - Per-rule violation trend across versions
  get_project_history(project)       - Per-project violation trend across versions
  cancel_run(run_id)                 - Cancel a specific or all active runs
  purge_run(run_id, zombies)         - Remove stale/zombie runs from tracking
  clear_results()                    - Remove old result directories
  deploy_sqc(host)                   - Deploy sqc binary to remote host(s)
"""

import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
PROJECT_DIR = _HERE.parent
RESULTS_BASE = Path("/tmp/realworld_results")
STATE_FILE = Path("/tmp/realworld_bench.json")
MANIFEST = PROJECT_DIR / "rules_templates" / "rules-benchmark.toml"
SQC_BIN = PROJECT_DIR / "target" / "release" / "sqc"

VALID_TOOLS = {"sqc", "cppcheck", "clang-tidy"}

# ── SQLite backend ───────────────────────────────────────────────────────────
sys.path.insert(0, str(PROJECT_DIR))
from bench.db import BenchDB

def _get_db() -> BenchDB:
    """Get a BenchDB instance."""
    return BenchDB()

# ── Remote execution ─────────────────────────────────────────────────────────
# Loaded from mcp_servers/remote_hosts.json (gitignored). If missing, remote is disabled.
REMOTE_HOSTS_CONFIG = _HERE / "remote_hosts.json"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]


def _load_remote_config() -> tuple[dict[str, str], str]:
    """Load remote hosts config. Returns (hosts_dict, ssh_user)."""
    try:
        data = json.loads(REMOTE_HOSTS_CONFIG.read_text())
        hosts = data.get("hosts", {})
        user = data.get("ssh_user", "brandon")
        return hosts, user
    except (FileNotFoundError, json.JSONDecodeError):
        return {}, "brandon"

# ── Codebase Registry ─────────────────────────────────────────────────────────
CODEBASES = {
    "libcrc": {
        "path": Path.home() / "toolchain" / "libcrc",
        "sqc": {
            "scan_path": None,  # same as path (whole project)
            # Per-codebase rules manifest (conf/realworld/<cb>-rules.toml).
            # Reused for every libcrc run so inapplicable rules are ignored
            # consistently — the real-world analog of a project's own sqc config.
            "manifest": "conf/realworld/libcrc-rules.toml",
            "includes": ["-I", "{path}/include"],
            "extra_args": ["-d", "{path}/src", "-d", "{path}/include"],
        },
        "cppcheck": {
            "includes": ["-I", "{path}/include"],
            "source_dirs": ["{path}/src/"],
            "extra_args": [],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}/include"],
            "source_dirs": ["{path}/src/"],
        },
    },
    "sqlite": {
        "path": Path.home() / "toolchain" / "sqlite",
        "sqc": {
            "scan_path": None,
            "manifest": "conf/realworld/sqlite-rules.toml",
            "includes": [
                "-I", "/usr/include",           # openssl, zlib, sqlite3
                "-I", "/usr/include/tcl8.6",    # Tcl (test infrastructure)
            ],
            # Scope = shipped engine (src/) + shipped extensions (ext/), matching
            # the precision oracle (data/precision_audit/sqlite/README.md).
            # `-d` doesn't restrict the scan (it only adds cross-file pre-scan
            # context; the primary scan root is still the whole repo when
            # scan_path is None), so out-of-scope trees are dropped via
            # --exclude instead: autosetup/ (vendored Jim Tcl), tool/ (lemon
            # parser-gen, build tools), test/ + src/test*.c (Tcl test glue),
            # and ext/jni + ext/wasm (language bindings, not the engine).
            "extra_args": [
                "--exclude", "autosetup/**",
                "--exclude", "tool/**",
                "--exclude", "test/**",
                "--exclude", "src/test*.c",
                "--exclude", "ext/jni/**",
                "--exclude", "ext/wasm/**",
            ],
        },
        "cppcheck": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/"],
            "extra_args": [],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/"],
        },
    },
    "mosquitto": {
        "path": Path.home() / "toolchain" / "mosquitto",
        "sqc": {
            "scan_path": None,
            "manifest": "conf/realworld/mosquitto-rules.toml",
            "includes": [
                "-I", "/usr/include",           # openssl, CUnit, sqlite3
                "-I", "/usr/include/cjson",     # cJSON
            ],
            # Scope = shipped product (lib/ libmosquitto client + src/ broker
            # daemon), matching the precision oracle
            # (data/precision_audit/mosquitto/README.md). `-d` doesn't restrict
            # the scan (it only adds cross-file pre-scan context; the primary
            # scan root is still the whole repo when scan_path is None), so
            # out-of-scope trees are dropped via --exclude instead: deps/
            # (vendored picohttpparser), test/, client/, apps/, plugins/
            # (example plugins), common/ and libcommon/ (shared helpers, pulled
            # in only as cross-file context).
            "extra_args": [
                "--exclude", "deps/**",
                "--exclude", "test/**",
                "--exclude", "client/**",
                "--exclude", "apps/**",
                "--exclude", "plugins/**",
                "--exclude", "common/**",
                "--exclude", "libcommon/**",
            ],
        },
        "cppcheck": {
            "includes": [
                "-I", "{path}/include",
                "-I", "{path}/common",
            ],
            "source_dirs": ["{path}/lib/", "{path}/src/"],
            "extra_args": ["-i", "{path}/deps"],
        },
        "clang-tidy": {
            "includes": [
                "-I", "{path}/include",
                "-I", "{path}/common",
            ],
            "source_dirs": ["{path}/lib/", "{path}/src/"],
        },
    },
    "curl": {
        "path": Path.home() / "toolchain" / "curl",
        "sqc": {
            "scan_path": None,
            "manifest": "conf/realworld/curl-rules.toml",
            "includes": [
                "-I", "/usr/include",           # openssl, mbedtls, gnutls, zlib
                "-I", "{path}/lib",             # internal curlx headers
                "-I", "{path}/include",         # public API headers (curl/curl.h et al.)
            ],
            # Scope = shipped product (lib/ libcurl + src/ curl CLI), matching
            # the precision oracle (data/precision_audit/curl/README.md). The
            # oracle explicitly excludes include/ (public API headers aren't
            # "shipped product" in the lib/+src/ sense) -- task 431 found 218
            # findings coming from include/ alone, none of which are or can be
            # in ground_truth, silently inflating totals outside the audited
            # denominator.
            # `-d` doesn't restrict the scan (it only adds cross-file pre-scan
            # context; the primary scan root is still the whole repo when
            # scan_path is None), so out-of-scope trees are dropped via
            # --exclude instead: tests/, docs/ (incl. docs/examples/*.c
            # snippets), scripts/, CMake/, projects/, include/ (vendored/build
            # tooling + public API headers). Excluding include/ from the
            # target list doesn't lose type/macro resolution for lib/+src/ --
            # the `-d {path}` full-repo prescan walk (added automatically
            # whenever extra_args has no explicit `-d`) already indexes
            # include/'s macros/enums/types independently of --exclude, which
            # only filters which files get reported, not which get parsed.
            # Does NOT exclude the WIN_MAC files (14 files under lib/vtls,
            # lib/curlx) — those stay in the scan since the oracle treats them
            # as a distinct build-config boundary, excluded only from
            # *scoring*, not from the scan itself.
            "extra_args": [
                "--exclude", "tests/**",
                "--exclude", "docs/**",
                "--exclude", "scripts/**",
                "--exclude", "CMake/**",
                "--exclude", "projects/**",
                "--exclude", "include/**",
            ],
        },
        "cppcheck": {
            "includes": [
                "-I", "{path}/include",
                "-I", "{path}/lib",
            ],
            "source_dirs": ["{path}/lib/", "{path}/src/"],
            "extra_args": [],
        },
        "clang-tidy": {
            "includes": [
                "-I", "{path}/include",
                "-I", "{path}/lib",
            ],
            "source_dirs": ["{path}/lib/", "{path}/src/"],
        },
    },
    "hostap": {
        "path": Path.home() / "toolchain" / "hostap",
        "sqc": {
            "scan_path": None,
            "manifest": "conf/realworld/hostap-rules.toml",
            "includes": [
                "-I", "/usr/include",              # openssl, gcrypt, pcap
                "-I", "/usr/include/libnl3",       # netlink (nla_, nlmsg_, nl_)
                "-I", "/usr/include/dbus-1.0",     # D-Bus
            ],
            # Scope = shipped hostapd (AP) + wpa_supplicant (station) daemons
            # and their shared library, matching the precision oracle
            # (data/precision_audit/hostap/README.md, task 159): src/ +
            # wpa_supplicant/ + hostapd/. `-d` doesn't restrict the scan (it
            # only adds cross-file pre-scan context; the primary scan root is
            # still the whole repo when scan_path is None), so out-of-scope
            # trees are dropped via --exclude instead: tests/, wlantest/
            # (separate test/monitoring tool), eap_example/, hs20/,
            # radius_example/, wpaspy/ — none of these ship as part of either
            # daemon.
            "extra_args": [
                "--exclude", "tests/**",
                "--exclude", "wlantest/**",
                "--exclude", "eap_example/**",
                "--exclude", "hs20/**",
                "--exclude", "radius_example/**",
                "--exclude", "wpaspy/**",
            ],
        },
        "cppcheck": {
            "includes": [
                "-I", "{path}/src",
                "-I", "{path}/src/utils",
                "-I", "{path}/src/common",
            ],
            "source_dirs": ["{path}/src/", "{path}/wpa_supplicant/"],
            "extra_args": [],
        },
        "clang-tidy": {
            "includes": [
                "-I", "{path}/src",
                "-I", "{path}/src/utils",
                "-I", "{path}/src/common",
                "-I", "{path}/src/crypto",
            ],
            "source_dirs": ["{path}/src/"],
        },
    },
    "lua": {
        "path": Path.home() / "toolchain" / "lua",
        "sqc": {
            "scan_path": None,
            "manifest": "conf/realworld/lua-rules.toml",
            "includes": ["-I", "{path}"],
            # Exclude the checked-in amalgamation (onelua.c #includes every
            # other .c), the internal test/debug harness (ltests.c/.h) and the
            # C test fixtures under testes/. Scope = shipping library + the
            # lua.c interpreter main. sqc parses raw (no preprocessor) so
            # onelua.c wouldn't double-count, but excluding keeps the scanned
            # fileset identical to the competitor tools below.
            "extra_args": [
                "--exclude", "**/onelua.c",
                "--exclude", "**/ltests.c",
                "--exclude", "**/ltests.h",
                "--exclude", "testes/**",
            ],
        },
        "cppcheck": {
            "includes": ["-I", "{path}"],
            "source_dirs": ["{path}/"],
            "extra_args": [
                "-i", "{path}/onelua.c",
                "-i", "{path}/ltests.c",
                "-i", "{path}/testes",
            ],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}"],
            "source_dirs": ["{path}/"],
            "exclude": ["*/onelua.c", "*/ltests.c", "*/testes/*"],
        },
    },
    "raylib": {
        "path": Path.home() / "toolchain" / "raylib",
        "sqc": {
            # Scope to raylib's OWN library code: src/ (the 7 module .c TUs +
            # platform backends + headers), excluding src/external/** which is
            # bundled third-party (glad, glfw, dr_*, cgltf, miniaudio, stb-like
            # single-headers). examples/, projects/ and tools/ are demo programs,
            # not the library, and fall outside scan_path. raylib is the suite's
            # structural-C99 oracle (compound literals + designated initializers),
            # the idioms Lua/the other oracles lack (task 217).
            "scan_path": "{path}/src",
            "manifest": "conf/realworld/raylib-rules.toml",
            "includes": ["-I", "{path}/src"],
            "extra_args": [
                "--exclude", "**/external/**",
            ],
        },
        "cppcheck": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/"],
            "extra_args": ["-i", "{path}/src/external"],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/"],
            "exclude": ["*/external/*"],
        },
    },
    # Registry key deliberately "pureftpd" (no hyphen), even though the
    # upstream project is "pure-ftpd" -- two hyphen-sensitive spots in
    # bench/db.py silently break on it otherwise: (1) ingest_realworld_run
    # parses result filenames as "sqc-{project}-{version}-{sha}.json" by
    # splitting on "-" and taking index 1, so "pure-ftpd" truncates to
    # "pure"; (2) project_relpath normalizes an absolute violation path to
    # a portable relative one by finding "/{project}/" in it, which
    # requires the checkout directory's basename to equal the registry key
    # -- so the checkout at ~/toolchain is ALSO named "pureftpd" (renamed
    # from the upstream "pure-ftpd" clone name), not just this dict key.
    # Every other registry key so far happened to be hyphen-free with a
    # matching checkout dir name; this is the first one that would trip
    # either bug.
    "pureftpd": {
        "path": Path.home() / "toolchain" / "pureftpd",
        "sqc": {
            # Onboarded task 301: the suite's SQL-client-API oracle for
            # CWE-89 (SQL injection) -- src/log_mysql.c/log_pgsql.c call
            # mysql_real_query/PQexec as a *client*, unlike sqlite (which
            # implements sqlite3_exec) or any other current oracle (none
            # touch SQL at all). Scope = whole project (src/ + puredb/);
            # gui/ is the separate, optional GTK admin GUI, not the ftpd
            # itself.
            "scan_path": None,
            "manifest": "conf/realworld/pureftpd-rules.toml",
            "includes": [],
            "extra_args": [
                "-d", "{path}/src",
                "-d", "{path}/puredb",
                "--exclude", "gui/**",
            ],
        },
        "cppcheck": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/", "{path}/puredb/"],
            "extra_args": ["-i", "{path}/gui"],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}/src"],
            "source_dirs": ["{path}/src/", "{path}/puredb/"],
            "exclude": ["*/gui/*"],
        },
    },
    # Onboarded task 381: candidate 8th real-world oracle, formally verified
    # microkernel (https://sel4.systems/Contribute/style.html). A literal
    # `if/for/while (...) {}` grep found zero hits, which looked promising as
    # an MSC12-C (no-effect/empty-body) oracle -- but full sample adjudication
    # (data/precision_audit/sel4/README.md) found the literal-braces grep
    # missed the dominant real idiom: `while (cond);` busy-wait polling loops
    # (empty body via bare `;`, not `{}`), plus commented no-op platform
    # stubs/cases and macro-hidden lock/barrier statements -- the SAME FP
    # families as every other oracle, at a similar ~2.8% sample precision.
    # MSC12-C stays disabled here too (sel4-rules.toml); this is now onboarded
    # as a general 8th oracle (novel domain: verified microkernel), not the
    # MSC12-C-specific oracle task 381 originally set out to find. sqc-only
    # (no cppcheck/clang-tidy config).
    "sel4": {
        "path": Path.home() / "toolchain" / "sel4",
        "sqc": {
            # Scope = the kernel proper (src/, 183 of 184 repo .c files).
            # libsel4/ (userspace bindings), tools/, manual/, configs/ are not
            # kernel code.
            "scan_path": "{path}/src",
            "manifest": "conf/realworld/sel4-rules.toml",
            "includes": ["-I", "{path}/include", "-I", "{path}/libsel4/include"],
            "extra_args": ["-d", "{path}/include", "-d", "{path}/libsel4/include"],
        },
    },
}

# ── MCP server ────────────────────────────────────────────────────────────────
mcp = FastMCP(
    "realworld-benchmark",
    instructions=(
        "Run sqc, cppcheck, and clang-tidy against real open-source C codebases "
        "(libcrc, sqlite, mosquitto, curl, hostap) and compare results across versions. "
        "Supports remote execution via SSH if mcp_servers/remote_hosts.json is configured — "
        "pass host parameter to run_analysis/run_all. Use deploy_sqc to push "
        "the sqc binary to remote hosts before running."
    ),
)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fmt_duration(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m or h:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _get_sqc_version() -> str:
    try:
        for line in (PROJECT_DIR / "Cargo.toml").read_text().splitlines():
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "unknown"


def _get_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_DIR, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _get_codebase_sha(path: Path) -> str | None:
    """Short HEAD SHA of a target codebase checkout (the thing being scanned).

    Distinct from _get_git_sha(), which is the sqc repo. Captured at scan time
    so results record exactly which revision of the target was analyzed.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _get_tool_version(tool: str) -> str:
    """Get the version string for any supported tool."""
    if tool == "sqc":
        return _get_sqc_version()
    elif tool == "cppcheck":
        try:
            result = subprocess.run(
                ["cppcheck", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "Cppcheck 2.13" or similar
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    elif tool == "clang-tidy":
        try:
            result = subprocess.run(
                ["clang-tidy", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Look for "LLVM version X.Y.Z" or "clang-tidy version X.Y.Z"
            m = re.search(r"version\s+(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    return "unknown"


def _make_version_dir_name(tool: str, version: str, sha: str) -> str:
    """Build version directory name: sqc includes git SHA, others just tool-version."""
    if tool == "sqc":
        return f"sqc-{version}-{sha}"
    return f"{tool}-{version}"


_STATE_LOCK = Path("/tmp/realworld_bench.lock")


def _read_state() -> dict:
    """Read persisted state. Returns dict with 'runs' key (map of run_id → run info)."""
    try:
        data = json.loads(STATE_FILE.read_text())
        if "runs" not in data:
            data["runs"] = {}
        return data
    except Exception:
        return {"runs": {}}


def _write_state(state: dict) -> None:
    """Atomic write: write to temp file then rename (POSIX atomic)."""
    content = json.dumps(state, indent=2)
    fd, tmp = tempfile.mkstemp(dir=STATE_FILE.parent, suffix=".tmp")
    closed = False
    try:
        os.write(fd, content.encode())
        os.fsync(fd)
        os.close(fd)
        closed = True
        os.rename(tmp, str(STATE_FILE))
    except Exception:
        if not closed:
            os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise


class _StateLock:
    """Context manager for exclusive access to the state file.

    Usage:
        with _StateLock() as state:
            state["runs"][run_id] = {...}
        # State is automatically written on exit
    """

    def __init__(self):
        self._fd = None
        self._state = None

    def __enter__(self) -> dict:
        self._fd = open(_STATE_LOCK, "w")
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        self._state = _read_state()
        return self._state

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                _write_state(self._state)
        finally:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
        return False


# ── Child-process reaping ─────────────────────────────────────────────────────
# run_analysis() spawns detached Popen children (start_new_session=True) and then
# drops the Popen reference, tracking the run by PID only. Because this server is
# a persistent process, those children become defunct zombies (state Z) the moment
# they exit and stay that way until *something* calls waitpid() — which made
# PID-based liveness checks (os.kill(pid, 0), `ps -p PID`) report finished runs as
# "alive" for hours (task 218).
#
# We keep the Popen objects in a registry and reap them with proc.poll(), which
# waits on that specific child only. A SIGCHLD handler reaps promptly without
# waiting for the next get_status() poll. We deliberately do NOT use
# `os.waitpid(-1, WNOHANG)`: this server makes many returncode-sensitive
# subprocess.run() calls (often from FastMCP's worker threads), and a wildcard
# reaper can swallow their child before subprocess reads its exit status,
# corrupting the reported returncode.
_CHILD_PROCS: dict[int, "subprocess.Popen"] = {}
_CHILD_PROCS_LOCK = threading.Lock()


def _register_child(proc: "subprocess.Popen") -> None:
    with _CHILD_PROCS_LOCK:
        _CHILD_PROCS[proc.pid] = proc


def _reap_children() -> None:
    """Reap any finished background children. Safe to call from any thread."""
    # Non-blocking acquire so a SIGCHLD handler interrupting the main thread can
    # never deadlock against an in-progress reap; whoever holds the lock will
    # finish the work.
    if not _CHILD_PROCS_LOCK.acquire(blocking=False):
        return
    try:
        for pid in list(_CHILD_PROCS):
            proc = _CHILD_PROCS[pid]
            try:
                if proc.poll() is not None:  # poll() reaps this specific child
                    del _CHILD_PROCS[pid]
            except Exception:
                del _CHILD_PROCS[pid]
    finally:
        _CHILD_PROCS_LOCK.release()


_prev_sigchld_handler = None


def _sigchld_handler(signum, frame):
    _reap_children()
    # Chain to any previously installed handler (e.g. an event loop's child
    # watcher) so we don't silently steal SIGCHLD from it.
    if callable(_prev_sigchld_handler):
        _prev_sigchld_handler(signum, frame)


def _install_sigchld_reaper() -> None:
    """Install a SIGCHLD handler that reaps tracked children promptly."""
    global _prev_sigchld_handler
    if not hasattr(signal, "SIGCHLD"):
        return  # non-POSIX; nothing to do
    try:
        prev = signal.getsignal(signal.SIGCHLD)
        # SIG_DFL/SIG_IGN are ints, not callables — don't chain to those.
        _prev_sigchld_handler = prev if callable(prev) else None
        signal.signal(signal.SIGCHLD, _sigchld_handler)
    except (ValueError, OSError):
        # signal.signal() only works on the main thread; if we're not there,
        # fall back to poll-based reaping at each tool entry point.
        pass


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        for line in status.splitlines():
            if line.startswith("State:") and "zombie" in line.lower():
                # Reap the zombie so it doesn't linger
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                return False
    except Exception:
        pass
    return True


def _remote_check_done(host: str, version_dir: Path, run_id: str) -> bool:
    """Check if a remote run finished by looking for its .done sentinel file."""
    _, ssh_user = _load_remote_config()
    sentinel = f"{version_dir / (run_id + '.done')}"
    try:
        result = subprocess.run(
            ["ssh"] + SSH_OPTS + [f"{ssh_user}@{host}", f"test -f {shlex.quote(sentinel)}"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    time.sleep(1.0)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass


def _dir_size_human(path: Path) -> str:
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except Exception:
        pass
    for unit in ("B", "KB", "MB", "GB"):
        if total < 1024:
            return f"{total:.1f} {unit}"
        total /= 1024
    return f"{total:.1f} TB"


def _make_run_id(tool: str, codebase: str, version: str, sha: str) -> str:
    return f"{tool}-{codebase}-{version}-{sha}"


def _expand(template_list: list[str], path: str) -> list[str]:
    """Expand {path} placeholders in argument lists."""
    return [s.replace("{path}", path) for s in template_list]


def _is_local(host: str | None) -> bool:
    """Returns True if host is None, 'local', or loopback."""
    return host is None or host.lower() in ("local", "localhost", "127.0.0.1")


def _resolve_host(host: str | None) -> str | dict:
    """Validate host. Returns IP string, or error dict if invalid."""
    if _is_local(host):
        return "local"
    hosts, _ = _load_remote_config()
    if not hosts:
        return {"error": "Remote execution not configured. Create mcp_servers/remote_hosts.json."}
    host = host.strip()
    if host in hosts:
        return host
    # Try matching by nickname
    for ip, name in hosts.items():
        if host == name:
            return ip
    return {
        "error": f"Unknown host '{host}'. Must be one of: local, "
                 + ", ".join(f"{ip} ({name})" for ip, name in hosts.items()),
    }


def _build_remote_shell_cmd(tool: str, cmd: list[str], version_dir: Path, run_id: str) -> str:
    """Convert a local command + I/O redirections into a single shell string for SSH.

    Every remote command ends by touching a .done sentinel file so the local
    server can cheaply detect completion without tracking remote PIDs.
    """
    dir_str = shlex.quote(str(version_dir))
    mkdir = f"mkdir -p {dir_str}"
    done = shlex.quote(str(version_dir / f"{run_id}.done"))
    sentinel = f"touch {done}"

    if tool == "sqc":
        # sqc writes JSON via --export; stdout/stderr → log
        log = shlex.quote(str(version_dir / f"{run_id}.log"))
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        return f"{mkdir} && {cmd_str} > {log} 2>&1 ; {sentinel}"

    elif tool == "cppcheck":
        # cppcheck: stderr is XML output, stdout → log
        xml = shlex.quote(str(version_dir / f"{run_id}.xml"))
        log = shlex.quote(str(version_dir / f"{run_id}.log"))
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        return f"{mkdir} && {cmd_str} > {log} 2> {xml} ; {sentinel}"

    else:  # clang-tidy
        # clang-tidy cmd is ["bash", "-c", "pipeline..."]
        # Extract the pipeline string and wrap with redirections
        pipeline = cmd[2]  # the bash -c argument
        txt = shlex.quote(str(version_dir / f"{run_id}.txt"))
        log = shlex.quote(str(version_dir / f"{run_id}.log"))
        return f"{mkdir} && bash -c {shlex.quote(pipeline)} > {txt} 2> {log} ; {sentinel}"


def _fetch_remote_results(host: str, version_dir: Path, run_id: str) -> dict:
    """SCP result + log files from remote host. Returns {fetched, failed}."""
    fetched = []
    failed = []
    version_dir.mkdir(parents=True, exist_ok=True)
    _, ssh_user = _load_remote_config()
    remote = f"{ssh_user}@{host}"

    for ext in (".json", ".xml", ".txt", ".log"):
        remote_file = f"{version_dir / (run_id + ext)}"
        local_file = version_dir / (run_id + ext)
        if local_file.exists() and local_file.stat().st_size > 0:
            continue  # already fetched
        try:
            result = subprocess.run(
                ["scp"] + SSH_OPTS + [f"{remote}:{remote_file}", str(local_file)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and local_file.exists() and local_file.stat().st_size > 0:
                fetched.append(ext)
            else:
                # Remote file may not exist (not all tools produce all extensions)
                local_file.unlink(missing_ok=True)
        except Exception as e:
            failed.append(f"{ext}: {e}")

    return {"fetched": fetched, "failed": failed}


def _build_sqc_cmd(codebase: str, cfg: dict, results_dir: Path, run_id: str) -> list[str]:
    path = str(cfg["path"])
    scan_path = cfg["sqc"].get("scan_path")
    scan_path = _expand([scan_path], path)[0] if scan_path else path
    output_file = results_dir / f"{run_id}.json"
    extra = _expand(cfg["sqc"].get("extra_args", []), path)
    includes = _expand(cfg["sqc"].get("includes", []), path)

    # Per-codebase manifest (relative to PROJECT_DIR) if configured; else the
    # shared benchmark base. Lets each codebase ignore rules that don't apply.
    rel_manifest = cfg["sqc"].get("manifest")
    manifest = (PROJECT_DIR / rel_manifest) if rel_manifest else MANIFEST

    cmd = [
        str(SQC_BIN), scan_path,
        "--manifest", str(manifest),
        "--export", str(output_file),
        "--jobs", str(min(os.cpu_count() or 4, 8)),
    ]
    if "-d" not in extra:
        cmd.extend(["-d", path])
    cmd.extend(extra)
    cmd.extend(includes)
    return cmd


def _build_cppcheck_cmd(codebase: str, cfg: dict, results_dir: Path, run_id: str) -> list[str]:
    path = str(cfg["path"])
    cmd = [
        "cppcheck",
        "--enable=all",
        "--std=c11",
        "--xml", "--xml-version=2",
        "--suppress=missingIncludeSystem",
    ]
    cmd.extend(_expand(cfg["cppcheck"].get("includes", []), path))
    cmd.extend(_expand(cfg["cppcheck"].get("extra_args", []), path))
    cmd.extend(_expand(cfg["cppcheck"].get("source_dirs", []), path))
    return cmd


def _build_clang_tidy_cmd(codebase: str, cfg: dict, results_dir: Path, run_id: str) -> list[str]:
    """Build a shell command string for clang-tidy (uses find|xargs pipeline)."""
    path = str(cfg["path"])
    source_dirs = _expand(cfg["clang-tidy"].get("source_dirs", []), path)
    includes = _expand(cfg["clang-tidy"].get("includes", []), path)
    # Optional glob patterns to prune from the find (e.g. checked-in
    # amalgamations or test harnesses). Matched with find -path, so use
    # path globs like "*/onelua.c" or "*/testes/*". Left empty for projects
    # that scope via source_dirs alone.
    excludes = cfg["clang-tidy"].get("exclude", [])
    prune = "".join(f" ! -path '{pat}'" for pat in excludes)

    # Build find command for all source dirs
    find_parts = []
    for sd in source_dirs:
        find_parts.append(f"find {sd} -name '*.c'{prune}")
    find_cmd = " && ".join(find_parts) if len(find_parts) > 1 else find_parts[0]
    if len(find_parts) > 1:
        find_cmd = "( " + " ; ".join(find_parts) + " )"

    includes_str = " ".join(includes)
    return [
        "bash", "-c",
        f"{find_cmd} | xargs -P $(nproc) -I{{}} clang-tidy "
        f"-checks='-*,cert-*,clang-analyzer-*' {{}} "
        f"-- -std=c11 {includes_str}"
    ]


def _check_tool_available(tool: str) -> bool:
    """Check if a tool binary is available."""
    if tool == "sqc":
        return SQC_BIN.exists()
    try:
        subprocess.run(
            [tool if tool != "clang-tidy" else "clang-tidy", "--version"],
            capture_output=True, timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── Result parsers ────────────────────────────────────────────────────────────

def _parse_sqc_json(filepath: Path) -> dict:
    """Parse sqc JSON export → violation count + per-rule breakdown."""
    try:
        violations = json.loads(filepath.read_text())
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}

    per_rule: dict[str, int] = {}
    for v in violations:
        rule = v.get("rule_id", "unknown")
        per_rule[rule] = per_rule.get(rule, 0) + 1

    return {
        "total": len(violations),
        "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1])),
    }


def _parse_cppcheck_xml(filepath: Path) -> dict:
    """Parse cppcheck XML output → error count + per-id breakdown."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}

    per_rule: dict[str, int] = {}
    total = 0
    for error in root.iter("error"):
        error_id = error.get("id", "unknown")
        severity = error.get("severity", "")
        # Skip informational messages (missingInclude, etc.)
        if severity == "information":
            continue
        per_rule[error_id] = per_rule.get(error_id, 0) + 1
        total += 1

    return {
        "total": total,
        "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1])),
    }


def _parse_clang_tidy_txt(filepath: Path) -> dict:
    """Parse clang-tidy text output → warning count + per-check breakdown."""
    try:
        content = filepath.read_text()
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}

    per_rule: dict[str, int] = {}
    total = 0
    # Match lines like: file.c:10:5: warning: ... [cert-err33-c]
    pattern = re.compile(r": warning: .+\[([^\]]+)\]$")
    for line in content.splitlines():
        m = pattern.search(line)
        if m:
            check_name = m.group(1)
            per_rule[check_name] = per_rule.get(check_name, 0) + 1
            total += 1

    return {
        "total": total,
        "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1])),
    }


def _parse_result_file(run_id: str, filepath: Path) -> dict:
    """Dispatch to the right parser based on file extension."""
    if filepath.suffix == ".json":
        return _parse_sqc_json(filepath)
    elif filepath.suffix == ".xml":
        return _parse_cppcheck_xml(filepath)
    elif filepath.suffix == ".txt":
        return _parse_clang_tidy_txt(filepath)
    return {"error": f"Unknown file type: {filepath.suffix}", "total": 0, "per_rule": {}}


def _parse_sqc_log_progress(version_dir: Path, run_id: str) -> dict | None:
    """Parse tail of sqc log for progress (parallel unit or single-file mode)."""
    log_file = version_dir / f"{run_id}.log"
    if not log_file.exists():
        return None
    try:
        size = log_file.stat().st_size
        with open(log_file, "rb") as f:
            # Read last 4KB to find the most recent progress line
            f.seek(max(0, size - 4096))
            tail = f.read().decode("utf-8", errors="replace")

        # Parallel mode: [parallel] Completed N/M: ...
        par_matches = re.findall(r"\[parallel\] Completed (\d+)/(\d+)", tail)
        if par_matches:
            current, total = par_matches[-1]
            return {"current_unit": int(current), "total_units": int(total),
                    "mode": "parallel"}

        # Single-process mode: Scanning: [file N/M]
        matches = re.findall(r"Scanning: \[file (\d+)/(\d+)\]", tail)
        if matches:
            current, total = matches[-1]
            return {"current_file": int(current), "total_files": int(total),
                    "mode": "single"}
    except Exception:
        pass
    return None


def _get_result_file(results_dir: Path, run_id: str) -> Path | None:
    """Find the result file for a run (json, xml, or txt)."""
    for ext in (".json", ".xml", ".txt"):
        p = results_dir / f"{run_id}{ext}"
        if p.exists():
            return p
    return None


def _completion_time(version_dir: Path, run_id: str) -> float | None:
    """Best estimate of when a run's process actually finished: the mtime of
    its last-written output artifact (result file or log, whichever is newer).

    get_status may not observe completion until long after the process exited,
    so wall clock at poll time over-reports duration (and, when a single late
    poll reaps several parallel runs, reports the same inflated total for all
    of them). The output file's final write is the faithful finish timestamp.
    """
    mtimes = []
    rf = _get_result_file(version_dir, run_id)
    if rf and rf.exists():
        mtimes.append(rf.stat().st_mtime)
    log_file = version_dir / f"{run_id}.log"
    if log_file.exists():
        mtimes.append(log_file.stat().st_mtime)
    return max(mtimes) if mtimes else None


def _latest_completed_version_dir(tool: str = "sqc") -> Path | None:
    """version_dir of the most-recently-completed run of `tool` in state.

    Used to drive auto-ingest off the sqc dir specifically (rather than the
    newest dir on disk, which in a run_all batch is often a competitor dir).
    """
    best: Path | None = None
    best_t = -1.0
    try:
        for _rid, info in _read_state().get("runs", {}).items():
            if info.get("tool") != tool or info.get("status") != "completed":
                continue
            vd = info.get("version_dir")
            t = info.get("end_time") or info.get("start_time") or 0
            if vd and t > best_t:
                best_t, best = t, Path(vd)
    except Exception:
        pass
    return best


def _get_version_dir(identifier: str | None = None) -> Path | None:
    """Find a results directory by name, commit SHA, or 'latest'.

    Args:
        identifier: One of:
          - Full dir name (e.g. "sqc-0.2.4-abc1234")
          - Commit SHA (e.g. "abc1234") — matches sqc dirs
          - "latest" or None — most recently modified dir
    """
    if not RESULTS_BASE.exists():
        return None

    if identifier and identifier != "latest":
        # Try exact dir name match
        p = RESULTS_BASE / identifier
        if p.exists():
            return p
        # Try as commit SHA — search sqc dirs
        for d in RESULTS_BASE.iterdir():
            if d.is_dir() and d.name.endswith(f"-{identifier}"):
                return d
        # Try legacy format (version-sha without tool prefix)
        for d in RESULTS_BASE.iterdir():
            if d.is_dir() and identifier in d.name:
                return d
        return None

    # Find latest by modification time
    dirs = sorted(
        (d for d in RESULTS_BASE.iterdir() if d.is_dir()),
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    return dirs[0] if dirs else None


def _parse_version_dir_name(name: str) -> tuple[str, str, str]:
    """Parse dir name into (tool, version, sha).

    Formats:
      sqc-{version}-{sha}     → ("sqc", version, sha)
      cppcheck-{version}      → ("cppcheck", version, "")
      clang-tidy-{version}    → ("clang-tidy", version, "")
      {version}-{sha}         → ("sqc", version, sha)  [legacy]
    """
    if name.startswith("clang-tidy-"):
        return ("clang-tidy", name[len("clang-tidy-"):], "")
    if name.startswith("cppcheck-"):
        return ("cppcheck", name[len("cppcheck-"):], "")
    if name.startswith("sqc-"):
        rest = name[len("sqc-"):]
        parts = rest.rsplit("-", 1)
        version = parts[0] if parts else "unknown"
        sha = parts[1] if len(parts) > 1 else "unknown"
        return ("sqc", version, sha)
    # Legacy format: {version}-{sha}
    parts = name.rsplit("-", 1)
    return ("sqc", parts[0], parts[1] if len(parts) > 1 else "unknown")


def _list_version_dirs() -> list[dict]:
    """List all version directories with metadata."""
    runs = []
    if not RESULTS_BASE.exists():
        return runs

    for entry in sorted(RESULTS_BASE.iterdir()):
        if not entry.is_dir():
            continue
        tool, version, sha = _parse_version_dir_name(entry.name)

        result_files = [
            f for f in entry.iterdir()
            if f.is_file() and f.suffix in (".json", ".xml", ".txt") and f.stem != "benchmark"
        ]

        try:
            mtime = entry.stat().st_mtime
        except Exception:
            mtime = 0

        runs.append({
            "dir_name": entry.name,
            "path": str(entry),
            "tool": tool,
            "version": version,
            "commit_sha": sha,
            "result_files": len(result_files),
            "size": _dir_size_human(entry),
            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)),
        })

    runs.sort(key=lambda r: r["modified"], reverse=True)
    return runs


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_analysis(tool: str, codebase: str, host: str | None = None) -> str:
    """
    Start a single analysis run (one tool against one codebase).

    Args:
        tool: One of "sqc", "cppcheck", "clang-tidy"
        codebase: A key from CODEBASES (e.g. "libcrc", "sqlite", "mosquitto",
              "curl", "hostap", "lua", "raylib", "pureftpd")
        host: Optional remote host IP or nickname (e.g. "10.0.0.97", "workstation-97").
              If omitted, runs locally.

    Every sqc run does a fresh prescan (no caching — measured ~10% wall-time
    savings from a warm prescan cache isn't worth the staleness risk for a
    benchmark whose entire point is precise measurement; see task 209).

    Returns immediately. Use get_status() to monitor progress.
    """
    _reap_children()  # opportunistically clear finished children before starting
    _start_watcher()  # ensure completion → ingest fires even without a poll
    tool = tool.strip().lower()
    codebase = codebase.strip().lower()

    if tool not in VALID_TOOLS:
        return json.dumps({
            "error": f"Unknown tool '{tool}'. Must be one of: {', '.join(sorted(VALID_TOOLS))}",
        })

    if codebase not in CODEBASES:
        return json.dumps({
            "error": f"Unknown codebase '{codebase}'. Must be one of: {', '.join(sorted(CODEBASES))}",
        })

    # Resolve host
    resolved = _resolve_host(host)
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    remote = not _is_local(host)

    cfg = CODEBASES[codebase]

    # Local-only checks (can't verify paths/tools on remote)
    if not remote:
        if not cfg["path"].exists():
            return json.dumps({
                "error": f"Codebase path does not exist: {cfg['path']}",
                "hint": "Clone the project first. See COMPARISON_SETUP.md section 8.",
            })

        if not _check_tool_available(tool):
            return json.dumps({
                "error": f"Tool '{tool}' not found on PATH.",
                "hint": "Install it first. See COMPARISON_SETUP.md sections 1-2.",
            })

    version = _get_tool_version(tool)
    sha = _get_git_sha()
    dir_name = _make_version_dir_name(tool, version, sha)
    version_dir = RESULTS_BASE / dir_name
    version_dir.mkdir(parents=True, exist_ok=True)

    run_id = _make_run_id(tool, codebase, version, sha)

    # Check if already running (locked read)
    with _StateLock() as state:
        if run_id in state["runs"]:
            existing = state["runs"][run_id]
            if _process_alive(existing.get("pid", 0)):
                elapsed = int(time.time() - existing["start_time"])
                return json.dumps({
                    "status": "already_running",
                    "run_id": run_id,
                    "pid": existing["pid"],
                    "elapsed_seconds": elapsed,
                    "message": f"Run '{run_id}' already in progress (PID {existing['pid']}). Use get_status().",
                })

    # Clean up stale local result files from prior runs with same run_id
    for ext in (".json", ".xml", ".txt", ".log", ".ssh.log", ".done", ".meta.json"):
        stale = version_dir / f"{run_id}{ext}"
        stale.unlink(missing_ok=True)

    # Capture the target codebase's commit at scan time (local only; for remote
    # the checkout lives on the host and is captured there). Written as a
    # sidecar next to the result file; ingest_realworld_run reads it.
    if not remote:
        codebase_sha = _get_codebase_sha(cfg["path"])
        if codebase_sha:
            (version_dir / f"{run_id}.meta.json").write_text(
                json.dumps({"codebase_commit": codebase_sha}))

    # Build command
    if tool == "sqc":
        cmd = _build_sqc_cmd(codebase, cfg, version_dir, run_id)
    elif tool == "cppcheck":
        cmd = _build_cppcheck_cmd(codebase, cfg, version_dir, run_id)
    else:  # clang-tidy
        cmd = _build_clang_tidy_cmd(codebase, cfg, version_dir, run_id)

    if remote:
        # Build SSH-wrapped command
        _, ssh_user = _load_remote_config()
        shell_cmd = _build_remote_shell_cmd(tool, cmd, version_dir, run_id)
        ssh_cmd = ["ssh"] + SSH_OPTS + [f"{ssh_user}@{resolved}", shell_cmd]

        # Log SSH command for debugging
        # NOTE: file handle intentionally left open — subprocess writes to it.
        # It will be closed when the subprocess exits and the fd is GC'd.
        ssh_log_path = version_dir / f"{run_id}.ssh.log"
        ssh_log_fh = ssh_log_path.open("w")
        ssh_log_fh.write(f"# SSH command: {' '.join(ssh_cmd)}\n")
        ssh_log_fh.flush()

        proc = subprocess.Popen(
            ssh_cmd,
            stdout=ssh_log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    else:
        # Local execution (unchanged)
        log_path = version_dir / f"{run_id}.log"
        log_fh = log_path.open("w")

        if tool == "cppcheck":
            result_path = version_dir / f"{run_id}.xml"
            result_fh = result_path.open("w")
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=result_fh,
                start_new_session=True,
            )
            result_fh.close()
        elif tool == "clang-tidy":
            result_path = version_dir / f"{run_id}.txt"
            result_fh = result_path.open("w")
            proc = subprocess.Popen(
                cmd,
                stdout=result_fh,
                stderr=log_fh,
                start_new_session=True,
            )
            result_fh.close()
        else:
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        log_fh.close()

    # Track the Popen so we can reap it when it exits (task 218); otherwise the
    # finished child lingers as a zombie and PID liveness checks misreport it.
    _register_child(proc)

    # Record new run in state (locked read-modify-write)
    start_time = time.time()
    with _StateLock() as state:
        state["runs"][run_id] = {
            "pid": proc.pid,
            "start_time": start_time,
            "tool": tool,
            "codebase": codebase,
            "version": version,
            "commit_sha": sha,
            "version_dir": str(version_dir),
            "status": "running",
            "host": resolved if remote else "local",
            "results_fetched": not remote,  # local results are always "fetched"
        }

    hosts, _ = _load_remote_config()
    host_label = f" on {hosts.get(resolved, resolved)}" if remote else ""
    return json.dumps({
        "status": "started",
        "run_id": run_id,
        "pid": proc.pid,
        "tool": tool,
        "codebase": codebase,
        "host": resolved if remote else "local",
        "version_dir": str(version_dir),
        "message": f"Started {tool} on {codebase}{host_label} (PID {proc.pid}). Use get_status() to monitor.",
    })


@mcp.tool()
def run_all(codebase: str | None = None, tool: str | None = None,
            host: str | None = None) -> str:
    """
    Run all tool×codebase combinations (or filter by codebase and/or tool).

    Args:
        codebase: Optional filter — only run against this codebase
        tool: Optional filter — only run this tool
        host: Optional remote host IP or nickname. If omitted, runs locally.

    Launches each combo as a separate subprocess. Returns summary of what was started.
    """
    tools = [tool.strip().lower()] if tool else sorted(VALID_TOOLS)
    codebases = [codebase.strip().lower()] if codebase else sorted(CODEBASES)

    # Validate
    for t in tools:
        if t not in VALID_TOOLS:
            return json.dumps({"error": f"Unknown tool '{t}'. Must be one of: {', '.join(sorted(VALID_TOOLS))}"})
    for cb in codebases:
        if cb not in CODEBASES:
            return json.dumps({"error": f"Unknown codebase '{cb}'. Must be one of: {', '.join(sorted(CODEBASES))}"})

    results = []
    for t in tools:
        for cb in codebases:
            try:
                result = json.loads(run_analysis(t, cb, host=host))
            except Exception as e:
                result = {"status": "error", "error": str(e)}
            results.append({
                "tool": t,
                "codebase": cb,
                "status": result.get("status", "error"),
                "host": result.get("host", "local"),
                "message": result.get("message") or result.get("error", ""),
            })

    started = sum(1 for r in results if r["status"] == "started")
    already = sum(1 for r in results if r["status"] == "already_running")
    errors = sum(1 for r in results if r["status"] not in ("started", "already_running"))

    return json.dumps({
        "started": started,
        "already_running": already,
        "errors": errors,
        "total": len(results),
        "runs": results,
        "message": f"Launched {started} runs ({already} already running, {errors} errors).",
    })


@mcp.tool()
def reconcile_db() -> str:
    """Ingest any completed-but-uningested realworld scan results into SQLite.

    Normally ingest happens automatically (on scan completion via the background
    watcher, and at server startup). This is the manual backstop / recovery path
    — e.g. to immediately pull in a run that finished while the server was down,
    instead of waiting for the next watcher tick. Idempotent: already-ingested
    runs are skipped. Replaces the hand-rolled BenchDB().ingest_realworld_run()
    backfill.
    """
    _reap_children()
    summary = _reconcile_pending_ingests()
    n = len(summary["ingested"])
    n_hist = len(summary["skipped_uningested"])
    hist_note = (
        f" {n_hist} older dir(s) are on disk but absent from the DB "
        "(skipped as settled history — backfill explicitly if wanted)."
        if n_hist else ""
    )
    return json.dumps({
        **summary,
        "message": (
            (f"Reconciled: {n} run(s) newly ingested of {summary['checked']} "
             f"current sqc dir(s) checked." if n else
             f"Nothing to ingest — the {summary['checked']} current sqc result "
             "dir(s) are already in the database.") + hist_note
        ),
    })


@mcp.tool()
def get_status() -> str:
    """
    Show status of all tracked runs (active, completed, failed).

    Returns per-run status with timing, plus overall summary.
    """
    # Reap any finished background children so PID liveness checks below stay
    # accurate (a zombie keeps its PID, so os.kill(pid, 0) still "succeeds").
    _reap_children()

    with _StateLock() as state:
        if not state["runs"]:
            return json.dumps({
                "status": "no_runs",
                "message": "No runs tracked. Use run_analysis() or run_all() to start.",
            })

        now = time.time()
        statuses = []
        active_count = 0
        completed_count = 0
        failed_count = 0

        for run_id, run_info in sorted(state["runs"].items()):
            pid = run_info.get("pid", 0)
            is_alive = _process_alive(pid)
            elapsed_s = int(now - run_info["start_time"])
            run_host = run_info.get("host", "local")
            is_remote = run_host != "local"

            # Determine status
            if run_info.get("status") == "cancelled":
                status = "cancelled"
                failed_count += 1
            elif is_alive:
                status = "running"
                active_count += 1
            elif is_remote and not run_info.get("results_fetched"):
                # Remote run: SSH process exited but remote job may still be running.
                # Check for .done sentinel on the remote host.
                # NOTE: This makes an SSH call per unfetched remote run. If the
                # remote is unreachable, each call can block up to ConnectTimeout
                # (10s). To avoid stalling get_status, we check the sentinel but
                # defer the SCP fetch to get_results(). Only mark status here.
                version_dir = Path(run_info.get("version_dir", ""))
                if _remote_check_done(run_host, version_dir, run_id):
                    # Remote is done — fetch results now (SCP has 30s timeout)
                    fetch_result = _fetch_remote_results(run_host, version_dir, run_id)
                    run_info["results_fetched"] = True
                    run_info["fetch_info"] = fetch_result
                    # Now check local result files
                    result_file = _get_result_file(version_dir, run_id)
                    if result_file and result_file.stat().st_size > 0:
                        status = "completed"
                        completed_count += 1
                        run_info["status"] = "completed"
                        run_info["end_time"] = (
                            _completion_time(version_dir, run_id) or now)
                    else:
                        log_file = version_dir / f"{run_id}.log"
                        if log_file.exists() and log_file.stat().st_size > 0:
                            status = "completed"
                            completed_count += 1
                            run_info["status"] = "completed"
                            run_info["end_time"] = (
                                _completion_time(version_dir, run_id) or now)
                        else:
                            status = "failed"
                            failed_count += 1
                    # Reap the zombie SSH process now that we've fetched results
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                elif elapsed_s > 14400:  # 4 hours
                    # Local SSH died, no sentinel, very old → zombie
                    status = "zombie"
                    failed_count += 1
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                else:
                    # Sentinel not found — remote still running
                    status = "running"
                    active_count += 1
            else:
                # Local run (or already-fetched remote): check result files
                version_dir = Path(run_info.get("version_dir", ""))
                result_file = _get_result_file(version_dir, run_id)
                if result_file and result_file.stat().st_size > 0:
                    status = "completed"
                    completed_count += 1
                    if run_info.get("status") != "completed":
                        run_info["status"] = "completed"
                        run_info["end_time"] = (
                            _completion_time(version_dir, run_id) or now)
                else:
                    log_file = version_dir / f"{run_id}.log"
                    if log_file.exists() and log_file.stat().st_size > 0:
                        status = "completed"
                        completed_count += 1
                        if run_info.get("status") != "completed":
                            run_info["status"] = "completed"
                            run_info["end_time"] = (
                                _completion_time(version_dir, run_id) or now)
                    else:
                        status = "failed"
                        failed_count += 1

            entry = {
                "run_id": run_id,
                "tool": run_info.get("tool"),
                "codebase": run_info.get("codebase"),
                "host": run_host,
                "status": status,
                "pid": pid,
                "elapsed_seconds": elapsed_s,
                "elapsed_human": _fmt_duration(elapsed_s),
            }

            # Add file-level progress for running sqc runs
            if status == "running" and run_info.get("tool") == "sqc":
                version_dir = Path(run_info.get("version_dir", ""))
                file_progress = _parse_sqc_log_progress(version_dir, run_id)
                if file_progress:
                    entry["file_progress"] = file_progress

            statuses.append(entry)

    # Auto-ingest completed runs into SQLite, then auto-score against the oracle.
    # Ingest is keyed on the sqc result dir (it creates the run row and pulls in
    # the sibling competitor dirs); a run_all batch finishes the fast competitor
    # scans last, so "latest dir by mtime" can be a cppcheck/clang-tidy dir —
    # locate the sqc dir explicitly so ingestion isn't silently skipped.
    score_summary = None
    if active_count == 0 and completed_count > 0:
        version_dir = _latest_completed_version_dir("sqc") or _get_version_dir()
        if version_dir:
            score_summary = _auto_ingest_to_sqlite(version_dir)

    result = {
        "active": active_count,
        "completed": completed_count,
        "failed": failed_count,
        "total": len(statuses),
        "runs": statuses,
    }
    if score_summary:
        result["measured"] = score_summary
    return json.dumps({
        **result,
        "message": (
            f"{active_count} running, {completed_count} completed, {failed_count} failed "
            f"out of {len(statuses)} tracked runs."
        ),
    })


@mcp.tool()
def get_results(run: str = "latest", project: str | None = None) -> str:
    """
    Get results for a realworld benchmark run.

    Args:
        run: Run identifier — "latest" (default), sqc version (e.g. "0.3.28"),
             commit SHA, or version dir name (e.g. "sqc-0.3.28-ae46ae3c").
        project: Optional filter — only show results for this codebase
                 (e.g. "curl", "hostap", "mosquitto", "sqlite", "libcrc").

    Returns per-project violation counts and per-rule breakdown from SQLite.
    Falls back to filesystem result files if not in database.
    """
    # ── Try SQLite first ─────────────────────────────────────────────────
    try:
        db = _get_db()
        run_id = db.resolve_realworld_run(run)
        if run_id:
            summary = db.get_realworld_run_summary(run_id)
            if "error" not in summary:
                run_info = summary["run"]
                projects = []
                for r in summary["projects"]:
                    if project and r["project"] != project:
                        continue
                    if r["tool"] != "sqc":
                        continue
                    proj_rules = summary["per_project_rules"].get(r["project"], [])
                    proj_entry = {
                        "project": r["project"],
                        "violation_count": r["violation_count"],
                        "c_files": r["c_files"],
                        "loc": r["loc"],
                        "top_rules": {
                            rr["rule_id"]: rr["count"]
                            for rr in proj_rules[:20]
                        },
                        "total_rules": len(proj_rules),
                    }
                    if r.get("duration_s") is not None:
                        proj_entry["duration_s"] = r["duration_s"]
                    projects.append(proj_entry)

                # Overall rule summary (filtered by project if given)
                if project:
                    rule_summary = db.get_realworld_rule_summary(run_id, project)
                else:
                    rule_summary = summary["rule_summary"]

                filtered_total = sum(p["violation_count"] for p in projects)

                return json.dumps({
                    "backend": "sqlite",
                    "run_id": run_id,
                    "sqc_version": run_info["sqc_version"],
                    "commit_sha": run_info.get("commit_sha"),
                    "scanned_at": run_info.get("scanned_at"),
                    "total_violations": filtered_total,
                    "projects": projects,
                    "top_rules": [
                        {"rule_id": r["rule_id"], "count": r["count"]}
                        for r in rule_summary[:20]
                    ],
                    "total_rules": len(rule_summary),
                })
    except Exception:
        pass

    # ── Legacy fallback: filesystem ──────────────────────────────────────
    version_dir = _resolve_version_dir(run if run != "latest" else None)
    if not version_dir:
        return json.dumps({
            "error": "No results found. Run run_analysis() or run_all() first.",
            "hint": "Or specify a version/run that exists in the database.",
        })

    all_results = []
    for f in sorted(version_dir.iterdir()):
        if f.is_file() and f.suffix in (".json", ".xml", ".txt") and not f.stem.endswith(".log"):
            if f.suffix == ".txt" and f.stem.endswith(".log"):
                continue
            run_name = f.stem
            parsed = _parse_result_file(run_name, f)
            tool_name, codebase_name = _parse_run_id(run_name)
            if project and codebase_name != project:
                continue

            all_results.append({
                "run_id": run_name,
                "tool": tool_name,
                "codebase": codebase_name,
                "total_violations": parsed["total"],
                "top_rules": dict(list(parsed["per_rule"].items())[:10]),
                "total_rules": len(parsed["per_rule"]),
            })

    _auto_ingest_to_sqlite(version_dir)

    return json.dumps({
        "backend": "filesystem",
        "version_dir": str(version_dir),
        "dir_name": version_dir.name,
        "runs": all_results,
        "total_runs": len(all_results),
    })


def _auto_ingest_to_sqlite(version_dir: Path) -> str | None:
    """Ingest a realworld result dir into SQLite if not already present, then
    auto-score it against the ground-truth oracle. Returns a one-line measured
    precision/recall summary (or None if nothing was ingested/scored)."""
    try:
        db = _get_db()
        dir_name = version_dir.name

        # sqc result files on disk for this dir (the projects we could store).
        json_files = [f for f in version_dir.glob("sqc-*.json")
                      if not f.name.endswith((".meta.json", ".score.json"))]
        if not json_files:
            return None
        disk_projects = {f.stem.split("-")[1] for f in json_files
                         if len(f.stem.split("-")) >= 3}

        # Extract per-codebase durations + size metrics from state / checkout
        durations = _extract_run_durations()
        metrics = _extract_run_metrics()
        machine = {"hostname": os.uname().nodename}

        # Re-use the existing run row for this dir rather than skipping when one
        # is found: a partial earlier ingest (e.g. a single-codebase smoke run)
        # must not permanently block the later full sweep from landing. Merge
        # only the projects not already stored, so repeated get_status polls
        # don't re-parse / re-score an already-complete run.
        existing = next((r for r in db.list_realworld_runs()
                         if r.get("notes") and dir_name in r["notes"]), None)
        if existing:
            run_id = existing["id"]
            stored = {r["project"] for r in db.get_realworld_results(run_id)
                      if r["tool"] == "sqc"}
            missing = disk_projects - stored
            if not missing:
                return None  # Already complete — nothing new to ingest
            db.ingest_realworld_run(dir_name, str(version_dir),
                                    machine=machine, durations=durations,
                                    metrics=metrics, run_id=run_id,
                                    only_projects=missing)
        else:
            run_id = db.ingest_realworld_run(dir_name, str(version_dir),
                                             machine=machine, durations=durations,
                                             metrics=metrics)
        # Attach cppcheck/clang-tidy rows from the same run_all batch (if any)
        # so the run row carries a full tool-vs-tool throughput comparison.
        _ingest_competitors(db, run_id)
        return _auto_score_run(db, run_id, version_dir)
    except Exception:
        return None  # Don't fail the MCP tool if ingestion/scoring fails


def _auto_score_run(db, run_id: int, version_dir: Path) -> str | None:
    """Score a freshly-ingested run against the ground-truth oracle, drop a
    <dir>.score.json sidecar, and return a one-line summary. Measures precision
    over the oracle-labeled subset of the run's findings; never adjudicates new
    findings (that requires judgment — use realworld-unlabeled + import-labels).
    """
    try:
        score = db.score_realworld_run(run_id)
        if score.get("error"):
            return None
        (version_dir / f"{version_dir.name}.score.json").write_text(
            json.dumps(score, indent=2, default=str))
        ov = score["overall"]
        labeled = ov["labeled_total"]
        if not labeled:
            n = len(score.get("warnings", []))
            return ("measured precision: no oracle labels cover this run's "
                    f"commits yet ({n} project(s) unscored)")
        prec = ov["precision_pct"]
        rec = ov["recall_pct"]
        rec_s = f", recall {rec}% ({ov['tp_detected']}/{ov['tp_labels']})" if rec is not None else ""
        return (f"measured precision {prec}% "
                f"(TP {ov['labeled_tp']}/{labeled} labeled of "
                f"{ov['run_findings']} findings){rec_s}")
    except Exception:
        return None


# ── Ingest reconciliation ────────────────────────────────────────────────────
# The detached scan child (start_new_session=True) only writes its JSON result
# to RESULTS_BASE and exits — it never touches SQLite. Ingest is otherwise a
# side effect of an interactive get_status()/get_results() poll. So a scan that
# finishes while no poll is arriving (it completed overnight, the session ended,
# or the server was restarted) leaves its result stranded on disk, un-ingested
# (this happened twice; the symptom is a run stuck "running" in the state file
# with a long-dead PID). Reconciliation makes ingest happen on completion
# regardless of polling: it runs once at startup (catches runs finished while
# the server was down), continuously via a background watcher (catches runs that
# finish while the server is up but idle), and on demand via reconcile_db().

def _finalize_dead_run_statuses() -> None:
    """Flip state-file runs whose PID is dead and whose result file exists from
    'running' to 'completed', so a finished-but-never-polled run stops being
    reported as active and the watcher's edge trigger stays accurate."""
    try:
        with _StateLock() as state:
            now = time.time()
            for run_id, info in state.get("runs", {}).items():
                if info.get("status") in ("completed", "cancelled"):
                    continue
                if _process_alive(info.get("pid", 0)):
                    continue
                version_dir = Path(info.get("version_dir", ""))
                result_file = _get_result_file(version_dir, run_id)
                log_file = version_dir / f"{run_id}.log"
                done = (result_file and result_file.stat().st_size > 0) or (
                    log_file.exists() and log_file.stat().st_size > 0)
                if done:
                    info["status"] = "completed"
                    info["end_time"] = _completion_time(version_dir, run_id) or now
    except Exception:
        pass


def _parse_sqc_version(v: str) -> tuple:
    """Parse a dotted sqc version (`0.4.68`) into a comparable int tuple. Unknown
    pieces sort low so a malformed version never outranks a real one."""
    parts = []
    for p in (v or "").split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(-1)
    return tuple(parts)


def _dir_version_sha(dir_name: str) -> tuple[str, str]:
    """Split `sqc-<version>-<sha>` into (version, sha)."""
    parts = dir_name.split("-")
    return (parts[1], parts[2]) if len(parts) >= 3 else ("", "")


def _reconcile_pending_ingests() -> dict:
    """Ingest the current completed-but-uningested sqc result dir(s) on disk.

    Scope is deliberately forward-only: a dir is ingested when its version is at
    or above the newest version already in the DB (the just-finished run that a
    missing poll would otherwise strand). Dirs *older* than the DB high-water
    mark that are absent from the DB are NOT silently backfilled — that history
    is settled (and may have been purged on purpose); they are surfaced under
    `skipped_uningested` so a backfill stays an explicit decision. Idempotent:
    _auto_ingest_to_sqlite no-ops / merges-missing-projects on dirs already
    stored; dirs with a still-running scan are skipped so no half-written result
    file is parsed.
    """
    _finalize_dead_run_statuses()
    summary = {"checked": 0, "ingested": [], "skipped_uningested": []}
    if not RESULTS_BASE.exists():
        return summary

    # DB high-water version and the set of (version, sha) already stored.
    try:
        db = _get_db()
        db_runs = db.list_realworld_runs()
    except Exception:
        db_runs = []
    ingested_keys = {(r.get("sqc_version"), r.get("commit_sha")) for r in db_runs}
    max_ingested = max(
        (_parse_sqc_version(r.get("sqc_version")) for r in db_runs), default=()
    )

    # version_dirs of scans still actively writing — don't touch a partial file.
    live_dirs = set()
    try:
        state = _read_state()
        for info in state.get("runs", {}).values():
            if info.get("tool") == "sqc" and _process_alive(info.get("pid", 0)):
                live_dirs.add(info.get("version_dir", ""))
    except Exception:
        pass

    for version_dir in sorted(RESULTS_BASE.iterdir()):
        if not version_dir.is_dir() or not version_dir.name.startswith("sqc-"):
            continue
        if str(version_dir) in live_dirs:
            continue
        if not any(version_dir.glob("sqc-*.json")):
            continue
        ver, sha = _dir_version_sha(version_dir.name)
        key = (ver, sha)
        is_current = _parse_sqc_version(ver) >= max_ingested
        if not is_current and key not in ingested_keys:
            # Present on disk, absent from DB, older than the high-water mark.
            summary["skipped_uningested"].append(version_dir.name)
            continue
        if not is_current:
            continue  # settled history already in the DB — leave it untouched
        summary["checked"] += 1
        try:
            measured = _auto_ingest_to_sqlite(version_dir)
        except Exception:
            measured = None
        # Non-None means a fresh ingest was scored; record it. (A fresh ingest
        # whose codebase has no oracle labels still lands in the DB but returns
        # None — the data guarantee holds even when the summary can't list it.)
        if measured is not None:
            summary["ingested"].append({"dir": version_dir.name, "measured": measured})
    return summary


_WATCHER_INTERVAL_S = 60
_watcher_started = False
_watcher_lock = threading.Lock()


def _watcher_loop() -> None:
    """Background daemon: when a tracked sqc scan finishes and nothing else is
    scanning, reconcile pending ingests. Edge-triggered off the live-run set so
    an idle server does no repeated DB work."""
    prev_live: set[str] = set()
    while True:
        time.sleep(_WATCHER_INTERVAL_S)
        try:
            _reap_children()
            state = _read_state()
            now_live = {
                rid for rid, info in state.get("runs", {}).items()
                if info.get("tool") == "sqc" and _process_alive(info.get("pid", 0))
            }
            finished = prev_live - now_live  # was scanning last tick, done now
            prev_live = now_live
            if finished and not now_live:
                _reconcile_pending_ingests()
        except Exception:
            pass


def _start_watcher() -> None:
    """Start the ingest watcher once (idempotent)."""
    global _watcher_started
    with _watcher_lock:
        if _watcher_started:
            return
        threading.Thread(
            target=_watcher_loop, name="rw-ingest-watcher", daemon=True
        ).start()
        _watcher_started = True


def _extract_run_durations(tool: str = "sqc") -> dict[str, float]:
    """Extract per-codebase durations from the state file.

    Returns dict mapping codebase name to elapsed seconds for completed runs
    of `tool`. end_time is the mtime of the run's output file (see
    _completion_time), so this is real process runtime regardless of poll time.
    """
    durations = {}
    try:
        state = _read_state()
        for run_id, info in state.get("runs", {}).items():
            if (info.get("tool") == tool
                    and info.get("status") == "completed"
                    and "start_time" in info
                    and "end_time" in info):
                codebase = info.get("codebase")
                if codebase:
                    durations[codebase] = round(info["end_time"] - info["start_time"], 1)
    except Exception:
        pass
    return durations


def _sqc_glob_to_regex(pattern: str) -> "re.Pattern":
    """Python port of sqc's suppression::glob_to_regex(pattern, is_path=True).

    Mirrors the exact path-glob semantics sqc applies to --exclude (src/analyze/
    suppression.rs): `**` spans `/`, a lone `*`/`?` stays within one segment, and
    the pattern is anchored as a suffix preceded by `/` or start-of-string. Kept
    in lockstep so the post-exclude fileset counted here matches what sqc scans.
    """
    out: list[str] = []
    chars = list(pattern)
    n = len(chars)
    i = 0
    while i < n:
        c = chars[i]
        if c == "*":
            if i + 1 < n and chars[i + 1] == "*":
                out.append(".*")
                i += 2
                if i < n and chars[i] == "/":
                    out.append("/?")
                    i += 1
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            if c in ".()+|[]{}^$\\":
                out.append("\\")
            out.append(c)
            i += 1
    return re.compile(f"(?:^|/){''.join(out)}$")


def _sqc_exclude_patterns(cfg: dict) -> list["re.Pattern"]:
    """Compile the --exclude globs from a codebase's sqc extra_args.

    These define the fileset sqc actually scans; applying them here keeps the
    DB's c_files/loc aligned with the analyzed set rather than the whole repo.
    For our codebases the competitor tools exclude the same files (e.g. Lua's
    onelua.c/ltests.c/testes), so the LOC denominator stays shared across tools.
    """
    args = cfg.get("sqc", {}).get("extra_args", [])
    return [
        _sqc_glob_to_regex(args[i + 1])
        for i in range(len(args) - 1)
        if args[i] == "--exclude"
    ]


def _count_c_source(cfg: dict) -> tuple[int, int]:
    """Count (c_files, loc) for a codebase's own C source.

    Uses the curated cppcheck source_dirs (which deliberately exclude vendored
    deps and test scaffolding) so the LOC denominator is identical across tools
    — the right basis for a fair LOC/s throughput comparison. Falls back to the
    project root if no source_dirs are configured. loc is physical lines across
    .c and .h files; c_files counts .c translation units. sqc --exclude globs
    are applied so the count reflects the post-exclude set sqc actually scanned.
    """
    path = str(cfg["path"])
    dirs = _expand(cfg.get("cppcheck", {}).get("source_dirs", []), path) or [path]
    excludes = _sqc_exclude_patterns(cfg)
    c_files = 0
    loc = 0
    seen: set[str] = set()
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for f in files:
                if not f.endswith((".c", ".h")):
                    continue
                fp = os.path.join(root, f)
                if fp in seen:
                    continue
                seen.add(fp)
                normalized = fp.replace("\\", "/")
                if any(p.search(normalized) for p in excludes):
                    continue
                if f.endswith(".c"):
                    c_files += 1
                try:
                    with open(fp, "rb") as fh:
                        loc += sum(1 for _ in fh)
                except OSError:
                    pass
    return c_files, loc


def _extract_run_metrics() -> dict[str, dict]:
    """Per-codebase {c_files, loc} for completed sqc runs in the current state.

    Computed from the live checkout, so it reflects the exact codebase commit
    that was scanned. Used to populate realworld_results.c_files / .loc, which
    were previously hardcoded to 0.
    """
    metrics: dict[str, dict] = {}
    try:
        state = _read_state()
        for _run_id, info in state.get("runs", {}).items():
            if info.get("tool") != "sqc" or info.get("status") != "completed":
                continue
            codebase = info.get("codebase")
            cfg = CODEBASES.get(codebase)
            if not codebase or not cfg or codebase in metrics:
                continue
            c_files, loc = _count_c_source(cfg)
            metrics[codebase] = {"c_files": c_files, "loc": loc}
    except Exception:
        pass
    return metrics


def _ingest_competitors(db, run_id: int) -> int:
    """Attach cppcheck + clang-tidy per-project rows to the sqc run row `run_id`.

    Uses the most-recent completed competitor runs in the current state (the
    run_all batch that produced this sqc run), giving the run row a full
    tool-vs-tool comparison: violation_count + loc + duration per project.
    loc reuses _count_c_source so the LOC/s denominator is identical across
    tools. Per-finding detail isn't stored — competitors aren't scored against
    the sqc oracle (which is keyed on CERT rule ids), and the historical
    competitor rows likewise carry counts only. Returns rows written.
    """
    written = 0
    try:
        state = _read_state()
        runs = state.get("runs", {})
        for tool in ("cppcheck", "clang-tidy"):
            # Most-recently-completed run per codebase for this tool.
            latest: dict[str, tuple[str, dict]] = {}
            for rid_name, info in runs.items():
                if info.get("tool") != tool or info.get("status") != "completed":
                    continue
                cb = info.get("codebase")
                if not cb:
                    continue
                if (cb not in latest
                        or info.get("end_time", 0) > latest[cb][1].get("end_time", 0)):
                    latest[cb] = (rid_name, info)
            for cb, (rid_name, info) in latest.items():
                cfg = CODEBASES.get(cb)
                if not cfg:
                    continue
                version_dir = Path(info.get("version_dir", ""))
                rf = _get_result_file(version_dir, rid_name)
                if not rf:
                    continue
                vcount = _parse_result_file(rid_name, rf).get("total", 0)
                c_files, loc = _count_c_source(cfg)
                duration = None
                if "start_time" in info and "end_time" in info:
                    duration = round(info["end_time"] - info["start_time"], 1)
                commit = _get_codebase_sha(cfg["path"]) or db.live_codebase_commit(cb)
                db.insert_realworld_result(run_id, cb, tool, c_files, loc,
                                           vcount, duration, commit)
                written += 1
    except Exception:
        pass
    return written


@mcp.tool()
def compare_runs(base: str, target: str,
                 project: str | None = None) -> str:
    """
    Compare two realworld benchmark runs showing per-rule violation deltas.

    Args:
        base: Base (older) run — sqc version (e.g. "0.3.27"), commit SHA,
              version dir name, or "latest"
        target: Target (newer) run — same formats as base
        project: Optional filter — only compare this codebase

    Returns overall and per-project violation deltas with per-rule breakdown.
    Positive delta = regression (more violations), negative = improvement.
    """
    # ── Try SQLite first ─────────────────────────────────────────────────
    try:
        db = _get_db()
        base_id = db.resolve_realworld_run(base)
        target_id = db.resolve_realworld_run(target)
        if base_id and target_id:
            if base_id == target_id:
                return json.dumps({
                    "error": "Base and target resolve to the same run.",
                    "resolved_id": base_id,
                })

            base_run = db.get_realworld_run(base_id)
            target_run = db.get_realworld_run(target_id)

            # Overall comparison
            overall = db.compare_realworld_runs(base_id, target_id, project)

            # Per-project comparisons
            base_results = db.get_realworld_results(base_id)
            target_results = db.get_realworld_results(target_id)

            # Collect project names (sqc only)
            base_projects = {r["project"] for r in base_results if r["tool"] == "sqc"}
            target_projects = {r["project"] for r in target_results if r["tool"] == "sqc"}
            all_projects = sorted(base_projects | target_projects)
            if project:
                all_projects = [p for p in all_projects if p == project]

            per_project = []
            for proj in all_projects:
                comp = db.compare_realworld_runs(base_id, target_id, proj)
                per_project.append({
                    "project": proj,
                    "base_total": comp["base_total"],
                    "target_total": comp["target_total"],
                    "delta": comp["delta_total"],
                    "top_rule_changes": comp["rule_deltas"][:15],
                })

            return json.dumps({
                "backend": "sqlite",
                "base": {
                    "run_id": base_id,
                    "sqc_version": base_run["sqc_version"],
                    "commit_sha": base_run.get("commit_sha"),
                },
                "target": {
                    "run_id": target_id,
                    "sqc_version": target_run["sqc_version"],
                    "commit_sha": target_run.get("commit_sha"),
                },
                "overall": {
                    "base_total": overall["base_total"],
                    "target_total": overall["target_total"],
                    "delta": overall["delta_total"],
                    "top_rule_changes": overall["rule_deltas"][:20],
                },
                "per_project": per_project,
            })
    except Exception:
        pass

    # ── Legacy fallback: filesystem ──────────────────────────────────────
    base_dir = _resolve_version_dir(base)
    target_dir = _resolve_version_dir(target)

    if not base_dir:
        return json.dumps({
            "error": f"Could not resolve base version '{base}'.",
            "available": [d["dir_name"] for d in _list_version_dirs()],
        })
    if not target_dir:
        return json.dumps({
            "error": f"Could not resolve target version '{target}'.",
            "available": [d["dir_name"] for d in _list_version_dirs()],
        })
    if base_dir == target_dir:
        return json.dumps({
            "error": "Base and target resolve to the same directory.",
            "resolved": str(base_dir),
        })

    base_results = _load_version_results(base_dir)
    target_results = _load_version_results(target_dir)

    comparisons = []
    all_keys = set(base_results) | set(target_results)
    for key in sorted(all_keys):
        k_tool, k_codebase = key
        if project and k_codebase != project:
            continue

        b = base_results.get(key, {"total": 0, "per_rule": {}})
        t = target_results.get(key, {"total": 0, "per_rule": {}})

        all_rules = set(b["per_rule"]) | set(t["per_rule"])
        rule_deltas = []
        for r in sorted(all_rules):
            b_count = b["per_rule"].get(r, 0)
            t_count = t["per_rule"].get(r, 0)
            if b_count != t_count:
                rule_deltas.append({
                    "rule": r,
                    "base": b_count,
                    "target": t_count,
                    "delta": t_count - b_count,
                })
        rule_deltas.sort(key=lambda x: abs(x["delta"]), reverse=True)

        comparisons.append({
            "tool": k_tool,
            "codebase": k_codebase,
            "base_total": b["total"],
            "target_total": t["total"],
            "delta": t["total"] - b["total"],
            "top_rule_changes": rule_deltas[:10],
        })

    return json.dumps({
        "backend": "filesystem",
        "base_dir": base_dir.name,
        "target_dir": target_dir.name,
        "comparisons": comparisons,
        "total_compared": len(comparisons),
    })


@mcp.tool()
def list_runs(limit: int = 10, compact: bool = True, verbose: bool = False) -> str:
    """
    List realworld benchmark runs, newest first (from SQLite DB and filesystem).

    By default returns only the most recent `limit` runs in a compact shape.
    Use sqc_version or dir names as identifiers in compare_runs()/get_results().

    Args:
        limit: Max runs to return, newest first. Use 0 for all. Default 10.
        compact: Trim each run to the fields callers actually use
                 (sqc_version, project_count, total_violations). Default True.
        verbose: Alias for compact=False — return every field, incl. the
                 per-run `projects` list, commit_sha, and notes.
    """
    if verbose:
        compact = False

    all_runs = []
    seen_versions = set()

    # SQLite runs
    try:
        db = _get_db()
        for r in db.list_realworld_runs():
            results = db.get_realworld_results(r["id"])
            sqc_results = [rr for rr in results if rr["tool"] == "sqc"]
            total_violations = sum(rr["violation_count"] for rr in sqc_results)
            projects = [rr["project"] for rr in sqc_results]
            all_runs.append({
                "run_id": r["id"],
                "sqc_version": r["sqc_version"],
                "commit_sha": r.get("commit_sha"),
                "scanned_at": r.get("scanned_at"),
                "projects": projects,
                "project_count": len(projects),
                "total_violations": total_violations,
                "notes": r.get("notes"),
                "backend": "sqlite",
            })
            seen_versions.add(r["sqc_version"])
    except Exception:
        pass

    # Filesystem dirs (only add if not already in SQLite)
    for d in _list_version_dirs():
        # Extract version from dir name: sqc-{version}-{sha}
        parts = d["dir_name"].split("-", 2)
        version = parts[1] if len(parts) > 1 else d["dir_name"]
        if version not in seen_versions:
            d["backend"] = "filesystem"
            all_runs.append(d)

    if not all_runs:
        return json.dumps({
            "runs": [],
            "message": "No benchmark runs found. Use run_all() to start one.",
        })

    # Newest first. SQLite rows carry `scanned_at`; filesystem rows carry
    # `modified` — both sort lexically in the same direction.
    all_runs.sort(
        key=lambda r: r.get("scanned_at") or r.get("modified") or "",
        reverse=True,
    )

    total = len(all_runs)
    shown = all_runs if limit <= 0 else all_runs[:limit]

    if compact:
        keep = ("run_id", "sqc_version", "project_count", "total_violations",
                "scanned_at", "dir_name")
        shown = [{k: r[k] for k in keep if k in r} for r in shown]

    msg = (
        f"{total} benchmark run(s) total; showing {len(shown)} (newest first). "
        "Use sqc_version or dir names in compare_runs() and get_results()."
    )
    if 0 < limit < total:
        msg += f" Pass limit=0 to see all {total}."

    return json.dumps({
        "runs": shown,
        "count": len(shown),
        "total": total,
        "message": msg,
    })


@mcp.tool()
def get_dashboard(run: str = "latest", compare: str | None = None,
                  top: int = 25) -> str:
    """
    Real-world FP tracking dashboard: top rules with deltas and per-project breakdown.

    Args:
        run: Target run — "latest" (default), sqc version, commit SHA, or run ID.
        compare: Base run to compare against. Default: previous run.
        top: Number of top rules to show (default 25).

    Returns top FP-producing rules, per-project summaries, and timing data.
    """
    try:
        db = _get_db()
        target_id = db.resolve_realworld_run(run)
        if not target_id:
            return json.dumps({"error": f"Could not resolve run '{run}'."})

        base_id = None
        if compare:
            base_id = db.resolve_realworld_run(compare)
            if not base_id:
                return json.dumps({"error": f"Could not resolve base run '{compare}'."})
        else:
            runs = db.list_realworld_runs()
            for i, r in enumerate(runs):
                if r["id"] == target_id and i + 1 < len(runs):
                    base_id = runs[i + 1]["id"]
                    break

        dashboard = db.get_realworld_dashboard(target_id, base_id, top_n=top)
        return json.dumps(dashboard, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_rule_trend(rule_id: str, project: str | None = None) -> str:
    """
    Get a rule's violation count trend across all realworld benchmark runs.

    Args:
        rule_id: CERT C rule ID (e.g. "EXP34-C", "INT32-C")
        project: Optional filter — only show trend for this codebase

    Returns per-version violation counts, showing how a rule's detections
    change across sqc versions. Useful for tracking FP reduction progress.
    """
    try:
        db = _get_db()
        rows = db.get_realworld_rule_trend(rule_id, project)
        if not rows:
            return json.dumps({
                "rule_id": rule_id,
                "project": project,
                "message": "No data found for this rule. Check rule_id spelling.",
            })

        # Group by version for summary
        by_version: dict[str, dict] = {}
        for r in rows:
            ver = r["sqc_version"]
            if ver not in by_version:
                by_version[ver] = {"sqc_version": ver, "run_id": r["run_id"],
                                    "total": 0, "per_project": {}}
            by_version[ver]["total"] += r["count"]
            by_version[ver]["per_project"][r["project"]] = r["count"]

        versions = list(by_version.values())

        # Compute deltas between consecutive versions
        for i in range(1, len(versions)):
            versions[i]["delta"] = versions[i]["total"] - versions[i - 1]["total"]
        if versions:
            versions[0]["delta"] = 0

        return json.dumps({
            "rule_id": rule_id,
            "project": project,
            "versions": versions,
            "total_runs": len(versions),
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_project_history(project: str) -> str:
    """
    Get violation count history for a project across all sqc versions.

    Args:
        project: Codebase name (e.g. "curl", "hostap", "mosquitto", "sqlite", "libcrc")

    Returns per-version total violation count and top rule changes.
    """
    try:
        db = _get_db()
        runs = db.list_realworld_runs()
        if not runs:
            return json.dumps({"error": "No runs in database."})

        history = []
        for run in runs:
            results = db.get_realworld_results(run["id"])
            sqc_result = next((r for r in results
                               if r["project"] == project and r["tool"] == "sqc"), None)
            if not sqc_result:
                continue
            rule_summary = db.get_realworld_rule_summary(run["id"], project)
            entry = {
                "sqc_version": run["sqc_version"],
                "run_id": run["id"],
                "violation_count": sqc_result["violation_count"],
                "top_rules": [
                    {"rule_id": r["rule_id"], "count": r["count"]}
                    for r in rule_summary[:10]
                ],
            }
            if sqc_result.get("duration_s") is not None:
                entry["duration_s"] = sqc_result["duration_s"]
            history.append(entry)

        # Compute deltas
        for i in range(1, len(history)):
            history[i]["delta"] = (history[i]["violation_count"]
                                   - history[i - 1]["violation_count"])
        if history:
            history[0]["delta"] = 0

        return json.dumps({
            "project": project,
            "history": history,
            "total_runs": len(history),
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def cancel_run(run_id: str | None = None) -> str:
    """
    Cancel a specific run or all active runs.

    Args:
        run_id: Run ID to cancel. If omitted, cancels ALL active runs.
    """
    with _StateLock() as state:
        if not state["runs"]:
            return json.dumps({
                "status": "no_runs",
                "message": "No runs tracked.",
            })

        cancelled = []
        not_running = []

        targets = {}
        if run_id:
            if run_id not in state["runs"]:
                return json.dumps({
                    "error": f"Run '{run_id}' not found.",
                    "available": sorted(state["runs"].keys()),
                })
            targets = {run_id: state["runs"][run_id]}
        else:
            targets = dict(state["runs"])

        for rid, info in targets.items():
            pid = info.get("pid", 0)
            if _process_alive(pid):
                _kill_process_group(pid)
                info["status"] = "cancelled"
                cancelled.append(rid)
            else:
                not_running.append(rid)

    return json.dumps({
        "cancelled": cancelled,
        "not_running": not_running,
        "message": f"Cancelled {len(cancelled)} run(s). {len(not_running)} were not running.",
    })


@mcp.tool()
def purge_run(run_id: str | None = None, zombies: bool = False) -> str:
    """
    Remove stale/zombie runs from tracking state (does not delete result files).

    Use this to clean up runs that are stuck as "running" but whose processes
    are actually dead (zombies). Does NOT remove result files on disk.
    Completed and cancelled runs are never purged by zombies=True — only
    runs that never reached a terminal status are candidates.

    Args:
        run_id: Specific run ID to purge. If omitted, requires zombies=True.
        zombies: If True, purge all zombie runs (dead process, not completed/cancelled,
                 elapsed > 4 hours). Ignored if run_id is specified.
    """
    zombie_threshold = 14400  # 4 hours

    _reap_children()  # reap before classifying so liveness checks are accurate
    with _StateLock() as state:
        if not state["runs"]:
            return json.dumps({"status": "no_runs", "message": "No runs tracked."})

        purged = []

        if run_id:
            if run_id not in state["runs"]:
                return json.dumps({
                    "error": f"Run '{run_id}' not found.",
                    "available": sorted(state["runs"].keys()),
                })
            info = state["runs"].pop(run_id)
            purged.append({
                "run_id": run_id,
                "host": info.get("host", "local"),
                "elapsed": _fmt_duration(int(time.time() - info["start_time"])),
            })
        elif zombies:
            now = time.time()
            to_purge = []
            for rid, info in state["runs"].items():
                pid = info.get("pid", 0)
                elapsed_s = int(now - info["start_time"])
                is_alive = _process_alive(pid)
                is_remote = info.get("host", "local") != "local"
                already_done = info.get("status") in ("completed", "cancelled")

                # Skip completed/cancelled runs — they're not zombies
                if already_done:
                    continue

                if not is_alive and elapsed_s > zombie_threshold:
                    if is_remote and not info.get("results_fetched"):
                        # Remote zombie: SSH dead, no results fetched, old
                        to_purge.append(rid)
                    elif not is_remote:
                        # Local zombie: process dead, old
                        to_purge.append(rid)

            for rid in to_purge:
                info = state["runs"].pop(rid)
                purged.append({
                    "run_id": rid,
                    "host": info.get("host", "local"),
                    "elapsed": _fmt_duration(int(time.time() - info["start_time"])),
                })
        else:
            return json.dumps({
                "error": "Specify run_id or set zombies=True to purge stale runs.",
            })

    return json.dumps({
        "purged": purged,
        "count": len(purged),
        "message": f"Purged {len(purged)} run(s) from tracking state.",
    })


@mcp.tool()
def clear_results() -> str:
    """
    Remove old result directories (protects directories with active runs).
    """
    if not RESULTS_BASE.exists():
        return json.dumps({
            "status": "nothing_to_clear",
            "message": f"{RESULTS_BASE} does not exist.",
        })

    # Find active version dirs
    with _StateLock() as state:
        active_dirs = set()
        for info in state["runs"].values():
            if _process_alive(info.get("pid", 0)):
                active_dirs.add(info.get("version_dir"))

        removed = []
        skipped = []
        errors = []

        for entry in sorted(RESULTS_BASE.iterdir()):
            if not entry.is_dir():
                continue
            if str(entry) in active_dirs:
                skipped.append(entry.name)
                continue
            try:
                size = _dir_size_human(entry)
                shutil.rmtree(entry)
                removed.append({"name": entry.name, "size": size})
            except Exception as e:
                errors.append(f"Failed to remove {entry.name}: {e}")

        # Clean up state entries for removed dirs
        to_remove = []
        for rid, info in state["runs"].items():
            vdir = info.get("version_dir", "")
            if not Path(vdir).exists() and not _process_alive(info.get("pid", 0)):
                to_remove.append(rid)
        for rid in to_remove:
            del state["runs"][rid]

    return json.dumps({
        "removed": removed,
        "skipped_active": skipped,
        "state_entries_cleaned": len(to_remove),
        "errors": errors,
        "message": f"Removed {len(removed)} directories, skipped {len(skipped)} active.",
    })


@mcp.tool()
def deploy_sqc(host: str | None = None) -> str:
    """
    Deploy sqc binary + manifest TOML to remote host(s).

    Args:
        host: Remote host IP or nickname. If omitted, deploys to ALL remote hosts.

    Copies target/release/sqc and rules_templates/rules-benchmark.toml, then verifies
    by running sqc --version on the remote.
    """
    if not SQC_BIN.exists():
        return json.dumps({
            "error": f"sqc binary not found at {SQC_BIN}. Run 'cargo build --release' first.",
        })
    if not MANIFEST.exists():
        return json.dumps({
            "error": f"Manifest not found at {MANIFEST}.",
        })

    hosts, ssh_user = _load_remote_config()
    if not hosts:
        return json.dumps({
            "error": "Remote execution not configured. Create mcp_servers/remote_hosts.json.",
        })

    targets: list[str] = []
    if host:
        resolved = _resolve_host(host)
        if isinstance(resolved, dict):
            return json.dumps(resolved)
        if resolved == "local":
            return json.dumps({"error": "deploy_sqc is for remote hosts only."})
        targets = [resolved]
    else:
        targets = list(hosts.keys())

    results = []
    for ip in targets:
        name = hosts.get(ip, ip)
        remote = f"{ssh_user}@{ip}"
        entry = {"host": ip, "name": name, "status": "unknown", "details": []}

        # scp binary
        try:
            r = subprocess.run(
                ["scp"] + SSH_OPTS + [str(SQC_BIN), f"{remote}:{SQC_BIN}"],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0:
                entry["details"].append("binary: copied")
            else:
                entry["details"].append(f"binary: FAILED ({r.stderr.strip()})")
                entry["status"] = "failed"
                results.append(entry)
                continue
        except Exception as e:
            entry["details"].append(f"binary: FAILED ({e})")
            entry["status"] = "failed"
            results.append(entry)
            continue

        # scp manifest
        try:
            r = subprocess.run(
                ["scp"] + SSH_OPTS + [str(MANIFEST), f"{remote}:{MANIFEST}"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                entry["details"].append("manifest: copied")
            else:
                entry["details"].append(f"manifest: FAILED ({r.stderr.strip()})")
        except Exception as e:
            entry["details"].append(f"manifest: FAILED ({e})")

        # Verify
        try:
            r = subprocess.run(
                ["ssh"] + SSH_OPTS + [remote, str(SQC_BIN), "--version"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                version_str = r.stdout.strip()
                entry["details"].append(f"verify: {version_str}")
                entry["status"] = "ok"
            else:
                entry["details"].append(f"verify: FAILED ({r.stderr.strip()})")
                entry["status"] = "partial"
        except Exception as e:
            entry["details"].append(f"verify: FAILED ({e})")
            entry["status"] = "partial"

        results.append(entry)

    ok = sum(1 for r in results if r["status"] == "ok")
    return json.dumps({
        "deployed": ok,
        "total": len(results),
        "hosts": results,
        "message": f"Deployed to {ok}/{len(results)} hosts.",
    })


# ── Internal helpers for compare ──────────────────────────────────────────────

def _resolve_version_dir(identifier: str) -> Path | None:
    """Resolve a version dir identifier to a path."""
    ident = identifier.strip()

    if ident.lower() in ("latest", "current"):
        return _get_version_dir()

    if ident.startswith("/"):
        p = Path(ident)
        return p if p.exists() else None

    # Direct dir name match
    p = RESULTS_BASE / ident
    if p.exists():
        return p

    # SHA suffix match
    if RESULTS_BASE.exists():
        for entry in sorted(RESULTS_BASE.iterdir(), reverse=True):
            if entry.is_dir() and entry.name.endswith(f"-{ident}"):
                return entry

    # Substring match
    if RESULTS_BASE.exists():
        for entry in sorted(RESULTS_BASE.iterdir(), reverse=True):
            if entry.is_dir() and ident in entry.name:
                return entry

    return None


def _load_version_results(version_dir: Path) -> dict[tuple[str, str], dict]:
    """Load all results from a version dir. Returns {(tool, codebase): parsed_data}."""
    results = {}
    for f in sorted(version_dir.iterdir()):
        if not f.is_file():
            continue
        if f.suffix not in (".json", ".xml", ".txt"):
            continue
        if f.stem.endswith(".log") or f.suffix == ".log":
            continue

        run_name = f.stem
        parsed = _parse_result_file(run_name, f)

        # Extract tool and codebase from run_id: {tool}-{codebase}-{version}-{sha}
        tool_name, codebase_name = _parse_run_id(run_name)
        results[(tool_name, codebase_name)] = parsed

    return results


def _parse_run_id(run_id: str) -> tuple[str, str]:
    """Extract (tool, codebase) from a run_id string."""
    # Handle clang-tidy which has a hyphen
    if run_id.startswith("clang-tidy-"):
        rest = run_id[len("clang-tidy-"):]
        parts = rest.split("-")
        codebase = parts[0] if parts else "unknown"
        return ("clang-tidy", codebase)

    parts = run_id.split("-")
    tool = parts[0] if parts else "unknown"
    codebase = parts[1] if len(parts) > 1 else "unknown"
    return (tool, codebase)


if __name__ == "__main__":
    _install_sigchld_reaper()  # reap finished children promptly (task 218)
    _reconcile_pending_ingests()  # catch runs that finished while the server was down
    _start_watcher()  # completion → ingest, no interactive poll required
    mcp.run()
