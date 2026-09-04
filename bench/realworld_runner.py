"""Real-world benchmark runner: sqc, cppcheck, clang-tidy, Infer and Frama-C
against real open-source C codebases (libcrc, sqlite, mosquitto, curl, hostap,
lua, raylib, pureftpd, sel4), scored against the ground-truth oracle in
data/benchmarks.db.

The five tools split into two groups. sqc, cppcheck and clang-tidy read source
as written and are pointed at a curated -I list. Infer and Frama-C need a real
build, so they are driven from each checkout's compile_commands.json (task
767); Frama-C additionally needs an entry point per analysis and so runs
bounded and PARTIAL -- see the Frama-C section below and
docs/design/framac-realworld.md before quoting one of its numbers.

Synchronous and local-only, by design: this is the manual-execution path for
an individual running a benchmark against their own SQLite DB, invoked via
`python -m bench realworld-run ...` (see docs/benchmark-running.rst). It has
no async run tracking, no remote-SSH execution, and no background watcher --
run it, it blocks until done, you see the result. That's a deliberate
reduction from this module's predecessor (mcp_servers/realworld_server.py,
removed): those features existed to let an always-on MCP server juggle
multiple concurrent/detached scans and remote hosts across many client
sessions, none of which apply to one person running one benchmark in their
own terminal. The maintainer's own shared/multi-node infrastructure lives
separately in the benchmarking_db repo, not here.
"""

import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

from bench.config import BENCH_ROOT, PROJECT_DIR
from bench.db import BenchDB

RESULTS_BASE = PROJECT_DIR / "results" / "realworld"
MANIFEST = PROJECT_DIR / "rules_templates" / "rules-benchmark.toml"
SQC_BIN = PROJECT_DIR / "target" / "release" / "sqc"

VALID_TOOLS = ("sqc", "cppcheck", "clang-tidy", "infer", "frama-c")

# Tools that cannot run without a build: they consume the checkout's own
# compile_commands.json (playbooks/setup-compile-commands.yml) instead of the
# hand-curated per-codebase -I list the source-reading tools use.
COMPILE_DB_TOOLS = ("infer", "frama-c")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


# Infer captures and analyses a whole compile database in one go; the ceiling
# is a guard against a pathological project, not a coverage knob.
INFER_BUDGET_S = _env_int("SQC_BENCH_INFER_BUDGET_S", 4 * 3600)

# Frama-C bounds. These ARE coverage knobs -- see the Frama-C section below.
FRAMAC_ENTRY_TIMEOUT_S = _env_int("SQC_BENCH_FRAMAC_ENTRY_TIMEOUT_S", 60)
FRAMAC_MAX_ENTRIES_PER_TU = _env_int("SQC_BENCH_FRAMAC_MAX_ENTRIES_PER_TU", 8)
FRAMAC_BUDGET_S = _env_int("SQC_BENCH_FRAMAC_BUDGET_S", 4 * 3600)
FRAMAC_PRECISION = _env_int("SQC_BENCH_FRAMAC_PRECISION", 1)

# ── Codebase registry ─────────────────────────────────────────────────────────
CODEBASES = {
    "libcrc": {
        "path": BENCH_ROOT / "libcrc",
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
        "path": BENCH_ROOT / "sqlite",
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
        "path": BENCH_ROOT / "mosquitto",
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
        "path": BENCH_ROOT / "curl",
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
        "path": BENCH_ROOT / "hostap",
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
        "path": BENCH_ROOT / "lua",
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
        "path": BENCH_ROOT / "raylib",
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
        "path": BENCH_ROOT / "pureftpd",
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
    # MSC12-C-specific oracle task 381 originally set out to find.
    "sel4": {
        "path": BENCH_ROOT / "sel4",
        "sqc": {
            # Scope = the kernel proper (src/, 183 of 184 repo .c files).
            # libsel4/ (userspace bindings), tools/, manual/, configs/ are not
            # kernel code.
            "scan_path": "{path}/src",
            "manifest": "conf/realworld/sel4-rules.toml",
            "includes": ["-I", "{path}/include", "-I", "{path}/libsel4/include"],
            "extra_args": ["-d", "{path}/include", "-d", "{path}/libsel4/include"],
        },
        # Same src/-only scope as sqc above, for a fair cross-tool comparison.
        "cppcheck": {
            "includes": ["-I", "{path}/include", "-I", "{path}/libsel4/include"],
            "source_dirs": ["{path}/src/"],
        },
        "clang-tidy": {
            "includes": ["-I", "{path}/include", "-I", "{path}/libsel4/include"],
            "source_dirs": ["{path}/src/"],
        },
    },
}


# ── Internal helpers ──────────────────────────────────────────────────────────

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
    """Full 40-char HEAD SHA of a target codebase checkout (the thing being
    scanned). Distinct from _get_git_sha(), which is the sqc repo.

    Full, not abbreviated: sqc_bench enforces
    `CHECK (codebase_commit ~ '^[0-9a-f]{40}$')` on realworld_results, and an
    abbreviated SHA fails the whole ingest after the scan has already run --
    run 227 lost 18 minutes that way on 2026-09-02. Both sqc_bench tables are
    fully migrated to 40-char (3,287 realworld_results and 89,412 ground_truth
    rows, no short ones left).

    Local data/benchmarks.db is gitignored, so a fresh clone starts empty and
    is consistent from its first run; this checkout's own SQLite scratch still
    holds mixed-length SHAs and is deliberately not migrated -- Postgres is the
    source of truth, and local SQLite exists only for one-off clone-and-run
    nodes."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _get_tool_version(tool: str) -> str:
    if tool == "sqc":
        return _get_sqc_version()
    elif tool == "cppcheck":
        try:
            result = subprocess.run(["cppcheck", "--version"],
                                     capture_output=True, text=True, timeout=5)
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    elif tool == "clang-tidy":
        try:
            result = subprocess.run(["clang-tidy", "--version"],
                                     capture_output=True, text=True, timeout=5)
            m = re.search(r"version\s+(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    elif tool == "infer":
        try:
            result = subprocess.run(["infer", "--version"],
                                     capture_output=True, text=True, timeout=15)
            m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    elif tool == "frama-c":
        try:
            result = subprocess.run(_opam_wrap(["frama-c", "-version"]),
                                     capture_output=True, text=True, timeout=30)
            # e.g. "32.0 (Germanium)" -- keep the codename out of a run_id.
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"
    return "unknown"


def _make_version_dir_name(tool: str, version: str, sha: str,
                           variant: str | None = None) -> str:
    """sqc includes the sqc-repo git SHA; competitor tools just tool-version,
    since they're versioned independently of sqc's build."""
    base = f"sqc-{version}-{sha}" if tool == "sqc" else f"{tool}-{version}"
    return f"{base}-{variant}" if variant else base


def _make_run_id(tool: str, codebase: str, version: str, sha: str,
                 variant: str | None = None) -> str:
    base = f"{tool}-{codebase}-{version}-{sha}"
    return f"{base}-{variant}" if variant else base


def _expand(template_list: list[str], path: str) -> list[str]:
    return [s.replace("{path}", path) for s in template_list]


def _build_sqc_cmd(cfg: dict, results_dir: Path, run_id: str,
                   compile_db: str | None = None) -> list[str]:
    path = str(cfg["path"])
    scan_path = cfg["sqc"].get("scan_path")
    scan_path = _expand([scan_path], path)[0] if scan_path else path
    output_file = results_dir / f"{run_id}.json"
    extra = _expand(cfg["sqc"].get("extra_args", []), path)
    includes = _expand(cfg["sqc"].get("includes", []), path)

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
    if compile_db:
        cmd.extend(["--compile-commands", compile_db])
    cmd.extend(extra)
    cmd.extend(includes)
    return cmd


def _build_cppcheck_cmd(cfg: dict) -> list[str]:
    path = str(cfg["path"])
    cmd = [
        "cppcheck", "--enable=all", "--std=c11",
        "--xml", "--xml-version=2",
        "--suppress=missingIncludeSystem",
    ]
    cmd.extend(_expand(cfg["cppcheck"].get("includes", []), path))
    cmd.extend(_expand(cfg["cppcheck"].get("extra_args", []), path))
    cmd.extend(_expand(cfg["cppcheck"].get("source_dirs", []), path))
    return cmd


def _build_clang_tidy_cmd(cfg: dict) -> list[str]:
    """Shell command string for clang-tidy (uses a find|xargs pipeline)."""
    path = str(cfg["path"])
    source_dirs = _expand(cfg["clang-tidy"].get("source_dirs", []), path)
    includes = _expand(cfg["clang-tidy"].get("includes", []), path)
    excludes = cfg["clang-tidy"].get("exclude", [])
    prune = "".join(f" ! -path '{pat}'" for pat in excludes)

    find_parts = [f"find {sd} -name '*.c'{prune}" for sd in source_dirs]
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
    if tool == "sqc":
        return SQC_BIN.exists()
    if tool == "frama-c":
        # Single-dash -version, and only on PATH once the opam switch is in
        # the environment -- `frama-c --version` exits nonzero on a perfectly
        # good install, so the generic probe below would report it missing.
        try:
            proc = subprocess.run(_opam_wrap(["frama-c", "-version"]),
                                  capture_output=True, timeout=30)
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    try:
        subprocess.run([tool, "--version"], capture_output=True,
                       timeout=30 if tool == "infer" else 5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── Result parsers ────────────────────────────────────────────────────────────

def _parse_sqc_json(filepath: Path) -> dict:
    try:
        violations = json.loads(filepath.read_text())
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}
    per_rule: dict[str, int] = {}
    for v in violations:
        rule = v.get("rule_id", "unknown")
        per_rule[rule] = per_rule.get(rule, 0) + 1
    return {"total": len(violations),
            "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1]))}


def _parse_cppcheck_xml(filepath: Path) -> dict:
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}
    per_rule: dict[str, int] = {}
    total = 0
    for error in root.iter("error"):
        if error.get("severity", "") == "information":
            continue
        error_id = error.get("id", "unknown")
        per_rule[error_id] = per_rule.get(error_id, 0) + 1
        total += 1
    return {"total": total,
            "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1]))}


def _parse_clang_tidy_txt(filepath: Path) -> dict:
    try:
        content = filepath.read_text()
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}
    per_rule: dict[str, int] = {}
    total = 0
    pattern = re.compile(r": warning: .+\[([^\]]+)\]$")
    for line in content.splitlines():
        m = pattern.search(line)
        if m:
            per_rule[m.group(1)] = per_rule.get(m.group(1), 0) + 1
            total += 1
    return {"total": total,
            "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1]))}


def _parse_result_file(filepath: Path, tool: str, cfg: dict | None = None) -> dict:
    """Dispatch on the TOOL, not the file extension: sqc and Infer both emit
    JSON, in unrelated shapes."""
    if tool == "sqc":
        return _parse_sqc_json(filepath)
    elif tool == "cppcheck":
        return _parse_cppcheck_xml(filepath)
    elif tool == "clang-tidy":
        return _parse_clang_tidy_txt(filepath)
    elif tool == "infer":
        return _parse_infer_json(filepath, cfg)
    elif tool == "frama-c":
        return _parse_framac_json(filepath, cfg)
    return {"error": f"Unknown tool: {tool}", "total": 0, "per_rule": {}}


# ── LOC/file counting (shared denominator across tools) ──────────────────────

def _sqc_glob_to_regex(pattern: str) -> "re.Pattern":
    """Python port of sqc's suppression::glob_to_regex(pattern, is_path=True),
    kept in lockstep so the post-exclude fileset counted here matches what
    sqc actually scans."""
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
    args = cfg.get("sqc", {}).get("extra_args", [])
    return [_sqc_glob_to_regex(args[i + 1]) for i in range(len(args) - 1)
            if args[i] == "--exclude"]


def _count_c_source(cfg: dict) -> tuple[int, int]:
    """(c_files, loc) for a codebase's own C source, using the curated
    cppcheck source_dirs (excludes vendored deps/test scaffolding) so the LOC
    denominator is identical across tools, with sqc's --exclude globs applied
    so the count matches the post-exclude set sqc actually scanned."""
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
                if any(p.search(fp.replace("\\", "/")) for p in excludes):
                    continue
                if f.endswith(".c"):
                    c_files += 1
                try:
                    with open(fp, "rb") as fh:
                        loc += sum(1 for _ in fh)
                except OSError:
                    pass
    return c_files, loc


def _count_sqc_scanned(cfg: dict) -> tuple[int, int]:
    """(c_files, loc) for the fileset sqc itself walked: the same scan_path
    `_build_sqc_cmd` passes, minus the same --exclude globs.

    Distinct from `_count_c_source`, which counts the curated cppcheck
    source_dirs so the LOC denominator is comparable across the three tools.
    The two diverge wherever sqc scans outside those dirs -- sqlite (cppcheck
    reads src/ only, sqc also reads ext/**) and curl are the wide cases. This
    is the figure that pairs with duration_s, since it is the corpus the clock
    was actually running over.

    Note this is NOT the oracle scope predicate (`bench.corpus.in_scope`):
    that filters *findings* at scoring time (task 636) and is never applied to
    the scan, so it cannot describe what a scan cost.
    """
    path = str(cfg["path"])
    scan_path = cfg["sqc"].get("scan_path")
    scan_path = _expand([scan_path], path)[0] if scan_path else path
    excludes = _sqc_exclude_patterns(cfg)
    c_files = 0
    loc = 0
    for root, _dirs, files in os.walk(scan_path):
        for f in files:
            if not f.endswith((".c", ".h")):
                continue
            fp = os.path.join(root, f)
            if any(p.search(fp.replace("\\", "/")) for p in excludes):
                continue
            if f.endswith(".c"):
                c_files += 1
            try:
                with open(fp, "rb") as fh:
                    loc += sum(1 for _ in fh)
            except OSError:
                pass
    return c_files, loc


# ── Build-based tools: Infer and Frama-C ─────────────────────────────────────
#
# Both consume a compile_commands.json rather than a curated -I list, because
# both need a real preprocess: that is the axis sqc deliberately does not
# require, and pretending otherwise would compare them at a handicap. The
# compile databases are provisioned for all nine checkouts by
# playbooks/setup-compile-commands.yml (task 767 -- sel4, hostap and pureftpd
# included; the belief that three corpora were unbuildable predates that
# playbook's sel4 Ninja fix).
#
# Scope. The compile DB lists every translation unit the project's own build
# compiles, which is wider than the curated cross-tool comparison scope
# (vendored deps, test harnesses, tooling). We filter it down to exactly the
# fileset `_count_c_source` counts -- cppcheck's source_dirs minus sqc's
# --exclude globs -- so all five tools are measured over one denominator. The
# filtered database is written next to the run's other artifacts, so what was
# analysed is recoverable from the results directory alone.


def _load_compile_db(cfg: dict) -> list[dict]:
    """Raw compile_commands.json entries for a codebase, or []."""
    from bench.config import compile_db_for
    found = compile_db_for(cfg["path"])
    if found is None:
        return []
    try:
        return json.loads(found.read_text())
    except Exception:
        return []


def _in_comparison_scope(cfg: dict):
    """Predicate over absolute source paths matching `_count_c_source`'s
    fileset: under a curated cppcheck source_dir, and not hit by one of sqc's
    --exclude globs."""
    path = str(cfg["path"])
    dirs = [os.path.realpath(d)
            for d in (_expand(cfg.get("cppcheck", {}).get("source_dirs", []), path) or [path])]
    excludes = _sqc_exclude_patterns(cfg)

    def ok(src: str) -> bool:
        real = os.path.realpath(src)
        if not any(real == d or real.startswith(d.rstrip("/") + "/") for d in dirs):
            return False
        return not any(p.search(real.replace("\\", "/")) for p in excludes)

    return ok


def _filtered_compile_db(cfg: dict, dest: Path) -> tuple[Path | None, int, int]:
    """Write the in-scope subset of a codebase's compile DB to `dest`.

    Returns (path or None, kept, total). One entry per source file: a build
    that compiles the same TU twice (curl builds lib/ for both the shared and
    static library) would otherwise make Infer capture it twice and Frama-C
    analyse it twice, inflating both the clock and the finding count."""
    entries = _load_compile_db(cfg)
    if not entries:
        return None, 0, 0
    in_scope = _in_comparison_scope(cfg)
    kept: list[dict] = []
    seen: set[str] = set()
    for e in entries:
        src = e.get("file", "")
        if not src.endswith(".c"):
            continue
        if not os.path.isabs(src):
            src = os.path.join(e.get("directory", ""), src)
        real = os.path.realpath(src)
        if real in seen or not in_scope(real):
            continue
        seen.add(real)
        kept.append(e)
    dest.write_text(json.dumps(kept, indent=1))
    return dest, len(kept), len(entries)


def _opam_wrap(argv: list[str]) -> list[str]:
    """Run `argv` with the user's opam switch on PATH.

    Frama-C is installed by playbooks/install-static-analyzers.yml into
    ~/.opam, which only lands on PATH via `eval $(opam env)` in a login shell
    -- and the benchmark runner is not one. `opam env` failing is not fatal:
    a Frama-C installed some other way is already on PATH, so the eval is
    tolerated rather than required."""
    return ["bash", "-c", 'eval "$(opam env 2>/dev/null)" 2>/dev/null; exec "$@"',
            "_", *argv]


# ── Infer ─────────────────────────────────────────────────────────────────────

_INFER_TRANSLATING_RE = re.compile(r"Starting translating (\d+) files")
_INFER_ANALYZING_RE = re.compile(r"Found (\d+) source files? to analyze")
# Infer's own "Found N source files to analyze" counts every TU it was HANDED,
# including ones whose capture died -- libcrc reports 9/9 while 2 of the 9
# never preprocessed. The clang diagnostic is the only honest signal of which
# translation units actually made it into the AST database.
_INFER_CAPTURE_FAIL_RE = re.compile(r"^(\S+):\d+:\d+: fatal error:", re.MULTILINE)


def _run_infer(cfg: dict, version_dir: Path, run_id: str,
               log_fh) -> tuple[Path, int]:
    """Capture the in-scope compile DB, then analyse it in one pass.

    Two phases rather than `infer run` so a capture failure is distinguishable
    from an analysis failure in the log -- Infer exits 0 from `run` even when
    capture silently produced nothing.

    Capture runs with --keep-going because a partial capture is the NORMAL
    outcome on this corpus, not an error. `setup-compile-commands.yml` restores
    each checkout to pristine after building it, which deletes the build's
    generated headers while leaving the compile database that references them
    -- libcrc's `tab/gentab32.inc` is the worked example, and 2 of its 9
    in-scope TUs cannot be preprocessed as a result. Without --keep-going Infer
    aborts the whole capture on the first such file and the run reports zero
    findings for a codebase it could have analysed 78% of. What matters is that
    the shortfall is RECORDED rather than silently absorbed, so `coverage`
    below carries captured-vs-in-scope and any Infer row derived from a partial
    capture is a floor, exactly as a Frama-C row is."""
    db_path = version_dir / f"{run_id}.compile_commands.json"
    filtered, kept, total = _filtered_compile_db(cfg, db_path)
    result_file = version_dir / f"{run_id}.infer.json"
    if filtered is None or kept == 0:
        result_file.write_text(json.dumps(
            {"tool": "infer", "findings": [],
             "coverage": {"tus_in_scope": 0, "tus_captured": 0, "partial": True}}))
        log_fh.write(f"no in-scope compile_commands.json entries "
                     f"({kept} kept of {total}); nothing to capture\n")
        return result_file, 1

    out_dir = version_dir / f"{run_id}.infer-out"
    jobs = str(min(os.cpu_count() or 4, 16))
    log_fh.write(f"infer: {kept} of {total} compile DB entries in scope\n")
    log_fh.flush()

    rc = 0
    start = time.monotonic()
    output = {}
    for name, phase in (
        ("capture", ["infer", "capture", "--results-dir", str(out_dir),
                     "--keep-going", "--compilation-database", str(filtered)]),
        ("analyze", ["infer", "analyze", "--results-dir", str(out_dir),
                     "--no-progress-bar", "--jobs", jobs]),
    ):
        log_fh.write(f"$ {' '.join(phase)}\n")
        log_fh.flush()
        try:
            proc = subprocess.run(phase, capture_output=True, text=True,
                                  timeout=INFER_BUDGET_S)
        except subprocess.TimeoutExpired:
            log_fh.write(f"TIMEOUT after {INFER_BUDGET_S}s\n")
            rc = rc or 124
            break
        output[name] = (proc.stdout or "") + (proc.stderr or "")
        log_fh.write(output[name])
        log_fh.flush()
        if proc.returncode != 0:
            log_fh.write(f"[{name}] exited {proc.returncode}\n")
            # A nonzero capture is survivable (see docstring); a nonzero
            # analyze is not, since it means no report was produced.
            if name != "capture":
                rc = rc or proc.returncode

    def _first_int(pattern, text, default=0):
        m = pattern.search(text or "")
        return int(m.group(1)) if m else default

    attempted = _first_int(_INFER_TRANSLATING_RE, output.get("capture", ""), kept)
    failed = sorted(set(_INFER_CAPTURE_FAIL_RE.findall(output.get("capture", ""))))
    captured = max(attempted - len(failed), 0)
    coverage = {
        "tus_in_scope": kept,
        "tus_attempted": attempted,
        "tus_captured": captured,
        "tus_pct": round(100.0 * captured / kept, 1) if kept else 0.0,
        "capture_failures": failed,
        "analyzed_reported": _first_int(_INFER_ANALYZING_RE, output.get("analyze", "")),
        "duration_s": round(time.monotonic() - start, 1),
        "partial": captured < kept,
    }
    if failed:
        log_fh.write("capture failed for: " + ", ".join(failed) + "\n")

    report = out_dir / "report.json"
    if report.exists():
        payload = {"tool": "infer", "coverage": coverage,
                   "findings": json.loads(report.read_text())}
    else:
        log_fh.write("infer produced no report.json\n")
        payload = {"tool": "infer", "coverage": coverage, "findings": []}
        rc = rc or 1
    result_file.write_text(json.dumps(payload, indent=1))
    log_fh.write(f"infer: captured {captured}/{kept} in-scope TUs "
                 f"({coverage['tus_pct']}%)\n")
    return result_file, rc


def _parse_infer_json(filepath: Path, cfg: dict | None = None) -> dict:
    """Infer's report.json: a flat list of bugs keyed on `bug_type`.

    Findings outside the checkout are dropped -- a captured TU pulls in system
    headers, and a bug attributed to /usr/include is not a finding about this
    codebase. cppcheck and clang-tidy need no equivalent filter because they
    are pointed at source_dirs directly."""
    try:
        payload = json.loads(filepath.read_text())
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}
    root = os.path.realpath(str(cfg["path"])) + "/" if cfg else None
    per_rule: dict[str, int] = {}
    total = 0
    for bug in payload.get("findings", []):
        f = bug.get("file", "")
        if root:
            if not os.path.isabs(f):
                f = os.path.join(str(cfg["path"]), f)
            if not os.path.realpath(f).startswith(root):
                continue
        bug_type = bug.get("bug_type", "unknown")
        per_rule[bug_type] = per_rule.get(bug_type, 0) + 1
        total += 1
    return {"total": total,
            "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1])),
            "coverage": payload.get("coverage", {})}


# ── Frama-C ───────────────────────────────────────────────────────────────────
#
# EVA analyses ONE entry point at a time, and a real codebase has no single
# one: curl's library has no main, and starting from the curl binary's main
# does not terminate. So the real-world mode is per-translation-unit --
# `-lib-entry -main=<f>` over the functions each TU defines, with unknown
# globals -- under three explicit bounds, because the unbounded version is
# not a job that finishes:
#
#   FRAMAC_ENTRY_TIMEOUT_S   per EVA invocation
#   FRAMAC_MAX_ENTRIES_PER_TU  how deep into one file to go
#   FRAMAC_BUDGET_S          total wall clock for the project
#
# Entry points are visited ROUND-ROBIN across translation units, not file by
# file: a budget spent depth-first would cover the alphabetically-first
# handful of files completely and never open the rest, which is a biased
# sample of the codebase rather than a shallow one. One pass gives every TU
# its first entry point before any TU gets a second.
#
# The consequence, stated rather than discovered later: a Frama-C real-world
# row is a PARTIAL scan, and `coverage` in the result file records how partial
# (entries reached, timeouts, whether the budget ran out). Any precision or
# finding-count comparison drawn against it must carry that caveat -- see
# docs/design/framac-realworld.md.

_C_KEYWORD_CALLS = frozenset((
    "if", "while", "for", "switch", "return", "sizeof", "do", "else",
    "case", "goto", "typedef", "defined", "_Static_assert", "static_assert",
))

_C_FUNC_CANDIDATE_RE = re.compile(
    r"^(?P<static>static\s+)?"
    r"(?:(?:inline|__inline|__inline__|extern|const|volatile|unsigned|signed|"
    r"struct|union|enum|register|_Noreturn|__attribute__\s*\(\([^)]*\)\))\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*"
    r"(?:\*\s*)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def _c_function_definitions(filepath: Path) -> list[str]:
    """Names of functions DEFINED at top level in a .c file, non-static first.

    A deliberately cheap textual pass rather than a parse: it only has to
    propose entry points, and Frama-C rejects a name it does not know (logged
    and skipped), so a false positive here costs one fast invocation. Ordering
    puts externally-linked functions first because those are the library's own
    API -- the code a caller can actually reach, and so the code worth
    spending a bounded budget on."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    external: list[str] = []
    internal: list[str] = []
    for m in _C_FUNC_CANDIDATE_RE.finditer(text):
        name = m.group("name")
        if name in _C_KEYWORD_CALLS:
            continue
        # Confirm it is a definition, not a declaration or a call: balance the
        # parameter list, then require '{' as the next non-space character.
        i = m.end() - 1
        depth = 0
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        j = i + 1
        while j < len(text) and text[j].isspace():
            j += 1
        if j >= len(text) or text[j] != "{":
            continue
        (internal if m.group("static") else external).append(name)
    seen: set[str] = set()
    ordered = []
    for name in external + internal:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


# `[eva:alarm] file:line: Warning: <kind>. assert <predicate>;` -- and EVA
# wraps, so <kind> lands on the following line whenever the header is long.
# The kind is what makes a per-"rule" breakdown expressible at all (EVA has no
# rule ids), so it is captured rather than bucketing everything as one alarm.
_FRAMAC_ALARM_RE = re.compile(
    r"\[eva:alarm\]\s+(?P<file>[^\s:]+):(?P<line>\d+):\s*Warning:\s*\n?\s*"
    r"(?P<kind>[^.\n]*)")
_FRAMAC_UNKNOWN_MAIN_RE = re.compile(r"cannot find entry point|Unable to find function")

_FRAMAC_PRECOND_RE = re.compile(r"function ([A-Za-z_]\w*): precondition")


def _framac_alarm_kind(raw: str) -> str:
    """Normalise EVA's alarm text into something usable as a rule id.

    Most alarms are already a short noun phrase ("out of bounds read", "signed
    overflow"). Precondition alarms instead carry the whole ACSL predicate
    (`function snprintf_va_1: precondition \\valid(s + (0 .. 255))`), which
    would make every call site its own "rule" and shred the breakdown -- those
    collapse to the callee."""
    kind = " ".join(raw.split())
    m = _FRAMAC_PRECOND_RE.search(kind)
    if m:
        return f"precondition of {m.group(1)}"
    return kind[:80] or "eva_alarm"


_framac_cdb_flag: str | None = None


def _framac_compile_db_flag() -> str:
    """The option name for "read cpp flags from compile_commands.json", which
    Frama-C renamed: `-json-compilation-database` through 32.0 (the version the
    published competitor Juliet runs used), `-compilation-db` from 33.0. Asking
    the binary is the only way to be right on both, and getting it wrong is
    silent-ish -- every EVA invocation aborts with "option is unknown", which
    the runner would otherwise tally as 22 analysis failures rather than one
    configuration error."""
    global _framac_cdb_flag
    if _framac_cdb_flag is None:
        try:
            out = subprocess.run(_opam_wrap(["frama-c", "-kernel-h"]),
                                 capture_output=True, text=True, timeout=60).stdout
        except Exception:
            out = ""
        _framac_cdb_flag = ("-compilation-db" if "-compilation-db" in out
                            else "-json-compilation-database")
    return _framac_cdb_flag


def _run_framac(cfg: dict, version_dir: Path, run_id: str,
                log_fh) -> tuple[Path, int]:
    db_path = version_dir / f"{run_id}.compile_commands.json"
    filtered, kept, total = _filtered_compile_db(cfg, db_path)
    result_file = version_dir / f"{run_id}.framac.json"

    tus: list[Path] = []
    if filtered is not None:
        for e in json.loads(filtered.read_text()):
            src = e.get("file", "")
            if not os.path.isabs(src):
                src = os.path.join(e.get("directory", ""), src)
            tus.append(Path(src))
    tus.sort()

    entries = {tu: _c_function_definitions(tu)[:FRAMAC_MAX_ENTRIES_PER_TU]
               for tu in tus}
    entries_total = sum(len(v) for v in entries.values())
    log_fh.write(f"frama-c: {kept} of {total} compile DB entries in scope; "
                 f"{entries_total} candidate entry points across {len(tus)} TUs; "
                 f"budget {FRAMAC_BUDGET_S}s\n")
    log_fh.flush()

    findings: list[dict] = []
    analysed = timeouts = failures = 0
    budget_exhausted = False
    start = time.monotonic()

    # Round-robin: pass 0 gives every TU its first entry point, pass 1 its
    # second, and so on -- so exhausting the budget yields a shallow scan of
    # the whole corpus rather than a deep scan of its first few files.
    for depth in range(FRAMAC_MAX_ENTRIES_PER_TU):
        if budget_exhausted:
            break
        for tu in tus:
            if depth >= len(entries[tu]):
                continue
            if time.monotonic() - start >= FRAMAC_BUDGET_S:
                budget_exhausted = True
                break
            entry = entries[tu][depth]
            cmd = _opam_wrap([
                "frama-c", "-eva",
                "-eva-precision", str(FRAMAC_PRECISION),
                "-machdep", "gcc_x86_64",
                "-lib-entry", f"-main={entry}",
                _framac_compile_db_flag(), str(filtered),
                str(tu),
            ])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=FRAMAC_ENTRY_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                timeouts += 1
                log_fh.write(f"TIMEOUT {FRAMAC_ENTRY_TIMEOUT_S}s {tu.name}:{entry}\n")
                continue
            except Exception as e:
                failures += 1
                log_fh.write(f"ERROR {tu.name}:{entry}: {e}\n")
                continue
            output = (proc.stdout or "") + (proc.stderr or "")
            if _FRAMAC_UNKNOWN_MAIN_RE.search(output):
                # The textual entry-point scan proposed a name EVA does not
                # know. Expected, cheap, and neither coverage nor a failure.
                continue
            if proc.returncode != 0:
                # Usually an unpreprocessable TU (a generated header the
                # playbook's restore-to-pristine step removed). Not coverage.
                failures += 1
                log_fh.write(f"FAILED rc={proc.returncode} {tu.name}:{entry}\n")
                continue
            analysed += 1
            for m in _FRAMAC_ALARM_RE.finditer(output):
                kind = _framac_alarm_kind(m.group("kind"))
                findings.append({"file": m.group("file"), "line": int(m.group("line")),
                                 "alarm_type": kind,
                                 "entry": entry, "tu": str(tu)})

    duration = round(time.monotonic() - start, 1)
    result_file.write_text(json.dumps({
        "tool": "frama-c",
        "findings": findings,
        "coverage": {
            "tus_total": len(tus),
            "entries_total": entries_total,
            "entries_analyzed": analysed,
            "entries_pct": round(100.0 * analysed / entries_total, 1) if entries_total else 0.0,
            "timeouts": timeouts,
            "failures": failures,
            "budget_s": FRAMAC_BUDGET_S,
            "budget_exhausted": budget_exhausted,
            "duration_s": duration,
            "partial": budget_exhausted or analysed < entries_total,
        },
    }, indent=1))
    log_fh.write(f"frama-c: analysed {analysed}/{entries_total} entry points "
                 f"({timeouts} timeouts, {failures} failures) in {duration}s"
                 f"{'; BUDGET EXHAUSTED' if budget_exhausted else ''}\n")
    return result_file, (0 if analysed else 1)


def _parse_framac_json(filepath: Path, cfg: dict | None = None) -> dict:
    """Count DISTINCT (file, line, alarm_type) alarms.

    EVA re-reports the same alarm from every entry point that reaches it, so a
    raw count would scale with FRAMAC_MAX_ENTRIES_PER_TU rather than with the
    codebase -- two runs at different caps would not be comparable, nor would
    a Frama-C row be comparable to another tool's."""
    try:
        payload = json.loads(filepath.read_text())
    except Exception as e:
        return {"error": str(e), "total": 0, "per_rule": {}}
    root = os.path.realpath(str(cfg["path"])) + "/" if cfg else None
    per_rule: dict[str, int] = {}
    seen: set[tuple] = set()
    for a in payload.get("findings", []):
        f = a.get("file", "")
        if root:
            if not os.path.isabs(f):
                f = os.path.join(str(cfg["path"]), f)
            if not os.path.realpath(f).startswith(root):
                continue
        key = (os.path.realpath(f), a.get("line"), a.get("alarm_type"))
        if key in seen:
            continue
        seen.add(key)
        kind = a.get("alarm_type", "unknown")
        per_rule[kind] = per_rule.get(kind, 0) + 1
    return {"total": len(seen),
            "per_rule": dict(sorted(per_rule.items(), key=lambda x: -x[1])),
            "coverage": payload.get("coverage", {})}


# ── Running one combo ─────────────────────────────────────────────────────────

def run_one(tool: str, codebase: str, compile_commands: bool = False) -> dict:
    """Run one tool against one codebase, synchronously, blocking until done.
    Writes result files under RESULTS_BASE. Returns a summary dict."""
    tool = tool.strip().lower()
    codebase = codebase.strip().lower()
    if tool not in VALID_TOOLS:
        raise ValueError(f"Unknown tool '{tool}'. Must be one of: {', '.join(VALID_TOOLS)}")
    if codebase not in CODEBASES:
        raise ValueError(f"Unknown codebase '{codebase}'. Must be one of: {', '.join(sorted(CODEBASES))}")

    cfg = CODEBASES[codebase]
    if not cfg["path"].exists():
        raise FileNotFoundError(
            f"Codebase path does not exist: {cfg['path']}\n"
            "Clone it first -- see docs/benchmark-setup.rst.")
    if not _check_tool_available(tool):
        raise FileNotFoundError(
            f"Tool '{tool}' not found on PATH."
            + ("\nInstall it with: ansible-playbook playbooks/install-static-analyzers.yml"
               " -i 'localhost,' -c local --ask-become-pass"
               if tool in COMPILE_DB_TOOLS else ""))
    if tool in COMPILE_DB_TOOLS:
        # Not a fallback situation: without the build's own flags these tools
        # produce a parse-error log, not a weaker scan.
        from bench.config import compile_db_for
        if compile_db_for(cfg["path"]) is None:
            raise FileNotFoundError(
                f"'{tool}' needs {cfg['path']}/compile_commands.json and there is none.\n"
                "Generate it with: ansible-playbook playbooks/setup-compile-commands.yml "
                "-i 'localhost,' -c local --ask-become-pass")

    compile_db = None
    variant = None
    if compile_commands:
        if tool != "sqc":
            raise ValueError(
                f"--compile-commands is an sqc OPT-IN, not a global flag; '{tool}' "
                "always uses the compile database and cannot be run without one.")
        from bench.config import compile_db_for
        variant = "cdb"
        found = compile_db_for(cfg["path"])
        if found is None:
            raise FileNotFoundError(
                f"compile_commands requested but no compile_commands.json in {cfg['path']}.\n"
                "Generate it with: ansible-playbook playbooks/setup-compile-commands.yml "
                "-i 'localhost,' -c local --ask-become-pass")
        compile_db = str(found)

    version = _get_tool_version(tool)
    sha = _get_git_sha()
    dir_name = _make_version_dir_name(tool, version, sha, variant)
    version_dir = RESULTS_BASE / dir_name
    version_dir.mkdir(parents=True, exist_ok=True)
    run_id = _make_run_id(tool, codebase, version, sha, variant)

    for ext in (".json", ".xml", ".txt", ".log", ".meta.json",
                ".infer.json", ".framac.json", ".compile_commands.json"):
        (version_dir / f"{run_id}{ext}").unlink(missing_ok=True)
    shutil.rmtree(version_dir / f"{run_id}.infer-out", ignore_errors=True)

    codebase_sha = _get_codebase_sha(cfg["path"])
    if codebase_sha:
        (version_dir / f"{run_id}.meta.json").write_text(
            json.dumps({"codebase_commit": codebase_sha}))

    log_path = version_dir / f"{run_id}.log"
    start = time.time()
    print(f"  [{tool}] {codebase} ...", end=" ", flush=True)

    with log_path.open("w") as log_fh:
        if tool == "sqc":
            cmd = _build_sqc_cmd(cfg, version_dir, run_id, compile_db)
            result_file = version_dir / f"{run_id}.json"
            proc = subprocess.run(cmd, stdout=log_fh, stderr=subprocess.STDOUT)
        elif tool == "cppcheck":
            cmd = _build_cppcheck_cmd(cfg)
            result_file = version_dir / f"{run_id}.xml"
            with result_file.open("w") as result_fh:
                proc = subprocess.run(cmd, stdout=log_fh, stderr=result_fh)
        elif tool == "clang-tidy":
            cmd = _build_clang_tidy_cmd(cfg)
            result_file = version_dir / f"{run_id}.txt"
            with result_file.open("w") as result_fh:
                proc = subprocess.run(cmd, stdout=result_fh, stderr=log_fh)
        else:  # infer, frama-c -- both drive themselves off the compile DB
            runner = _run_infer if tool == "infer" else _run_framac
            result_file, rc = runner(cfg, version_dir, run_id, log_fh)
            proc = SimpleNamespace(returncode=rc)

    duration = round(time.time() - start, 1)

    # Task 715: persist the per-project scan facts into the sidecar. These are
    # only true at scan time, and the queue worker cannot recover them -- it
    # shells out to `python -m bench realworld-run` once for every project, so
    # it sees one wall time and no per-project split. The sidecar is the only
    # transport that survives that subprocess boundary.
    #
    # `c_files`/`loc` deliberately stay on the _count_c_source basis, which is
    # what every existing realworld_results row already means; changing the
    # basis under a column of that name would put two definitions in one
    # column. The as-scanned figures ride alongside under their own names.
    scanned_c_files, scanned_loc = _count_sqc_scanned(cfg)
    cmp_c_files, cmp_loc = _count_c_source(cfg)
    meta = {
        "codebase_commit": codebase_sha,
        "duration_s": float(duration),
        "c_files": cmp_c_files,
        "loc": cmp_loc,
        "metrics_basis": "cppcheck_source_dirs+sqc_excludes",
        "scanned_c_files": scanned_c_files,
        "scanned_loc": scanned_loc,
        "scanned_basis": "sqc_scan_path+sqc_excludes",
    }
    (version_dir / f"{run_id}.meta.json").write_text(json.dumps(meta))

    parsed = _parse_result_file(result_file, tool, cfg) if result_file.exists() \
        else {"total": 0, "error": "no output file"}
    coverage = parsed.get("coverage") or None
    if coverage and coverage.get("partial"):
        meta["coverage"] = coverage
        (version_dir / f"{run_id}.meta.json").write_text(json.dumps(meta))
    ok = proc.returncode == 0 and "error" not in parsed
    note = ""
    if coverage and coverage.get("partial"):
        # Printed on the run line, not buried in the log: a partial scan's
        # finding count is a floor, and the number is about to be quoted.
        pct = coverage.get("entries_pct", coverage.get("tus_pct"))
        note = f", PARTIAL {pct}%" if pct is not None else ", PARTIAL"
    print(f"{'ok' if ok else 'FAILED'} ({duration}s, {parsed.get('total', 0)} findings{note})"
          + (f" -- {parsed['error']}" if parsed.get("error") else ""))

    return {
        "tool": tool, "codebase": codebase, "run_id": run_id,
        "version_dir": version_dir, "version": version, "sha": sha,
        "codebase_commit": codebase_sha, "duration_s": duration,
        "returncode": proc.returncode, "total": parsed.get("total", 0),
        "result_file": result_file, "ok": ok, "coverage": coverage,
    }


# ── Orchestration + SQLite ingest ─────────────────────────────────────────────

def run_and_ingest(tools: list[str], codebases: list[str],
                   compile_commands: bool = False) -> dict:
    """Run every tool x codebase combo sequentially, then ingest sqc results
    (+ attach cppcheck/clang-tidy comparison rows) into SQLite and score
    against the ground-truth oracle. Returns a summary dict."""
    results: list[dict] = []
    for tool in tools:
        for codebase in codebases:
            try:
                results.append(run_one(tool, codebase, compile_commands))
            except Exception as e:
                print(f"  [{tool}] {codebase} FAILED to start: {e}")
                results.append({"tool": tool, "codebase": codebase, "ok": False,
                                 "error": str(e), "duration_s": None, "total": 0})

    db = BenchDB()
    machine = {"hostname": os.uname().nodename}
    summary = {"results": results, "run_id": None, "score": None}

    sqc_results = [r for r in results if r["tool"] == "sqc" and r.get("ok")]
    if sqc_results:
        sqc_dir = sqc_results[0]["version_dir"]  # shared across codebases for one invocation
        durations = {r["codebase"]: r["duration_s"] for r in sqc_results}
        metrics = {r["codebase"]: dict(zip(("c_files", "loc"), _count_c_source(CODEBASES[r["codebase"]])))
                   for r in sqc_results}
        run_id = db.ingest_realworld_run(sqc_dir.name, str(sqc_dir), machine=machine,
                                         durations=durations, metrics=metrics)
        summary["run_id"] = run_id

        for r in results:
            if r["tool"] == "sqc" or not r.get("ok"):
                continue
            cfg = CODEBASES[r["codebase"]]
            c_files, loc = _count_c_source(cfg)
            commit = r.get("codebase_commit")
            db.insert_realworld_result(run_id, r["codebase"], r["tool"],
                                       c_files, loc, r["total"], r["duration_s"], commit,
                                       coverage=r.get("coverage"))

        score = db.score_realworld_run(run_id)
        if not score.get("error"):
            (sqc_dir / f"{sqc_dir.name}.score.json").write_text(
                json.dumps(score, indent=2, default=str))
            ov = score["overall"]
            labeled = ov["labeled_total"]
            if labeled:
                rec = ov.get("recall_pct")
                rec_s = f", recall {rec}% ({ov['tp_detected']}/{ov['tp_labels']})" if rec is not None else ""
                print(f"\nMeasured precision {ov['precision_pct']}% "
                      f"(TP {ov['labeled_tp']}/{labeled} labeled of {ov['run_findings']} findings){rec_s}")
            else:
                print("\nNo oracle labels cover this run's commit(s) yet -- nothing scored.")
        summary["score"] = score

    return summary
