"""Real-world benchmark runner: sqc, cppcheck, and clang-tidy against real
open-source C codebases (libcrc, sqlite, mosquitto, curl, hostap, lua,
raylib, pureftpd, sel4), scored against the ground-truth oracle in
data/benchmarks.db.

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
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from bench.config import BENCH_ROOT, PROJECT_DIR
from bench.db import BenchDB

RESULTS_BASE = PROJECT_DIR / "results" / "realworld"
MANIFEST = PROJECT_DIR / "rules_templates" / "rules-benchmark.toml"
SQC_BIN = PROJECT_DIR / "target" / "release" / "sqc"

VALID_TOOLS = ("sqc", "cppcheck", "clang-tidy")

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
    """Short HEAD SHA of a target codebase checkout (the thing being scanned).
    Distinct from _get_git_sha(), which is the sqc repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
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
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=5)
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


def _parse_result_file(filepath: Path) -> dict:
    if filepath.suffix == ".json":
        return _parse_sqc_json(filepath)
    elif filepath.suffix == ".xml":
        return _parse_cppcheck_xml(filepath)
    elif filepath.suffix == ".txt":
        return _parse_clang_tidy_txt(filepath)
    return {"error": f"Unknown file type: {filepath.suffix}", "total": 0, "per_rule": {}}


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
        raise FileNotFoundError(f"Tool '{tool}' not found on PATH.")

    compile_db = None
    variant = None
    if compile_commands:
        if tool != "sqc":
            raise ValueError(f"--compile-commands applies to sqc only, not '{tool}'.")
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

    for ext in (".json", ".xml", ".txt", ".log", ".meta.json"):
        (version_dir / f"{run_id}{ext}").unlink(missing_ok=True)

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
        else:  # clang-tidy
            cmd = _build_clang_tidy_cmd(cfg)
            result_file = version_dir / f"{run_id}.txt"
            with result_file.open("w") as result_fh:
                proc = subprocess.run(cmd, stdout=result_fh, stderr=log_fh)

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

    parsed = _parse_result_file(result_file) if result_file.exists() else {"total": 0, "error": "no output file"}
    ok = proc.returncode == 0 and "error" not in parsed
    print(f"{'ok' if ok else 'FAILED'} ({duration}s, {parsed.get('total', 0)} findings)"
          + (f" -- {parsed['error']}" if parsed.get("error") else ""))

    return {
        "tool": tool, "codebase": codebase, "run_id": run_id,
        "version_dir": version_dir, "version": version, "sha": sha,
        "codebase_commit": codebase_sha, "duration_s": duration,
        "returncode": proc.returncode, "total": parsed.get("total", 0),
        "result_file": result_file, "ok": ok,
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
            commit = r.get("codebase_commit") or db.live_codebase_commit(r["codebase"])
            db.insert_realworld_result(run_id, r["codebase"], r["tool"],
                                       c_files, loc, r["total"], r["duration_s"], commit)

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
