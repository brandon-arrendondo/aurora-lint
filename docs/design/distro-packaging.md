# Distro packaging audit

Answer sheet for the questions a Debian/Fedora/Homebrew packager asks before
adopting sqc. Written so a reviewer does not have to re-derive any of it, and
so we do not silently regress a property a downstream packager depends on.

**The unit distros consume is the crates.io tarball, not the GitHub release
assets.** Fedora's `rust2rpm` and Debian's `debcargo` both generate packaging
from the published crate. Anything attached only to a GitHub release — the
`.deb`/`.rpm`/AppImage built by `.github/workflows/release.yml`, its generated
`THIRD_PARTY_LICENSES.txt` — is invisible to them. So the `include` allowlist
in `Cargo.toml` is the packaging interface, and `cargo package --list` is how
you inspect it.

---

## Offline build

**Status: clean. `build.rs` performs no network access of any kind.**

Distro builders (Debian `sbuild`, Fedora `mock`, Homebrew's sandbox) run with
the network off. A single fetch in a build script is a hard stop on all three.

What `build.rs` actually does, in `main()` order:

| Step | Effect |
|---|---|
| `winres` resource compile | `#[cfg(target_os = "windows")]` only; embeds `assets/icon.ico` (see note below) |
| `generate_rules_all_toml()` | reads `src/rules/*/**/*.toml`, validates, writes `src/rules/<ruleset>/rules-all.toml` |
| `sync_rules_templates()` | reads that file, writes `rules_templates/rules-all.toml` and `rules-benchmark.toml` |
| `generate_integration_tests()` | walks `src/rules/**/tests/*.c` and `tests/`, writes generated Rust into `$OUT_DIR` |

Its entire import surface is `anyhow`, `serde`, `std::collections`, `std::fs`,
`std::io::Write`, `std::path` and `walkdir`. There is no `std::net`, no
`std::process::Command` (the only `std::process` use is `exit` on a codegen
error), and no HTTP client anywhere in the build-dependency set. Every path it
touches is relative to the crate root or `$OUT_DIR`.

Verified by `cargo package`, whose verify step rebuilds the extracted tarball:
it completes without contacting anything beyond cargo's own dependency
resolution (which a distro replaces with system crates and `--offline`).

**Re-check when `build.rs` changes.** The grep that establishes this is:

```bash
grep -nEi 'reqwest|curl|wget|http|ureq|hyper|download|fetch|TcpStream|Command::new' build.rs
```

Empty output is the invariant.

### Note: `winres` is host-gated, and the host is never Windows

`winres` is declared under `[target.'cfg(windows)'.build-dependencies]`, which
for a build script keys on the **host**, matching build.rs's own
`#[cfg(target_os = "windows")]`. Before that gating it was a plain
build-dependency, so a crate Debian does not package was fetched and compiled
on every Linux build to do nothing.

It does nothing on the release path either: `.github/workflows/release.yml`
cross-compiles the Windows binary from `ubuntu-latest` with
`--target x86_64-pc-windows-gnu`, so the host is Linux and the icon has never
actually been embedded in a shipped `sqc.exe`. The gating did not cause that —
it makes it visible. Fixing it means a Windows runner or an
`embed-resource`-style crate that keys on the *target*.

### Caveat: the build writes into the source tree

`generate_rules_all_toml()` and `sync_rules_templates()` write three files
*outside* `$OUT_DIR`, which Cargo's build-script contract discourages:

- `src/rules/cert_c/rules-all.toml`
- `rules_templates/rules-all.toml`
- `rules_templates/rules-benchmark.toml`

This is deliberate — the generated manifests are committed, and
`rules_templates/rules-all.toml` is `include_str!`'d into the binary as the
built-in default. It is not an offline problem, and it is not a problem for
Debian or Fedora, both of which unpack into a writable build directory. Two
consequences to keep in mind anyway:

1. A build against a **read-only** source tree fails. If a packaging
   environment ever imposes one, the fix is to make the three writes
   conditional on the generated content already matching.
2. If a committed generated file ever drifts from its inputs, the write
   changes it during the verify build and `cargo package` fails with
   *"Source directory was modified by build.rs"*. That is a useful tripwire,
   not a bug — but it means **an out-of-sync manifest breaks publishing, not
   just testing**. Run `cargo package --list` before a release.

---

## Grammar dependency surface

**Status: already collapsed to C and C++. No action needed.**

`lang-parsing-substrate` ships 16 tree-sitter grammars behind features. sqc
takes `default-features = false, features = ["lang-c", "lang-cpp"]`, and sqc's
own `default = []`, so the resolved tree contains exactly two:

```
lang-parsing-substrate v0.7.0
├── globset
├── tree-sitter          v0.25.10
├── tree-sitter-c        v0.24.2
└── tree-sitter-cpp      v0.23.4
```

`Cargo.lock` agrees — it names four `tree-sitter*` crates total
(`tree-sitter`, `-c`, `-cpp`, `-language`) and none of the other grammars.
This matters because several of the substrate's grammars
(`kotlin-ng`, `ada`, `swift`, `scala`) are not packaged for Debian; sqc dodges
them entirely via the feature narrowing. A sibling tool that needs all 16 does
not, which is an argument for packaging sqc first.

Re-verify with:

```bash
cargo tree -e normal | grep -iE 'tree-sitter|lang-parsing' | sort -u
```

`tree-sitter-cpp` is present only for `cpp_header::looks_like_cpp` — deciding
whether an ambiguous `.h` is C++ — not for any C++ analysis. Dropping it would
be a behaviour change, not a packaging cleanup.

---

## Debian dependency availability

Checked against `api.ftp-master.debian.org/madison`. Two direct dependencies
are **not in Debian at all** and must be packaged before sqc can be:

| Crate | Debian `librust-*-dev` | Note |
|---|---|---|
| `lang-parsing-substrate` | **absent** | our own crate; needs packaging first |
| `rust_xlsxwriter` | **absent** | used for `--format xlsx` reports |

Several others exist but at versions outside sqc's requirement in *testing*,
which debcargo will surface as a version-relaxation decision rather than a
blocker:

| Crate | sqc wants | Debian testing | Debian stable |
|---|---|---|---|
| `tree-sitter` | `0.25` | 0.26.11 | 0.22.6 |
| `tree-sitter-c` | `0.24` | 0.24.1 | 0.21.3 |
| `tree-sitter-cpp` | `0.23` | 0.23.4 | — |
| `toml` | `0.8` | 1.1.4 | 0.8.19 |
| `sha2` | `0.10` | 0.11.0 | 0.10.8 |
| `thiserror` | `1.0` | 2.0.18 | 2.0.11 |

`thiserror` is the one worth acting on independently: Debian carries only 2.x,
and sqc is the last thing here pinning 1.0.

Everything else (`anyhow`, `chrono`, `clap`, `csv`, `git2`, `rayon`, `regex`,
`serde`, `serde_json`, `streaming-iterator`, `walkdir`, `globset`,
`tree-sitter-language`) is present at a compatible version.

Re-check with:

```bash
curl -s "https://api.ftp-master.debian.org/madison?package=librust-<crate>-dev&text=on"
```

(hyphenate underscores: `rust_xlsxwriter` → `librust-rust-xlsxwriter-dev`).

---

## What the crate tarball ships

`cargo package --list` is authoritative. Confirmed present: `src/**`,
`tests/**`, `rules_templates/**`, `build.rs`, `README.md`, `LICENSE`,
`assets/icon.ico`, `docs/sqc.1`. Confirmed absent: `data/`, `bench/`, `conf/`,
`todo-sqlite-cli.db`, `.env.example`, `tasks.py`, `playbooks/`.

**The man page ships in the crate** (`docs/sqc.1`, hand-maintained,
version-stamped by `tasks.py` on a version bump). Without it a generated
`.deb`/`.rpm` installs `/usr/bin/sqc` with no man page — a Debian Policy 12.1
bug. Keep the `docs/sqc.1` entry in `include`.

**`THIRD_PARTY_LICENSES.txt` is deliberately not in the crate.** It is
generated at release time by `cargo about` for the *statically linked binary*
artifacts, where bundling dependency licenses is required. A distro build links
against separately packaged `librust-*-dev` crates that each carry their own
copyright file, so a bundled list there would be redundant and would go stale.
`LICENSE` (Apache-2.0, sqc's own) is present and is what `debcargo`/`rust2rpm`
read.

**sqc ships no shell completions**, in the crate or in the release assets —
`clap`'s completion generator is not wired up. Nothing is being dropped by the
`include` allowlist here; the feature simply does not exist yet.
