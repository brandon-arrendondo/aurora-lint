# Ventoy2Disk onboarding — sqc 0.4.336 at the onboarding commit, codebase commit 7cbdc5cf

Ventoy (registry key `ventoy`, checked out at `~/toolchain/ventoy`) is the
suite's **first genuine Win32-API oracle**. Every `WIN*-C` rule (WIN00-05,
WIN30) had no true-positive-capable target across the ten POSIX codebases:
libcrc disables the family categorically, and the others keep it enabled on
code that never calls a Win32 API (curl's own Windows backend files sit
outside its scan scope). The family had therefore never been measured on
real code, in either direction. `~/toolchain/ventoy` is pinned to
`7cbdc5cf69935bcf1f085ae67f40e70ea7e74bae` (tag `v1.1.17`, GPL-3.0).

**Registry key note**: lowercase `ventoy`, the checkout-directory basename,
for the same two `bench/db.py` reasons pureftpd's README documents
(result-filename parsing and `project_relpath`'s `/{project}/` normalization
both require the key and the basename to match).

## Scope: the installer's own top-level sources only

`Ventoy2Disk/Ventoy2Disk/*.c` and `*.h` — **22 files** (16 `.c`, 6 `.h`,
~14.7K lines): the Windows GUI installer plus its `ventoy_cli.c` CLI. It is
first-party C, not C++: COM (VDS, WMI) is driven through the classic
C-style `lpVtbl->Method(...)` vtable idiom. The machine-readable mirror in
`data/benchmark_repos.json` is:

```json
"scope_include": ["Ventoy2Disk/Ventoy2Disk/*.c", "Ventoy2Disk/Ventoy2Disk/*.h"],
"scope_exclude": [
  "Ventoy2Disk/Ventoy2Disk/fat_io_lib/**",
  "Ventoy2Disk/Ventoy2Disk/ff14/**",
  "Ventoy2Disk/Ventoy2Disk/xz-embedded-20130513/**"
]
```

Under path-aware globbing `*` stops at `/`, so the include alone already
yields the 22 files; the exclude states the intent (the same reason raylib
keeps its `src/external/*` exclude) and names the three vendored
subdirectories the runner drops with `--exclude`:

| Directory                 | What it is                              | Licence       | `.c`/`.h` |
|---------------------------|-----------------------------------------|---------------|----------:|
| `fat_io_lib/`             | Ultra-Embedded FAT library              | GPL           | 20        |
| `ff14/`                   | ChaN's FatFs R0.14                      | permissive    | 7         |
| `xz-embedded-20130513/`   | XZ Embedded decompressor                | public domain | 18        |

They stay in the `-d` prescan so the headers the installer includes from
them (`ff.h`, `fat_filelib.h`, `xz.h`) resolve; they are excluded from
*reporting* because they are not Ventoy's code and carry different
provenance.

**Non-scope**: everything else in the repository — `GRUB2/`, `IPXE/`,
`BUSYBOX/`, `EDK2/`, `ExFAT/`, `LinuxGUI/`, `Plugson/`, `VtoyTool/`, the
`vtoy*` Linux tools and the shell/Python tooling. Linux, GRUB, firmware and
build-system code, none of it relevant to a CERT-C scan of the installer.
`Vlnk/src/main_windows.c` (+ shared `crc32.c`/`vlnk.c`, ~890 lines) is a
second, smaller genuine Win32 C tool in the same repo, deferred as a
separate low-priority follow-up: low marginal value next to Ventoy2Disk's
surface.

## What the first scan established

**Setup**: aurora-lint 0.4.336 at the onboarding commit, release build;
`corpus-check` clean for the ten checkouts this node has (mbedtls, landed the same day, is not cloned here); the exact command
`bench/realworld_runner.py` builds for `--codebase ventoy` (scan path
`Ventoy2Disk/Ventoy2Disk`, `conf/realworld/ventoy-rules.toml`, explicit `-d`
on the same directory, the three `--exclude`s, no `-I`). Export:
`ventoy_cfg.json` in this directory. Local numbers from one checkout, not a
project measurement — nothing here went through `benchmarking_db`.

**2,561 findings across 101 rules, all 22 files, all in scope.** Top of the
distribution: DCL31-C 570, DCL06-C 182, MSC13-C 166, INT01-C 149, DCL05-C
140, EXP19-C 87, PRE12-C 75, API00-C 74, PRE00-C 70, EXP34-C 64. DCL31-C's
share is the unresolved-`<windows.h>` shape already characterised on raylib
(`FPBUCKET_DCL31_TASK692.md`, tools_sqc task 1042): every Win32 typedef
(`HANDLE`, `DWORD`, `LPVOID`, ...) is an undeclared identifier to a scan with
no Windows SDK on the path. Expected, and the same measured-not-hidden
treatment applies.

**The WIN family: 1 finding, and that is the headline.** `WIN03-C` once
(`VentoyJson.c:727`, `fopen(argv[1], "rb")` without the `N` mode flag);
WIN00-C, WIN01-C, WIN02-C, WIN04-C, WIN05-C, WIN30-C: **zero**. Against a
codebase that was chosen because it has the textbook shapes:

| Rule    | Shape in Ventoy2Disk                                         | Sites | Why it was missed |
|---------|--------------------------------------------------------------|------:|-------------------|
| WIN00-C | `LoadLibraryA("fmifs.dll")`, `LoadLibraryW(L"kernel32.dll")` | 5     | rule matches only the bare `LoadLibrary` macro name, never the `A`/`W` entry points real code calls |
| WIN02-C | `CreateProcessA(NULL, CmdBuf, NULL, NULL, FALSE, 0, ...)`   | 4     | same: matches only `CreateProcess` |
| WIN05-C | `ReadRegistryKey32(REGKEY_HKLM, ...)`, `GetRegDwordValue(HKEY_LOCAL_MACHINE, ...)` | 2 | HKLM reaches `RegOpenKeyExA` through a wrapper parameter, one hop the rule does not follow |
| WIN30-C | `CoTaskMemFree` ×3, no `Global*`/`Local*`/`Heap*` pairs     | 3     | rule covers only the `FormatMessage`/`GlobalFree` pairing; nothing to pair here |
| WIN01-C | no `TerminateThread`                                         | 0     | genuinely absent |
| WIN04-C | `FormatEx = (PFORMATEX)GetProcAddress(ifsModule, "FormatEx")` and the other `GetProcAddress` stores, no `EncodePointer` anywhere | 4 files | rule walks `declaration` nodes only; every store here is an assignment to a previously declared (global or local) pointer |

So the first thing this oracle measured is recall, not precision: two rules
are blind to the suffixed API names that every real Win32 C program uses,
which no POSIX corpus could ever have shown. Filed as follow-ups in this
repo's backlog (WIN00-C/WIN02-C `A`/`W` names; WIN04-C's zero on stored
`GetProcAddress` results). No WIN* precision claim is possible until those
land and the delta is adjudicated.

**POS family: 1 finding**, POS05-C on the same `fopen` (chroot-jail advice
on a Windows program). Left enabled on purpose — the manifest explains why:
a POSIX rule that emits nothing on a Win32 target is a measurement, and one
that emits *something* is an FP to count, not a family to hide.

## Two tool defects the onboarding surfaced (fixed / filed)

1. **UTF-16 sources.** Visual Studio saved 4 of the 22 files as UTF-16LE
   with a BOM (`PartDialog.c`, `WinDialog.c`, `YesDialog.c`, `resource.h`)
   and 2 as UTF-8 with a BOM (`process.c`, `process.h`). The reader's
   ISO-8859-1 fallback turned each UTF-16 file into NUL-interleaved text
   (`i\0n\0t\0`), on which `WinDialog.c` (2,434 lines) **never finished** —
   killed after 10 minutes at 100% of one core, bisected to the rule-independent
   parse stage. `src/parser/mod.rs` now decodes by byte-order mark (UTF-16
   LE/BE, UTF-8 BOM stripped), which is why the four files carry 755 of the
   2,561 findings instead of zero. The whole scan takes ~9 s.
2. **Parse-stage blow-up on garbage input** is still there for a file that
   *is* garbage; the decode fix only stops well-formed UTF-16 from looking
   like it. Filed as its own follow-up with the repro (the old binary against
   the raw `WinDialog.c` bytes; the first 1,363 lines suffice).

## Adjudication status

None yet. Every finding above is unlabeled; `ground_truth` has no `ventoy`
rows. The first labelling pass belongs to `benchmarking_db` once the WIN
recall follow-ups land — adjudicating the WIN family before then labels a
sample two rules are about to change.

## Manifest

`conf/realworld/ventoy-rules.toml`: `rules_templates/rules-all.toml` with
only the four dead-config disables every manifest carries (ENV04-C, MSC18-C,
MSC19-C, MSC25-C). No categorical disable, POS* included (see above).
