# Known Gap: CWE-123 (Write-What-Where Condition) (task 384)

**Status:** TRIAGED, closed as a documented permanent gap (no fix scoped).
This is a documentation-only outcome — no rule code changed.

## 1. The finding

CWE-123's Juliet manifest (`ARR00-C`, `ARR30-C`, `ARR38-C`, `ENV01-C`,
`EXP33-C`, `EXP39-C`, `STR31-C`, `STR32-C`) scores 0% flaw-hit detection
across all 168 CWE-123 test cases, in both base and fixed runs. Task 146
found EXP33-C's 114 file-level "hits" on this CWE were coincidental
(a different bug on the same file, not the injected flaw line — see commit
`e4c31831`).

All 168 CWE-123 test cases (`connect_socket`, `fgets`, `listen_socket` ×
~56 flow variants each) share one template. The injected flaw is always
this shape:

```c
typedef struct _linkedList {
    struct _linkedList *next;
    struct _linkedList *prev;
} linkedList;
typedef struct _badStruct { linkedList list; } badStruct;
...
badStruct data;
/* link data into a list, so data.list.next/prev hold valid pointers */
...
/* FLAW: overwrite linked list pointers with data */
fgets((char*)&data, sizeof(data), stdin);   // or recv(sock, (char*)&data, sizeof(data), 0)
...
/* unlink 'data' from the list using the now-attacker-controlled pointers */
linkedListPrev = data.list.prev;
linkedListNext = data.list.next;
linkedListPrev->next = linkedListNext;   // write-what-where
linkedListNext->prev = linkedListPrev;
```

External input is read byte-for-byte over a struct that contains pointer
fields, and those fields are later dereferenced as pointers. No buffer
overflow occurs (`sizeof(data)` is exactly the destination size) — the
defect is pure type/trust confusion, not a sizing bug.

## 2. Why no manifest rule is a semantic fit

- **EXP39-C** (incompatible pointer type access) is the closest candidate,
  since a struct's pointer fields end up populated with non-pointer data
  through a `(char*)&data` cast. But `char*`/`unsigned char*` is the
  explicit strict-aliasing exception in the C standard (6.5p7) and in
  EXP39-C's own compliant examples (`memcpy`, serialization, byte-level
  I/O all cast through `char*` legitimately). Making EXP39-C flag
  `(char*)&struct_with_pointers` casts generically would flag the standard,
  correct way to do binary I/O in C — not a targeted fix, a rule-scope
  change with large real-world FP blast radius for something CERT does not
  itself treat as a EXP39-C violation.
- **ARR00-C / ARR30-C / ARR38-C / STR31-C / STR32-C** (bounds/sizing rules):
  don't apply — there's no size mismatch. `sizeof(data)` is correct.
- **ENV01-C** (environment-variable trust): unrelated source (`fgets`/`recv`,
  not `getenv`).
- No CERT-C rule encodes "do not let externally-controlled bytes populate a
  struct's pointer-typed fields and later dereference them." CWE-123 is a
  memory-corruption/control-flow pattern (attacker controls both WHAT is
  written and WHERE), and CERT's C secure-coding rules are organized around
  type safety, bounds, and resource lifetime — not this specific taint
  shape. CERT's own CWE-to-rule cross-reference lists CWE-123 against
  EXP39-C (see `EXP39-C.toml`'s `cwe = [..., "CWE-123", ...]`), but that is
  the *official SEI taxonomy mapping*, not evidence EXP39-C's actual
  detection logic (or any other CERT-C rule) covers this construct — and it
  doesn't, by design (see the char* exception above).

## 3. Disposition

Confirmed genuine, permanent gap per the task's own hypothesis: none of
CWE-123's manifest rules are a plausible semantic fit, and closing it would
require either a new taint-tracking rule outside the CERT-C rule set's scope
(aurora-lint targets CERT-C compliance, not general CWE coverage — see
[`docs/index.rst`](../index.rst) project structure) or weakening EXP39-C's
char* exception in a way that contradicts the C standard and would generate
large real-world noise on legitimate serialization/IPC code. No fix is
scoped. This CWE stays a structural 0% in Juliet comparisons going forward;
that is expected and should not be re-investigated as a regression.
