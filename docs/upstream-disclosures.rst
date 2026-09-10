Upstream Disclosures
=====================

Both of aurora-lint's real-world benchmark projects that have gone through a
full file-at-a-time adjudication audit (see
:doc:`testing-methodology`) have produced genuine defects, reported to each
project's maintainers. As of 2026-09-08, **17 of 17 disclosed defects across
the two audits have been confirmed and fixed upstream** — nine in SQLite,
eight in hostapd/wpa_supplicant.

A finding being disclosed here does not always mean aurora-lint detected it.
Adjudicating a run means a reviewer reads every flagged site against source
to label it TP/FP; that close reading regularly surfaces genuine defects the
tool's rule set missed entirely. Those are false negatives for aurora-lint,
not detections, and each table below marks its source honestly rather than
crediting the tool for what a human reviewer found.

Methodology
-----------

Every defect below came out of the same process described in full in
:doc:`testing-methodology`: a file-at-a-time real-world audit, not a
sampled spot-check. A reviewer works through every file in scope for the
codebase, adjudicates every aurora-lint finding in that file TP/FP against
source, and — because that means reading the surrounding function rather
than just the flagged line — logs any genuine defect noticed along the way,
whether or not a rule flagged it. That is why most of the disclosed items
below are audit read-throughs rather than tool detections: the read-through
is a structural side effect of doing adjudication file-at-a-time instead of
finding-at-a-time.

Two things this audit discipline is not:

- **Not a Juliet-style synthetic benchmark.** These are production
  codebases with no injected ground truth; every TP/FP label and every
  audit-found defect is a human judgment call against real source, recorded
  in the project's own ``data/precision_audit/<project>/`` directory.
- **Not the sole source of official precision/recall figures.** Those come
  from the persistent ``ground_truth`` oracle keyed on
  ``(project, commit, file, line, rule)`` — see :doc:`testing-methodology`
  and, for how a rule change is re-adjudicated before its precision is
  cited, the project's benchmark-workflow documentation. Disclosure status
  here and precision/recall status there are tracked separately and can
  move independently: a defect can be disclosed and fixed long before (or
  after) the finding that surfaced it is folded into an official precision
  number.

Before any item below was filed to a maintainer, it was re-verified against
current upstream mainline — not just cited at the audit's original pinned
commit — to avoid disclosing something already fixed. hostap's audit found
and excluded one such case (item 15 below) this way.

SQLite
------

Nine defects found while auditing SQLite (220 files at a pinned commit) were
reported upstream. **The SQLite team confirmed and fixed all nine, most the
same day they were filed.**

.. list-table::
   :header-rows: 1
   :widths: 22 45 15 18

   * - Site
     - Defect
     - Source
     - Report
   * - ``src/os_kv.c`` — ``kvvfsDecode()``
     - Heap buffer overflow: the hex-pair decode branch writes without the
       bounds check its sibling branch has (check-in ``732c8f81b5``)
     - Audit read-through (false negative — aurora-lint does not flag this site)
     - `afbc56be7b <https://sqlite.org/bugs/forumpost/afbc56be7b>`__
   * - ``ext/fts5/fts5_index.c`` — ``fts5SegmentSize()``
     - Signed integer overflow on page numbers decoded from an on-disk
       record with no upper bound validated (check-in ``c97a940ceb``)
     - aurora-lint finding (INT32-C)
     - `2026-08-17 <https://sqlite.org/bugs/info/2026-08-17T20:07:33Z>`__
   * - ``ext/fts5/fts5_index.c`` — ``fts5TestUtf8()``
     - UTF-8 validator advances 3 bytes through a 4-byte sequence, so every
       valid astral-plane character is rejected (check-in ``ac094ec69b``)
     - aurora-lint finding (MSC12-C)
     - `b02657db71 <https://sqlite.org/bugs/forumpost/b02657db71>`__
   * - ``ext/session/changeset.c``
     - ``sqlite3_mprintf()`` result passed to libc ``printf``'s ``%s``,
       bypassing SQLite's own NULL-safe ``mprintf`` — NULL dereference
       under allocation failure
     - aurora-lint finding (EXP34-C)
     - `f20ea456ac <https://sqlite.org/bugs/forumpost/f20ea456ac>`__
   * - ``expert.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `c06a3c0d3f <https://sqlite.org/bugs/forumpost/c06a3c0d3f>`__
   * - ``amatch.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `20d89d613b <https://sqlite.org/bugs/forumpost/20d89d613b>`__
   * - ``sqlite3_stdio.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `ba00fdddda <https://sqlite.org/bugs/forumpost/ba00fdddda>`__
   * - ``fts3.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `9b4276628a <https://sqlite.org/bugs/forumpost/9b4276628a>`__
   * - ``qrf.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `18338dc19d <https://sqlite.org/bugs/forumpost/18338dc19d>`__

Eight of the nine started as an aurora-lint finding — an EXP34-C, INT32-C or
MSC12-C violation that hand-adjudication then confirmed against the source.
The ``kvvfsDecode()`` overflow did not: it was found by the close reading
that reviewing aurora-lint's findings prompted, which makes it a false
negative for the tool. It is listed because it is an honest account of what
the audit produced, not a detection to claim.

All nine came out of the same file-at-a-time audit behind the real-world
precision figures in :doc:`testing-methodology`.

hostap (hostapd / wpa_supplicant)
----------------------------------

The hostap ground-truth audit (736 files, commit ``dcee60436``) surfaced 109
genuine defects the audit log tracked outside of TP/FP labeling — the large
majority found by full file read-throughs during adjudication, not by
aurora-lint's rule set. Of those, the 16 judged attacker-reachable via wire
data (the highest-priority class) were re-verified against current mainline
before any filing. Eight were disclosed privately to Jouni Malinen on
2026-08-25; **he applied all eight patches to hostap mainline on
2026-09-08.** No separate security advisory was published — impact was
judged too small for one, though three of the eight (items 1, 14 and 16
below) were still fixed as defense-in-depth over the maintainer's own doubts
about practical reachability.

.. list-table::
   :header-rows: 1
   :widths: 22 42 12 12 12

   * - Site
     - Defect
     - Source
     - Fixed
     - Commit
   * - ``src/ap/wpa_auth_ft.c`` — ``wpa_ft_process_rdie()``
     - Bounds-checks ``sizeof(*rdie)`` but then writes 2 extra header bytes
       beyond that check (802.11r FT RIC subelement, off-by-2 OOB write)
     - Audit read-through (false negative)
     - 2026-09-08
     - ``fcae90b60``
   * - ``src/common/ieee802_11_common.c`` — ``get_max_nss_capability()``
     - Reads ``optional[0..7]`` of a peer's HE Capabilities element without
       validating the element is long enough to contain those bytes
     - Audit read-through (false negative)
     - 2026-09-08
     - ``895fd5881``
   * - ``src/ap/ieee802_11_eht.c`` — ``hostapd_parse_link_reconf_req_sta_profile()``
     - OOB read when ``sta_info == end``, a valid boundary case the
       preceding length check does not exclude
     - Audit read-through (false negative)
     - 2026-09-08
     - ``652a34915``
   * - ``src/common/ieee802_11_he.c`` — ``copy_sta_he_capab()``
     - Calls ``check_valid_he_mcs()``, which reads unconditionally, before
       the IE-length validation that should gate it
     - Audit read-through (false negative)
     - 2026-09-08
     - ``6cf41afd5``
   * - ``src/ap/drv_callbacks.c`` — ``hostapd_action_rx()`` (NAN USD)
     - Checks only ``plen >= 5`` before reading byte offset 5; needs
       ``>= 6``. Sibling DPP branch in the same function does this correctly
     - Audit read-through (false negative)
     - 2026-09-08
     - ``7ce112433``
   * - ``src/eap_server/eap_server_peap.c`` (SoH vendor-TLV)
     - Checks ``tlv_len < 4`` but reads a 4-byte header that requires
       ``tlv_len >= 8``
     - Audit read-through (false negative)
     - 2026-09-08
     - ``4b5965e61``
   * - ``src/common/nan_de.c`` — ``nan_de_config()`` / ``nan_de_start_new_publish_state()``
     - Rejects ``n_max < n_min`` but not ``n_max == n_min``; equal values
       later cause a mod-by-zero
     - Audit read-through (false negative)
     - 2026-09-08
     - ``ec339318a``
   * - ``src/eap_server/eap_server_ttls.c`` (resumption path)
     - Off-by-one length check (``len < 1`` where the code reads a second
       byte); currently unreachable since the writer always emits ≥2 bytes,
       fixed as defense-in-depth
     - Audit read-through (false negative)
     - 2026-09-08
     - ``95e57025f``

All eight of the disclosed-and-fixed items were audit-discovered false
negatives, not aurora-lint detections — the same honesty distinction drawn
for SQLite's ``kvvfsDecode()`` above. Two further wire-reachable items from
the same audit (``src/eap_server/eap_server.c``'s EAP-Response/Nak length
underflow and ``src/common/nan_de.c``'s bloom-filter mod-by-zero) **were**
genuine aurora-lint (EXP34-C) true positives, are still present upstream,
and remain open: judged not reachable, so never filed. A sixteenth item
(``src/common/sae.c``'s missing NULL guard, also a confirmed EXP34-C true
positive) turned out to already be fixed upstream before the 2026-08-25
filing, per w1.fi advisory 2026-3.

Combined total
--------------

17 defects disclosed across the two audits, 17 fixed upstream — SQLite's
nine the same day (most of them) or within days, hostap/wpa_supplicant's
eight within two weeks by the project's original author and lead
maintainer.
