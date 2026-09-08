"""BenchDB.project_relpath -- absolute scan path to portable, label-keyed path.

Pinned because the defect this function had was SILENT BY CONSTRUCTION
(task 762): findings and ground-truth labels both normalize through here, so
using the last `/<project>/` segment instead of the first left the two sides
agreeing and every precision/recall figure intact, while the stored path named
no file on disk. Nothing downstream errored. What broke was resolving a label
back to a file -- `corpus.in_scope` is handed this path and no glob matches a
bare basename, so the finding read as out of scope and never reached
adjudication.
"""

import unittest

from bench.db import BenchDB

relpath = BenchDB.project_relpath


class TestProjectRelpath(unittest.TestCase):
    # (project, absolute path, expected relative path, what it pins)
    CASES = [
        (
            "curl", "/home/b/toolchain/curl/lib/doh.c", "lib/doh.c",
            "the ordinary case",
        ),
        (
            # Four of the nine corpora hold a subdirectory named after the
            # project. First-occurrence keeps the prefix; last-occurrence
            # would collapse this to the bare basename.
            "mosquitto",
            "/home/b/toolchain/mosquitto/include/mosquitto/libmosquitto.h",
            "include/mosquitto/libmosquitto.h",
            "project-named subdirectory (mosquitto)",
        ),
        (
            "curl", "/home/b/toolchain/curl/include/curl/curl.h",
            "include/curl/curl.h",
            "project-named subdirectory (curl)",
        ),
        (
            "sqlite",
            "/home/b/toolchain/sqlite/ext/jni/src/org/sqlite/Foo.c",
            "ext/jni/src/org/sqlite/Foo.c",
            "project-named subdirectory (sqlite)",
        ),
        (
            # sel4 is the collision hazard the docstring calls a loaded gun:
            # 155 headers under a sel4/ directory, 53 of them constants.h.
            # Under last-occurrence these two collapse to ONE key and merge
            # two different files' labels with no error.
            "sel4", "/home/b/toolchain/sel4/libsel4/sel4/constants.h",
            "libsel4/sel4/constants.h",
            "sel4 basename collision, path A",
        ),
        (
            "sel4", "/home/b/toolchain/sel4/libsel4/arch/sel4/constants.h",
            "libsel4/arch/sel4/constants.h",
            "sel4 basename collision, path B",
        ),
        (
            "lua", "/home/b/toolchain/lua/lapi.c", "lapi.c",
            "lua's flat layout -- a bare basename here is CORRECT",
        ),
        (
            "curl", "/tmp/scratch/other.c", "/tmp/scratch/other.c",
            "marker absent -- returned unchanged",
        ),
    ]

    def test_normalizes_each_case(self):
        for project, path, want, why in self.CASES:
            with self.subTest(why=why, project=project, path=path):
                self.assertEqual(relpath(project, path), want)

    def test_sel4_collision_paths_stay_distinct(self):
        """The two sel4 constants.h paths must not normalize to one key."""
        a = relpath("sel4", "/home/b/toolchain/sel4/libsel4/sel4/constants.h")
        b = relpath("sel4",
                    "/home/b/toolchain/sel4/libsel4/arch/sel4/constants.h")
        self.assertNotEqual(a, b)

    def test_result_is_relative_whenever_the_marker_is_present(self):
        """ground_truth keys on this value, so a leading slash would key a
        machine-specific path and never match a label from another checkout."""
        for project, path, _want, why in self.CASES:
            if f"/{project}/" not in path:
                continue
            with self.subTest(why=why, path=path):
                self.assertFalse(relpath(project, path).startswith("/"))

    def test_idempotent_on_an_already_relative_path(self):
        """Re-normalizing a stored label must not strip it further -- unless
        the relative path itself still contains the marker, which is the
        project-named-subdirectory case covered above."""
        self.assertEqual(relpath("curl", "lib/doh.c"), "lib/doh.c")
