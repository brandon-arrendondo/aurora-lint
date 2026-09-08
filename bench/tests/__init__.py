"""Tests for bench/.

Stdlib `unittest`, deliberately: every module under bench/ imports only the
standard library, so the whole benchmark side of this repo runs on a bare
Python. A test dependency would be the first one and would put `pip install`
in front of `python3 -m unittest`, which is exactly the fresh-clone promise
bench/ exists to keep (see CLAUDE.md's clone-experience test).

    python3 -m unittest discover -s . -t .

benchmarking_db has a much larger suite over some of the same shapes. It is
the right model but is NOT importable from here and must not become a
dependency -- what belongs here is the subset a stranger needs in order to
trust `python -m bench` against their own codebase.
"""
