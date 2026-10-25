"""bench.config.opam_wrap: a command run through it sees the opam switch's
environment, whatever the user's login shell, and still runs when opam is
missing or fails."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from bench.config import opam_wrap

# Stands in for opam: prints sh syntax only when asked for it, and the
# syntax of $SHELL otherwise, as opam env does.
FAKE_OPAM = """#!/bin/sh
case " $* " in
    *" --shell=sh "*) echo "OPAM_SWITCH_PREFIX='/fake/switch'; export OPAM_SWITCH_PREFIX;" ;;
    *) echo "set -gx OPAM_SWITCH_PREFIX '/fake/switch';" ;;
esac
"""

FAILING_OPAM = "#!/bin/sh\necho 'opam: no switch' >&2\nexit 50\n"


class OpamWrapTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.bin = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def install_opam(self, script):
        opam = self.bin / "opam"
        opam.write_text(script)
        opam.chmod(opam.stat().st_mode | stat.S_IXUSR)

    def run_wrapped(self, argv, shell="/usr/bin/fish"):
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
               "SHELL": shell}
        env.pop("OPAM_SWITCH_PREFIX", None)
        return subprocess.run(opam_wrap(argv), env=env, capture_output=True, text=True)

    def test_switch_environment_reaches_the_command_under_a_fish_login_shell(self):
        self.install_opam(FAKE_OPAM)
        result = self.run_wrapped(["sh", "-c", 'printf %s "$OPAM_SWITCH_PREFIX"'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "/fake/switch")

    def test_arguments_pass_through_unsplit(self):
        self.install_opam(FAKE_OPAM)
        result = self.run_wrapped(["printf", "%s|", "a b", "c"])
        self.assertEqual(result.stdout, "a b|c|")

    def test_a_failing_opam_still_runs_the_command(self):
        self.install_opam(FAILING_OPAM)
        result = self.run_wrapped(["printf", "ran"])
        self.assertEqual((result.returncode, result.stdout), (0, "ran"))

    def test_no_opam_still_runs_the_command(self):
        env = {**os.environ, "PATH": "/usr/bin:/bin"}
        result = subprocess.run(opam_wrap(["printf", "ran"]), env=env,
                                capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, "ran"))

    def test_the_command_exit_status_is_kept(self):
        self.install_opam(FAKE_OPAM)
        self.assertEqual(self.run_wrapped(["sh", "-c", "exit 7"]).returncode, 7)


if __name__ == "__main__":
    unittest.main()
