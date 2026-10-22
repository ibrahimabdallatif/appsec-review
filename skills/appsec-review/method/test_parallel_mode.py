"""Unit tests for parallel_mode.py. Run: python -I test_parallel_mode.py"""
import contextlib
import io
import os
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parallel_mode  # noqa: E402


class DecideTest(unittest.TestCase):
    def test_default_is_parallel(self):
        self.assertEqual(parallel_mode.decide([], {}), ("parallel", "default"))

    def test_blank_env_is_default(self):
        self.assertEqual(parallel_mode.decide([], {"APPSEC_REVIEW_PARALLEL": "  "}),
                         ("parallel", "default"))

    def test_user_flag_forces_sequential(self):
        mode, reason = parallel_mode.decide(["--sequential"], {"APPSEC_REVIEW_PARALLEL": "1"})
        self.assertEqual(mode, "sequential")
        self.assertIn("user asked", reason)

    def test_off_values(self):
        for value in ("0", "false", "no", "off", "sequential", " FALSE "):
            mode, reason = parallel_mode.decide([], {"APPSEC_REVIEW_PARALLEL": value})
            self.assertEqual(mode, "sequential", value)
            self.assertTrue(reason.startswith("APPSEC_REVIEW_PARALLEL="), reason)

    def test_on_values(self):
        for value in ("1", "true", "yes", "on", "parallel"):
            mode, reason = parallel_mode.decide([], {"APPSEC_REVIEW_PARALLEL": value})
            self.assertEqual(mode, "parallel", value)
            self.assertIn(value, reason)

    def test_unknown_env_is_an_error(self):
        with self.assertRaises(ValueError):
            parallel_mode.decide([], {"APPSEC_REVIEW_PARALLEL": "maybe"})

    def test_unknown_argument_is_an_error(self):
        with self.assertRaises(ValueError):
            parallel_mode.decide(["--fast"], {})

    def test_non_string_env_is_an_error(self):
        with self.assertRaises(ValueError):
            parallel_mode.decide([], {"APPSEC_REVIEW_PARALLEL": 0})


class MainTest(unittest.TestCase):
    def test_prints_mode_and_reason(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(parallel_mode.main([], {}), 0)
        self.assertTrue(out.getvalue().startswith("parallel\t"))

    def test_bad_env_exits_2_without_echoing_other_variables(self):
        err = io.StringIO()
        out = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = parallel_mode.main([], {"APPSEC_REVIEW_PARALLEL": "maybe", "API_KEY": "secret-value"})
        self.assertEqual(code, 2)
        blob = err.getvalue() + out.getvalue()
        self.assertNotIn("secret-value", blob)
        self.assertNotIn("API_KEY", blob)
        self.assertIn("APPSEC_REVIEW_PARALLEL", err.getvalue())

    def test_script_entrypoint(self):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parallel_mode.py")
        env = os.environ.copy()
        env.pop("APPSEC_REVIEW_PARALLEL", None)
        result = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("parallel\t"), result.stdout)
        self.assertNotIn("secret", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
